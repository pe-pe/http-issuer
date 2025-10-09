/*
Copyright 2023 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	httpissuerv1alpha1 "http-issuer/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
)

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=httpissuers.ca.internal/*;httpclusterissuers.ca.internal/*

// +kubebuilder:rbac:groups=ca.internal,resources=httpissuers;httpclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=ca.internal,resources=httpissuers/status;httpclusterissuers/status,verbs=patch

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

type Signer struct{
	KubeClient client.Client
}

type HttpCredentials struct {
	Type     string
	Name	 string
	Username string
	Password string
	Token    string
}

func (s Signer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return (&controllers.CombinedController{
		IssuerTypes:        []v1alpha1.Issuer{&httpissuerv1alpha1.HttpIssuer{}},
		ClusterIssuerTypes: []v1alpha1.Issuer{&httpissuerv1alpha1.HttpClusterIssuer{}},

		FieldOwner:       "httpissuer.ca.internal",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorderFor("httpissuer.ca.internal"),
	}).SetupWithManager(ctx, mgr)
}

func (s Signer) getHttpCredentials(ctx context.Context, issuerObject v1alpha1.Issuer) (*HttpCredentials, error) {
	// Determine the issuer type and extract spec + namespace if HttpIssuer
	// For HttpClusterIssuer, namespace will be set from *secretRef (mandatory in API definition)
	var spec *httpissuerv1alpha1.HttpCertificateSource
	var secretNamespace *string
	httpCredentials := &HttpCredentials{}

	switch issuer := issuerObject.(type) {
	case *httpissuerv1alpha1.HttpIssuer:
		spec = &issuer.Spec
		secretNamespace = &issuer.Namespace
	case *httpissuerv1alpha1.HttpClusterIssuer:
		spec = &issuer.Spec
	default:
		return nil, fmt.Errorf("expected HttpIssuer or HttpClusterIssuer, got %T", issuerObject)
	}

	if spec.BasicAuthSecretRef != nil && spec.TokenSecretRef != nil {
		return nil, fmt.Errorf("only one of basicAuthSecretRef or tokenSecretRef can be set")
	}
	if spec.BasicAuthSecretRef != nil {
		httpCredentials.Type = "basic-auth"
		httpCredentials.Name = spec.BasicAuthSecretRef.Name
		if secretNamespace == nil {
			secretNamespace = spec.BasicAuthSecretRef.Namespace
		}
	} else if spec.TokenSecretRef != nil {
		httpCredentials.Type = "token"
		httpCredentials.Name = spec.TokenSecretRef.Name
		if secretNamespace == nil {
			secretNamespace = spec.TokenSecretRef.Namespace
		}
	} else {
		return nil, fmt.Errorf("one of basicAuthSecretRef or tokenSecretRef must be set")
	}

	var secret corev1.Secret
	err := s.KubeClient.Get(ctx, types.NamespacedName{
		Name:      httpCredentials.Name,
		Namespace: *secretNamespace,
	}, &secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", *secretNamespace, httpCredentials.Name, err)
	}

	switch httpCredentials.Type {
		case "basic-auth":
			username, ok := secret.Data["username"]
			if !ok {
				return nil, fmt.Errorf("failed to get username from secret %s/%s", *secretNamespace, httpCredentials.Name)
			}
			password, ok := secret.Data["password"]
			if !ok {
				return nil, fmt.Errorf("failed to get password from secret %s/%s", *secretNamespace, httpCredentials.Name)
			}
			httpCredentials.Username = string(username)
			httpCredentials.Password = string(password)
		case "token":
			token, ok := secret.Data["token"]
			if !ok {
				return nil, fmt.Errorf("failed to get token from secret %s/%s", *secretNamespace, httpCredentials.Name)
			}
			httpCredentials.Token = string(token)
	}
	return httpCredentials, nil
}

func (s Signer) Check(ctx context.Context, issuerObject v1alpha1.Issuer) error {
	httpCredentials, err := s.getHttpCredentials(ctx, issuerObject)
	if err != nil {
		return err
	}
	ctrl.LoggerFrom(ctx).Info("Health check started for issuer", "httpCredentials", httpCredentials)

	return nil
}

func (s Signer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject v1alpha1.Issuer) (signer.PEMBundle, error) {
	httpCredentials, err := s.getHttpCredentials(ctx, issuerObject)
	if err != nil {
		return signer.PEMBundle{}, err
	}
	ctrl.LoggerFrom(ctx).Info("Sign started for issuer", "httpCredentials", httpCredentials)

	// generate random ca private key
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	caCRT := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// load client certificate request
	certDetails, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	clientCRTTemplate, err := certDetails.CertificateTemplate()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, clientCRTTemplate, caCRT, clientCRTTemplate.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}

	clientCrt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	return signer.PEMBundle{
		ChainPEM: clientCrt,
	}, nil
}
