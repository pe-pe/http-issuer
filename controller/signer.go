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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

const (
	AuthTypeBasicAuth = "basic-auth"
	AuthTypeToken     = "token"
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

type Signer struct {
	KubeClient client.Client
}

type HttpCredentials struct {
	Type     string
	Name     string
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
		EventRecorder: mgr.GetEventRecorder("httpissuer.ca.internal"),
	}).SetupWithManager(ctx, mgr)
}

func getHttpIssuerSpec(issuerObject v1alpha1.Issuer) (*httpissuerv1alpha1.HttpCertificateSource, error) {
	switch issuer := issuerObject.(type) {
	case *httpissuerv1alpha1.HttpIssuer:
		return &issuer.Spec, nil
	case *httpissuerv1alpha1.HttpClusterIssuer:
		return &issuer.Spec, nil
	default:
		return nil, fmt.Errorf("expected HttpIssuer or HttpClusterIssuer, got %T", issuerObject)
	}
}

func (s Signer) Check(ctx context.Context, issuerObject v1alpha1.Issuer) error {
	ctrl.LoggerFrom(ctx).Info("Health check started for issuer")

	spec, err := getHttpIssuerSpec(issuerObject)
	if err != nil {
		return err
	}
	httpCredentials, err := s.getHttpCredentials(ctx, issuerObject)
	if err != nil {
		return err
	}

	// Create HTTP client and make authenticated request with defined timeout
	httpClient := &http.Client{
		Timeout: time.Duration(spec.HttpTimeout) * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL+spec.HealthPath, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	switch httpCredentials.Type {
	case AuthTypeBasicAuth:
		req.SetBasicAuth(httpCredentials.Username, httpCredentials.Password)
	case AuthTypeToken:
		req.Header.Set("Authorization", "Bearer "+httpCredentials.Token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", spec.URL+spec.HealthPath, err)
	}
	err = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to close response body: %w", err)
	}

	// Check if the response status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed, expected status %d OK, got %d", http.StatusOK, resp.StatusCode)
	}

	ctrl.LoggerFrom(ctx).Info("Health check completed for issuer")

	return nil
}

func (s Signer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject v1alpha1.Issuer) (signer.PEMBundle, error) {
	ctrl.LoggerFrom(ctx).Info("Sign started for issuer")

	spec, err := getHttpIssuerSpec(issuerObject)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to get issuer spec: %w", err)
	}
	httpCredentials, err := s.getHttpCredentials(ctx, issuerObject)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to get HTTP credentials: %w", err)
	}
	certDetails, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to get certificate details: %w", err)
	}
	requestAnnotations := cr.GetAnnotations()

	// Prepare request body with annotations, CSR and Duration
	data := make(map[string]interface{})
	groupPrefix := issuerObject.GetObjectKind().GroupVersionKind().Group + "/"
	for key, value := range requestAnnotations {
		// match annotations containing groupPrefix and strip it from the key
		if strings.HasPrefix(key, groupPrefix) {
			data[strings.TrimPrefix(key, groupPrefix)] = value
		}
	}
	data[spec.CSRField] = string(certDetails.CSR)
	if spec.DurationField != nil && certDetails.Duration != 0 {
		data[*spec.DurationField] = int(certDetails.Duration.Minutes())
	}
	requestBody, err := json.Marshal(data)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create HTTP client and make authenticated request with defined timeout
	httpClient := &http.Client{
		Timeout: time.Duration(spec.HttpTimeout) * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, spec.SignMethod, spec.URL+spec.SignPath, bytes.NewReader(requestBody))
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to create request: %w", err)
	}
	switch httpCredentials.Type {
	case AuthTypeBasicAuth:
		req.SetBasicAuth(httpCredentials.Username, httpCredentials.Password)
	case AuthTypeToken:
		req.Header.Set("Authorization", "Bearer "+httpCredentials.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to connect to %s: %w", spec.URL+spec.SignPath, err)
	}

	// Check if the response status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		return signer.PEMBundle{}, fmt.Errorf("sign failed, expected status %d OK, got %d", http.StatusOK, resp.StatusCode)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to read response body: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to close response body: %w", err)
	}

	ctrl.LoggerFrom(ctx).Info("Sign data obtained", "body", string(bodyBytes))

	return signer.PEMBundle{
		ChainPEM: bodyBytes,
	}, nil
}

func (s Signer) getHttpCredentials(ctx context.Context, issuerObject v1alpha1.Issuer) (*HttpCredentials, error) {
	// Get issuerObject.Spec
	spec, err := getHttpIssuerSpec(issuerObject)
	if err != nil {
		return nil, err
	}
	// For HttpClusterIssuer, namespace will be set from *secretRef (mandatory in API definition)
	secretNamespace := issuerObject.GetNamespace()
	httpCredentials := &HttpCredentials{}

	if spec.BasicAuthSecretRef != nil && spec.TokenSecretRef != nil {
		return nil, fmt.Errorf("only one of basicAuthSecretRef or tokenSecretRef can be set")
	}
	if spec.BasicAuthSecretRef != nil {
		httpCredentials.Type = AuthTypeBasicAuth
		httpCredentials.Name = spec.BasicAuthSecretRef.Name
		if secretNamespace == "" { // HttpClusterIssuer case
			secretNamespace = *spec.BasicAuthSecretRef.Namespace
		}
	} else if spec.TokenSecretRef != nil {
		httpCredentials.Type = AuthTypeToken
		httpCredentials.Name = spec.TokenSecretRef.Name
		if secretNamespace == "" { // HttpClusterIssuer case
			secretNamespace = *spec.TokenSecretRef.Namespace
		}
	} else {
		return nil, fmt.Errorf("one of basicAuthSecretRef or tokenSecretRef must be set")
	}

	var secret corev1.Secret
	err = s.KubeClient.Get(ctx, types.NamespacedName{
		Name:      httpCredentials.Name,
		Namespace: secretNamespace,
	}, &secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", secretNamespace, httpCredentials.Name, err)
	}

	switch httpCredentials.Type {
	case AuthTypeBasicAuth:
		username, ok := secret.Data["username"]
		if !ok {
			return nil, fmt.Errorf("failed to get username from secret %s/%s", secretNamespace, httpCredentials.Name)
		}
		password, ok := secret.Data["password"]
		if !ok {
			return nil, fmt.Errorf("failed to get password from secret %s/%s", secretNamespace, httpCredentials.Name)
		}
		httpCredentials.Username = string(username)
		httpCredentials.Password = string(password)
	case AuthTypeToken:
		token, ok := secret.Data["token"]
		if !ok {
			return nil, fmt.Errorf("failed to get token from secret %s/%s", secretNamespace, httpCredentials.Name)
		}
		httpCredentials.Token = string(token)
	}

	return httpCredentials, nil
}
