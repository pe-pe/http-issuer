package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	httpissuerv1alpha1 "http-issuer/api/v1alpha1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
)

func TestGetHttpIssuerSpec(t *testing.T) {
	tests := []struct {
		name        string
		issuer      v1alpha1.Issuer
		expectError bool
	}{
		{
			name: "HttpIssuer returns spec",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					URL: "https://example.com",
				},
			},
			expectError: false,
		},
		{
			name: "HttpClusterIssuer returns spec",
			issuer: &httpissuerv1alpha1.HttpClusterIssuer{
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					URL: "https://example.com",
				},
			},
			expectError: false,
		},
		{
			name:        "unsupported issuer type returns error",
			issuer:      &mockIssuer{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := getHttpIssuerSpec(tt.issuer)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, spec)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, spec)
			}
		})
	}
}

func TestSigner_Check(t *testing.T) {
	tests := []struct {
		name           string
		issuer         v1alpha1.Issuer
		secret         *corev1.Secret
		serverResponse int
		expectError    bool
		errorContains  string
	}{
		{
			name: "successful health check with basic auth",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					URL:         "http://localhost",
					HealthPath:  "/health",
					HttpTimeout: 5,
					BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "basic-auth-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic-auth-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			serverResponse: http.StatusOK,
			expectError:    false,
		},
		{
			name: "successful health check with token auth",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					URL:         "http://localhost",
					HealthPath:  "/health",
					HttpTimeout: 5,
					TokenSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "token-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "token-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("secret-token"),
				},
			},
			serverResponse: http.StatusOK,
			expectError:    false,
		},
		{
			name: "health check fails with non-200 status",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					URL:         "http://localhost",
					HealthPath:  "/health",
					HttpTimeout: 5,
					BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "basic-auth-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic-auth-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			serverResponse: http.StatusInternalServerError,
			expectError:    true,
			errorContains:  "health check failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify authentication
				if tt.issuer.(*httpissuerv1alpha1.HttpIssuer).Spec.BasicAuthSecretRef != nil {
					username, password, ok := r.BasicAuth()
					assert.True(t, ok)
					assert.Equal(t, "user", username)
					assert.Equal(t, "pass", password)
				}
				if tt.issuer.(*httpissuerv1alpha1.HttpIssuer).Spec.TokenSecretRef != nil {
					auth := r.Header.Get("Authorization")
					assert.Equal(t, "Bearer secret-token", auth)
				}
				w.WriteHeader(tt.serverResponse)
			}))
			defer server.Close()

			// Update issuer URL to use test server
			spec, _ := getHttpIssuerSpec(tt.issuer)
			spec.URL = server.URL

			// Create fake client with secret
			scheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(scheme))
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.secret).Build()

			signer := Signer{KubeClient: client}
			err := signer.Check(context.Background(), tt.issuer)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	tests := []struct {
		name           string
		issuer         v1alpha1.Issuer
		secret         *corev1.Secret
		cr             *mockCertificateRequest
		serverResponse int
		responseBody   string
		expectError    bool
		errorContains  string
	}{
		{
			name: "successful signing with basic auth",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					URL:         "http://localhost",
					SignPath:    "/sign",
					SignMethod:  "POST",
					CSRField:    "csr",
					HttpTimeout: 5,
					BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "basic-auth-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic-auth-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			cr: &mockCertificateRequest{
				csr: []byte("test-csr"),
				annotations: map[string]string{
					"ca.internal/test-annotation": "test-value",
				},
			},
			serverResponse: http.StatusOK,
			responseBody:   "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
			expectError:    false,
		},
		{
			name: "signing fails with non-200 status",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					URL:         "http://localhost",
					SignPath:    "/sign",
					SignMethod:  "POST",
					CSRField:    "csr",
					HttpTimeout: 5,
					TokenSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "token-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "token-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("secret-token"),
				},
			},
			cr: &mockCertificateRequest{
				csr: []byte("test-csr"),
			},
			serverResponse: http.StatusBadRequest,
			responseBody:   "Bad Request",
			expectError:    true,
			errorContains:  "sign failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify HTTP method
				spec, _ := getHttpIssuerSpec(tt.issuer)
				assert.Equal(t, spec.SignMethod, r.Method)

				// Verify Content-Type
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				// Verify authentication
				if spec.BasicAuthSecretRef != nil {
					username, password, ok := r.BasicAuth()
					assert.True(t, ok)
					assert.Equal(t, "user", username)
					assert.Equal(t, "pass", password)
				}
				if spec.TokenSecretRef != nil {
					auth := r.Header.Get("Authorization")
					assert.Equal(t, "Bearer secret-token", auth)
				}

				// Verify request body contains CSR
				var requestData map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&requestData)
				assert.NoError(t, err)
				assert.Equal(t, "test-csr", requestData[spec.CSRField])

				w.WriteHeader(tt.serverResponse)
				_, err = w.Write([]byte(tt.responseBody))
				require.NoError(t, err)
			}))
			defer server.Close()

			// Update issuer URL to use test server
			spec, _ := getHttpIssuerSpec(tt.issuer)
			spec.URL = server.URL

			// Create fake client with secret
			scheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(scheme))
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.secret).Build()

			signer := Signer{KubeClient: client}
			bundle, err := signer.Sign(context.Background(), tt.cr, tt.issuer)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, []byte(tt.responseBody), bundle.ChainPEM)
			}
		})
	}
}

func TestSigner_getHttpCredentials(t *testing.T) {
	tests := []struct {
		name          string
		issuer        v1alpha1.Issuer
		secret        *corev1.Secret
		expectError   bool
		errorContains string
		expectedCreds *HttpCredentials
	}{
		{
			name: "basic auth credentials",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "basic-auth-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic-auth-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			expectError: false,
			expectedCreds: &HttpCredentials{
				Type:     AuthTypeBasicAuth,
				Name:     "basic-auth-secret",
				Username: "user",
				Password: "pass",
			},
		},
		{
			name: "token credentials",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					TokenSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "token-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "token-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("secret-token"),
				},
			},
			expectError: false,
			expectedCreds: &HttpCredentials{
				Type:  AuthTypeToken,
				Name:  "token-secret",
				Token: "secret-token",
			},
		},
		{
			name: "both auth types specified - error",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "basic-auth-secret",
					},
					TokenSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "token-secret",
					},
				},
			},
			expectError:   true,
			errorContains: "only one of basicAuthSecretRef or tokenSecretRef can be set",
		},
		{
			name: "no auth specified - error",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{},
			},
			expectError:   true,
			errorContains: "one of basicAuthSecretRef or tokenSecretRef must be set",
		},
		{
			name: "secret not found - error",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "non-existent-secret",
					},
				},
			},
			expectError:   true,
			errorContains: "failed to get secret",
		},
		{
			name: "missing username in basic auth secret",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "incomplete-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "incomplete-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"password": []byte("pass"),
				},
			},
			expectError:   true,
			errorContains: "failed to get username from secret",
		},
		{
			name: "missing token in token secret",
			issuer: &httpissuerv1alpha1.HttpIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "default",
				},
				Spec: httpissuerv1alpha1.HttpCertificateSource{
					TokenSecretRef: &httpissuerv1alpha1.SecretSelector{
						Name: "incomplete-token-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "incomplete-token-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"other": []byte("value"),
				},
			},
			expectError:   true,
			errorContains: "failed to get token from secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client
			scheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(scheme))

			var objects []client.Object
			if tt.secret != nil {
				objects = append(objects, tt.secret)
			}

			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

			signer := Signer{KubeClient: client}
			creds, err := signer.getHttpCredentials(context.Background(), tt.issuer)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, creds)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCreds, creds)
			}
		})
	}
}

// Test HttpClusterIssuer specific scenarios
func TestSigner_getHttpCredentials_ClusterIssuer(t *testing.T) {
	namespace := "test-namespace"
	clusterIssuer := &httpissuerv1alpha1.HttpClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-issuer",
		},
		Spec: httpissuerv1alpha1.HttpCertificateSource{
			BasicAuthSecretRef: &httpissuerv1alpha1.SecretSelector{
				Name:      "basic-auth-secret",
				Namespace: &namespace,
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "basic-auth-secret",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"username": []byte("user"),
			"password": []byte("pass"),
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	signer := Signer{KubeClient: client}
	creds, err := signer.getHttpCredentials(context.Background(), clusterIssuer)

	assert.NoError(t, err)
	expectedCreds := &HttpCredentials{
		Type:     AuthTypeBasicAuth,
		Name:     "basic-auth-secret",
		Username: "user",
		Password: "pass",
	}
	assert.Equal(t, expectedCreds, creds)
}

// Mock types for testing

type mockIssuer struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

func (m *mockIssuer) GetStatus() *v1alpha1.IssuerStatus  { return nil }
func (m *mockIssuer) SetStatus(_ *v1alpha1.IssuerStatus) {}
func (m *mockIssuer) DeepCopyObject() runtime.Object     { return m }
func (m *mockIssuer) GetConditions() []metav1.Condition  { return nil }
func (m *mockIssuer) GetIssuerTypeIdentifier() string    { return "mockissuers.test" }

type mockCertificateRequest struct {
	csr         []byte
	duration    time.Duration
	annotations map[string]string
}

func (m *mockCertificateRequest) GetCertificateDetails() (signer.CertificateDetails, error) {
	return signer.CertificateDetails{
		CSR:      m.csr,
		Duration: m.duration,
	}, nil
}

func (m *mockCertificateRequest) GetAnnotations() map[string]string {
	if m.annotations == nil {
		return make(map[string]string)
	}
	return m.annotations
}

func (m *mockCertificateRequest) GetConditions() []cmapi.CertificateRequestCondition { return nil }
func (m *mockCertificateRequest) SetCertificate(_ []byte) error                      { return nil }
func (m *mockCertificateRequest) SetCA(_ []byte) error                               { return nil }
func (m *mockCertificateRequest) SetFailed(_ string, _ string) error                 { return nil }

// Implement metav1.Object interface
func (m *mockCertificateRequest) GetName() string                                { return "test-cr" }
func (m *mockCertificateRequest) SetName(_ string)                               {}
func (m *mockCertificateRequest) GetNamespace() string                           { return "default" }
func (m *mockCertificateRequest) SetNamespace(_ string)                          {}
func (m *mockCertificateRequest) GetGenerateName() string                        { return "" }
func (m *mockCertificateRequest) SetGenerateName(_ string)                       {}
func (m *mockCertificateRequest) GetUID() types.UID                              { return "" }
func (m *mockCertificateRequest) SetUID(_ types.UID)                             {}
func (m *mockCertificateRequest) GetResourceVersion() string                     { return "" }
func (m *mockCertificateRequest) SetResourceVersion(_ string)                    {}
func (m *mockCertificateRequest) GetGeneration() int64                           { return 0 }
func (m *mockCertificateRequest) SetGeneration(_ int64)                          {}
func (m *mockCertificateRequest) GetSelfLink() string                            { return "" }
func (m *mockCertificateRequest) SetSelfLink(_ string)                           {}
func (m *mockCertificateRequest) GetCreationTimestamp() metav1.Time              { return metav1.Time{} }
func (m *mockCertificateRequest) SetCreationTimestamp(_ metav1.Time)             {}
func (m *mockCertificateRequest) GetDeletionTimestamp() *metav1.Time             { return nil }
func (m *mockCertificateRequest) SetDeletionTimestamp(_ *metav1.Time)            {}
func (m *mockCertificateRequest) GetDeletionGracePeriodSeconds() *int64          { return nil }
func (m *mockCertificateRequest) SetDeletionGracePeriodSeconds(_ *int64)         {}
func (m *mockCertificateRequest) GetLabels() map[string]string                   { return nil }
func (m *mockCertificateRequest) SetLabels(_ map[string]string)                  {}
func (m *mockCertificateRequest) SetAnnotations(_ map[string]string)             {}
func (m *mockCertificateRequest) GetFinalizers() []string                        { return nil }
func (m *mockCertificateRequest) SetFinalizers(_ []string)                       {}
func (m *mockCertificateRequest) GetOwnerReferences() []metav1.OwnerReference    { return nil }
func (m *mockCertificateRequest) SetOwnerReferences(_ []metav1.OwnerReference)   {}
func (m *mockCertificateRequest) GetManagedFields() []metav1.ManagedFieldsEntry  { return nil }
func (m *mockCertificateRequest) SetManagedFields(_ []metav1.ManagedFieldsEntry) {}
