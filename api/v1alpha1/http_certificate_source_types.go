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

package v1alpha1

type HttpCertificateSource struct{
    // URL to check or fetch the certificate from
    URL string `json:"url"`
    // HealthPath is the HTTP path to use for health checks, defaults to "/healthz"
    // +optional
    // +kubebuilder:default="/healthz"
    HealthPath string `json:"healthPath"`
    // SignPath is the HTTP path to use for signing requests, mandatory
    SignPath string `json:"signPath"`
    // SignMethod is the HTTP method to use for signing requests, defaults to "POST"
    // +optional
    // +kubebuilder:default="POST"
    SignMethod string `json:"signMethod"`
    // CSRField is the name of the parameter to use for the certificate signing request, defaults to "CSR"
    // +optional
    // +kubebuilder:default="CSR"
    CSRField string `json:"csrField"`
    // DurationField is the name of the parameter to use for the certificate duration,
    // if empty, duration will not be sent to the server
    // +optional
    DurationField *string `json:"durationField,omitempty"`
    // HttpTimeout is the timeout for HTTP requests in seconds, defaults to "5"
    // +optional
    // +kubebuilder:default="5"
    HttpTimeout int `json:"httpTimeout"`
    // Only one of the fields below should be set
    // Name of the secret holding 'username' and 'password' keys for basic auth
    // +optional
    BasicAuthSecretRef *SecretSelector `json:"basicAuthSecretRef,omitempty"`
    // Name of the secret holding the token for bearer auth
    // +optional
    TokenSecretRef *SecretSelector `json:"tokenSecretRef,omitempty"`
}

type SecretSelector struct {
    // Name of the secret
    Name string `json:"name"`
    // Namespace of the secret, defaults to the issuer namespace
    // +optional
    Namespace *string `json:"namespace,omitempty"`
}
