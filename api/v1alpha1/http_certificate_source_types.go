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
