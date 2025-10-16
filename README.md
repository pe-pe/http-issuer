# HTTP Issuer for cert-manager

A universal cert-manager issuer for interacting with internal Certificate Authorities (CAs) that expose custom HTTP APIs.

## Motivation

This project was created to provide a universal issuer that can accommodate the need for cert-manager to interact with internal CAs exposing custom APIs without the need to create multiple custom issuers or update them each time the API changes.

Instead of developing and maintaining separate issuer implementations for each CA vendor or custom internal CA solution, the HTTP Issuer follows a **convention over configuration** approach. It provides a flexible, configurable issuer that can adapt to various HTTP-based CA APIs through simple configuration changes rather than code modifications.

## Features

- **Universal HTTP CA Integration**: Works with CA that exposes an HTTP API for certificate signing
- **Multiple Authentication Methods**: Supports Basic Auth and Bearer Token authentication
- **Flexible Configuration**: Configurable HTTP paths, methods, and request parameters
- **Convention over Configuration**: Minimal setup required with sensible defaults
- **Namespace and Cluster Scoped**: Supports both `HttpIssuer` (namespace-scoped) and `HttpClusterIssuer` (cluster-scoped) resources
- **cert-manager Integration**: Built using the official cert-manager issuer-lib
- **Production Ready**: Includes health checks, proper RBAC, and security best practices

## Architecture

The HTTP Issuer consists of:

- **Custom Resource Definitions (CRDs)**: `HttpIssuer` and `HttpClusterIssuer`
- **Controller**: Watches for `CertificateRequest` resources and processes them via HTTP CA APIs
- **Signer**: Handles the actual HTTP communication with the CA endpoints

## Installation

### Prerequisites

- Kubernetes cluster with cert-manager installed
- Access to deploy custom resources and controllers

### Deploy the HTTP Issuer

1. **Apply the CRDs and RBAC:**
   ```bash
   kubectl apply -f deploy/crds/
   kubectl apply -f deploy/rbac/
   ```

2. **Deploy the controller:**
   ```bash
   kubectl apply -k deploy/static/
   ```

The controller will be deployed in the `cert-manager` namespace by default.

## Configuration

### HttpIssuer (Namespace-scoped)

```yaml
apiVersion: ca.internal/v1alpha1
kind: HttpIssuer
metadata:
  name: my-http-issuer
  namespace: default
spec:
  # Base URL of your CA API
  url: https://my-ca.example.com
  # Health check endpoint (optional, defaults to "/healthz")
  healthPath: /health
  # Certificate signing endpoint (required)
  signPath: /api/v1/sign
  # HTTP method for signing (optional, defaults to "POST")
  signMethod: POST
  # Field name for CSR in the request (optional, defaults to "CSR")
  csrField: csr
  # Field name for cert duration (minutes) provided in the request (optional)
  durationField: validity_period
  # HTTP timeout in seconds (optional, defaults to 30)
  httpTimeout: 10
  # Authentication (choose one)
  basicAuthSecretRef: # must follow kubernetes.io/basic-auth type
    name: ca-credentials
    namespace: default  # optional, defaults to issuer namespace
  # OR use token authentication
  # tokenSecretRef: # must contain "token" key
  #   name: ca-token
```

### HttpClusterIssuer (Cluster-scoped)

```yaml
apiVersion: ca.internal/v1alpha1
kind: HttpClusterIssuer
metadata:
  name: my-cluster-issuer
spec:
  url: https://my-ca.internal.com
  signPath: /api/v1/sign
  basicAuthSecretRef:
    name: ca-credentials
    namespace: cert-manager  # required for cluster issuers
```

### Authentication Secrets

**Basic Authentication:**
```yaml
apiVersion: v1
kind: Secret
type: kubernetes.io/basic-auth
metadata:
  name: ca-credentials
  namespace: default
data:
  username: <base64-encoded-username>
  password: <base64-encoded-password>
```

**Bearer Token:**
```yaml
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: ca-token
  namespace: default
data:
  token: <base64-encoded-token>
```

## Usage

### Requesting Certificates

Once an issuer is configured, you can request certificates using standard cert-manager `Certificate` resources:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
  namespace: default
spec:
  secretName: example-cert-tls
  duration: 24h
  renewBefore: 8h
  commonName: example.com
  dnsNames:
  - example.com
  - www.example.com
  issuerRef:
    group: ca.internal
    kind: HttpIssuer
    name: my-http-issuer
```

### Direct CertificateRequest

You can also create `CertificateRequest` resources directly:

```yaml
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
  name: example-csr
  namespace: default
spec:
  request: <base64-encoded-csr>
  duration: 24h
  issuerRef:
    group: ca.internal
    kind: HttpIssuer
    name: my-http-issuer
```

## CA API Requirements

Your CA's HTTP API should meet these requirements:

### Health Check Endpoint
- **Method**: `GET`
- **Path**: Configurable (default: `/healthz`)
- **Response**: HTTP 200 for healthy status

### Certificate Signing Endpoint
- **Method**: Configurable (default: `POST`)
- **Path**: Configurable (required)
- **Request Format**: `application/json`
- **Request Parameters**:
  - CSR field (default: `CSR`): PEM-encoded Certificate Signing Request
  - Duration field (optional): Certificate validity duration in minutes
- **Response**: PEM-encoded signed certificate
- **Authentication**: Basic Auth or Bearer Token

### Example CA API Response

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL8+9...
-----END CERTIFICATE-----
```

## Development

### Building

```bash
# Build the binary
make build
# Build the Docker image
make docker-build
# Run tests
make test
```

### Running Locally

```bash
# Run the controller locally
make run
```

### Testing

The project includes end-to-end tests that can be run against a Kubernetes cluster:

```bash
# Run unit tests
make test
# Run e2e tests (sets up Kind cluster automatically)
make test-e2e
# Clean up e2e test environment
make cleanup-test-e2e
```

## API Reference

### HttpCertificateSource Spec

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `url` | `string` | Base URL of the CA API | Required |
| `healthPath` | `string` | Health check endpoint path | `/healthz` |
| `signPath` | `string` | Certificate signing endpoint path | Required |
| `signMethod` | `string` | HTTP method for signing requests | `POST` |
| `csrField` | `string` | Request parameter name for CSR | `CSR` |
| `durationField` | `*string` | Request parameter name for duration | `nil` |
| `httpTimeout` | `int` | HTTP request timeout in seconds | `30` |
| `basicAuthSecretRef` | `*SecretSelector` | Basic auth credentials secret | `nil` |
| `tokenSecretRef` | `*SecretSelector` | Bearer token secret | `nil` |

### SecretSelector

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `name` | `string` | Secret name | Required |
| `namespace` | `*string` | Secret namespace | Issuer namespace |

## Troubleshooting

### Common Issues

1. **Certificate Request Pending**: Check issuer status and CA endpoint health
2. **Authentication Errors**: Verify secret credentials and CA API requirements
3. **Timeout Errors**: Increase `httpTimeout` value or check network connectivity

### Debugging

Enable debug logging by setting the controller's log level:

```bash
kubectl patch deployment http-issuer-controller -n cert-manager -p '{"spec":{"template":{"spec":{"containers":[{"name":"http-issuer-controller","args":["--zap-log-level=debug"]}]}}}}'
```

Check controller logs:

```bash
kubectl logs -n cert-manager deployment/http-issuer-controller
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

## Related Projects

- [cert-manager](https://github.com/cert-manager/cert-manager) - Native Kubernetes certificate management controller
- [cert-manager issuer-lib](https://github.com/cert-manager/issuer-lib) - Library for building cert-manager issuers
- [CA Demo API](https://github.com/pe-pe/ca-demo-api/) - Example CA API for testing purposes
