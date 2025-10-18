# Image URL to use all building/pushing image targets
IMG ?= http-issuer-controller:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests.
	go test $$(go list ./... | grep -v /e2e) -cover

# For e2e tests, the default setup assumes Kind is pre-installed
# setup-test-e2e will:
# * Create a Kind cluster named after KIND_CLUSTER variable, if it does not exist
# * Install cert-manager 1.19.1 in the Kind cluster
# * Deploy the http-issuer controller to the Kind cluster
# * Deploy a demo CA API to the Kind cluster to serve test certificates

KIND_CLUSTER ?= http-issuer-test-e2e

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster for e2e tests if it does not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			$(MAKE) docker-build ; \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) ; \
			echo "Deploying cert-manager to Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) apply -f https://github.com/cert-manager/cert-manager/releases/download/$$(awk '/github.com.cert-manager.cert-manager/ { print $$2 }' go.mod)/cert-manager.yaml ; \
			echo "Deploying http-issuer to Kind cluster '$(KIND_CLUSTER)'..."; \
			${CONTAINER_TOOL} save -o _temporary_docker_image.tar ${IMG} ; \
			$(KIND) load image-archive _temporary_docker_image.tar --name $(KIND_CLUSTER) ; \
			rm -f _temporary_docker_image.tar ; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) apply -f deploy/crds ; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) apply -f deploy/rbac ; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) apply -k deploy/static ; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) patch deployment http-issuer-controller -n cert-manager --type='merge' -p='{"spec":{"template":{"spec":{"containers":[{"name":"http-issuer-controller","image":"localhost/${IMG}","imagePullPolicy":"Never"}]}}}}' ; \
			echo "Waiting for cert-manager to be ready..."; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) -n cert-manager wait --for=condition=Available=True deployment/cert-manager --timeout=300s ; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) -n cert-manager wait --for=condition=Available=True deployment/cert-manager-webhook --timeout=300s ; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) -n cert-manager wait --for=condition=Available=True deployment/cert-manager-cainjector --timeout=300s ; \
			echo "Waiting for http-issuer-controller to be ready..."; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) -n cert-manager wait --for=condition=Available=True deployment/http-issuer-controller --timeout=300s ; \
			echo "Deploying ca-demo-api (latest) to serve test certificates..."; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) -n cert-manager run ca-demo-api --image=ghcr.io/pe-pe/ca-demo-api:latest --port=5000 ; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) -n cert-manager expose pod ca-demo-api --name ca --port=80 --target-port=5000 ; \
			echo "Waiting for ca-demo-api to be ready..."; \
			$(KUBECTL) --cluster kind-$(KIND_CLUSTER) -n cert-manager wait --for=condition=Ready pod/ca-demo-api --timeout=300s ; \
			;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) go test -tags=e2e ./e2e/ -v
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

##@ Build

.PHONY: build
build: fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: clean
clean: ## Clean temporary files and bin directory
	go clean -testcache
	rm -rf $(LOCALBIN)

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.4.0

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $$(realpath $(1)-$(3)) $(1)
endef
