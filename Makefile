BINARY      := registry
PKG         := ./cmd/registry
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DATA_DIR    ?= ./data
IMAGE       ?= container-registry:$(VERSION)

GO          ?= go
GOFLAGS     := -trimpath
LDFLAGS     := -s -w -X main.version=$(VERSION)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the registry binary into ./bin
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

.PHONY: run
run: ## Run the registry locally on :5000
	REGISTRY_DATA_DIR=$(DATA_DIR) $(GO) run $(PKG)

.PHONY: test
test: ## Run the test suite
	$(GO) test ./...

.PHONY: test-race
test-race: ## Run the test suite under the race detector
	$(GO) test -race ./...

.PHONY: cover
cover: ## Run tests and open a coverage report
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format all Go source
	gofmt -w ./cmd ./internal ./web

.PHONY: vuln
vuln: ## Report known vulnerabilities in reachable code
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: staticcheck
staticcheck: ## Run staticcheck
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest ./...

.PHONY: check
check: fmt vet test ## Format, vet and test

.PHONY: audit
audit: vet staticcheck vuln ## Everything CI checks except the image scan

.PHONY: certs
certs: ## Generate a development TLS certificate into ./certs
	@./scripts/dev-certs.sh $(HOSTS)

.PHONY: conformance
conformance: build ## Run the official OCI distribution-spec conformance suite
	@./scripts/conformance.sh

.PHONY: docker
docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) -t container-registry:latest .

.PHONY: up
up: ## Start the registry with docker compose
	docker compose up -d --build

.PHONY: down
down: ## Stop the docker compose stack
	docker compose down

.PHONY: logs
logs: ## Follow docker compose logs
	docker compose logs -f

.PHONY: clean
clean: ## Remove build output and local data
	rm -rf bin coverage.out $(DATA_DIR)
