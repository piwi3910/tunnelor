.PHONY: help build test test-unit test-integration test-coverage lint fmt vet clean install-tools run-server run-client

# Variables
BINARY_SERVER=bin/tunnelord
BINARY_CLIENT=bin/tunnelorc
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"
COVERAGE_FILE=coverage.out

# Default target
help:
	@echo "Tunnelor - QUIC-based Tunneling Platform"
	@echo ""
	@echo "Available targets:"
	@echo "  make build              - Build both server and client binaries"
	@echo "  make build-server       - Build server binary only"
	@echo "  make build-client       - Build client binary only"
	@echo ""
	@echo "  make test               - Run all tests"
	@echo "  make test-unit          - Run unit tests only"
	@echo "  make test-integration   - Run integration tests only"
	@echo "  make test-coverage      - Run tests with coverage report"
	@echo "  make test-race          - Run tests with race detector"
	@echo ""
	@echo "  make lint               - Run golangci-lint"
	@echo "  make fmt                - Format code with goimports"
	@echo "  make vet                - Run go vet"
	@echo "  make check              - Run fmt, vet, and lint"
	@echo ""
	@echo "  make clean              - Remove built binaries and coverage files"
	@echo "  make install-tools      - Install development tools"
	@echo ""
	@echo "  make run-server         - Run server with example config"
	@echo "  make run-client         - Run client with example config"

# Build targets
build: build-server build-client

build-server:
	@echo "Building server..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_SERVER) ./cmd/tunnelord

build-client:
	@echo "Building client..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_CLIENT) ./cmd/tunnelorc

# Test targets
test:
	@echo "Running all tests..."
	$(GO) test ./... -v

test-unit:
	@echo "Running unit tests..."
	$(GO) test ./... -v -short

test-integration:
	@echo "Running integration tests..."
	$(GO) test ./... -v -run Integration -tags=integration

test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	$(GO) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-race:
	@echo "Running tests with race detector..."
	$(GO) test ./... -race -short

# Code quality targets
lint:
	@echo "Running golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout 5m; \
	else \
		echo "golangci-lint not installed. Run 'make install-tools' first."; \
		exit 1; \
	fi

fmt:
	@echo "Formatting code..."
	@if command -v goimports >/dev/null 2>&1; then \
		find . -name '*.go' -not -path "./vendor/*" -exec goimports -w -local github.com/piwi3910/tunnelor {} \;; \
	else \
		echo "goimports not installed. Using gofmt instead..."; \
		$(GO) fmt ./...; \
	fi

vet:
	@echo "Running go vet..."
	$(GO) vet ./...

check: fmt vet lint
	@echo "All checks passed!"

# Utility targets
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f $(COVERAGE_FILE) coverage.html

install-tools:
	@echo "Installing development tools..."
	$(GO) install golang.org/x/tools/cmd/goimports@latest
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install gotest.tools/gotestsum@latest
	@echo "Tools installed successfully!"

# Run targets
run-server:
	@echo "Starting server..."
	@if [ ! -f examples/server.yaml ]; then \
		echo "Error: examples/server.yaml not found"; \
		exit 1; \
	fi
	@$(BINARY_SERVER) --config examples/server.yaml --verbose --pretty

run-client:
	@echo "Starting client..."
	@if [ ! -f examples/client.yaml ]; then \
		echo "Error: examples/client.yaml not found"; \
		exit 1; \
	fi
	@$(BINARY_CLIENT) connect --config examples/client.yaml --verbose --pretty

# Development helpers
watch-test:
	@echo "Watching for changes and running tests..."
	@if command -v gotestsum >/dev/null 2>&1; then \
		gotestsum --watch; \
	else \
		echo "gotestsum not installed. Run 'make install-tools' first."; \
		exit 1; \
	fi

deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

verify:
	@echo "Verifying dependencies..."
	$(GO) mod verify

# Generate test certificates (for development)
gen-certs:
	@echo "Generating test TLS certificates..."
	@mkdir -p examples/certs
	openssl req -x509 -newkey rsa:4096 -keyout examples/certs/server.key \
		-out examples/certs/server.crt -days 365 -nodes \
		-subj "/CN=localhost"
	@echo "Certificates generated in examples/certs/"

# Docker targets (future)
docker-build:
	@echo "Building Docker images..."
	docker build -t tunnelor-server:latest -f Dockerfile.server .
	docker build -t tunnelor-client:latest -f Dockerfile.client .

# CI/CD target
ci: deps check test-coverage
	@echo "CI pipeline completed successfully!"
