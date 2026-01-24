# Makefile for Paigram

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=paigram

# Proto parameters
PROTO_DIR=proto
PROTO_OUT_DIR=internal/grpc/pb
PROTO_FILES=$(shell find $(PROTO_DIR) -name '*.proto')

# Build parameters
BUILD_TAGS=
LDFLAGS=

.PHONY: all build clean test proto help

all: build

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## build: Build the binary
build:
	$(GOBUILD) -tags "$(BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) -v ./main.go

## build-debug: Build the binary with debug mode (includes swagger)
build-debug:
	$(GOBUILD) -tags "debug" -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) -v ./main.go

## build-release: Build the binary for release (without swagger)
build-release:
	$(GOBUILD) -tags "release" -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) -v ./main.go

## test: Run tests
test:
	$(GOTEST) -v ./...

## test-cover: Run tests with coverage
test-cover:
	$(GOTEST) -cover -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## clean: Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

## deps: Download dependencies
deps:
	$(GOMOD) download

## deps-update: Update dependencies
deps-update:
	$(GOGET) -u ./...
	$(GOMOD) tidy

## proto: Generate code from proto files
proto:
	@echo "Generating Go code from proto files..."
	@mkdir -p $(PROTO_OUT_DIR)
	@for file in $(PROTO_FILES); do \
		echo "Processing $$file..."; \
		protoc \
			--go_out=$(PROTO_OUT_DIR) --go_opt=paths=source_relative \
			--go-grpc_out=$(PROTO_OUT_DIR) --go-grpc_opt=paths=source_relative \
			-I$(PROTO_DIR) \
			$$file; \
	done

## proto-install: Install protoc and plugins
proto-install:
	@echo "Installing protoc plugins..."
	$(GOGET) google.golang.org/protobuf/cmd/protoc-gen-go
	$(GOGET) google.golang.org/grpc/cmd/protoc-gen-go-grpc

## dev-setup: Install development tools
dev-setup: deps proto-install
	@echo "Installing development tools..."
	go install github.com/go-swagger/go-swagger/cmd/swagger@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Development setup complete!"

## run: Run the application
run:
	$(GOCMD) run main.go

## run-debug: Run the application with debug mode (includes swagger)
run-debug:
	$(GOCMD) run -tags debug main.go

## swagger: Generate swagger documentation
swagger:
	swagger generate spec -o ./docs/swagger.json --scan-models -m

## swagger-serve: Generate swagger docs and run in debug mode
swagger-serve: swagger run-debug

## lint: Run golangci-lint
lint:
	golangci-lint run

## fmt: Format code
fmt:
	$(GOCMD) fmt ./...

## vet: Run go vet
vet:
	$(GOCMD) vet ./...

## migrate-up: Run database migrations up
migrate-up:
	$(GOCMD) run main.go migrate up

## migrate-down: Run database migrations down
migrate-down:
	$(GOCMD) run main.go migrate down

## docker-build: Build docker image
docker-build:
	docker build -t paigram:latest .

## docker-run: Run docker container
docker-run:
	docker-compose up -d