BINARY_NAME := dudu-probe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/seakee/dudu-probe/internal/version.Version=$(VERSION) \
	-X github.com/seakee/dudu-probe/internal/version.Commit=$(COMMIT) \
	-X github.com/seakee/dudu-probe/internal/version.BuildDate=$(DATE)

.PHONY: all build build-linux test vet clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/dudu-probe

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/dudu-probe
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/dudu-probe

test:
	go test -v -race ./...
	bash scripts/test_install.sh
vet:
	go vet ./...

clean:
	rm -rf bin/ dist/
