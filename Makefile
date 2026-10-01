.PHONY: all build test clean install lint fmt

BINARY=tidegate
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

all: build

# Static build: no glibc version requirement, runs on any distro (the
# Dockerfile already builds this way). modernc/sqlite is pure Go.
CGO_ENABLED ?= 0
export CGO_ENABLED

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/tidegate

test:
	go test -v -race ./...

test-short:
	go test -v ./...

fmt:
	go fmt ./...

lint:
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

clean:
	rm -rf bin/ dist/

# Install for the current user. Default scope "auto": /usr/local/bin when
# writable, otherwise ~/.local/bin.
# Override with:  make install PREFIX=/usr/local/bin   or   PREFIX=~/.local/bin
PREFIX ?= auto

install: build
	@if [ "$(PREFIX)" = "auto" ] || [ -z "$(PREFIX)" ]; then \
		if [ -w /usr/local/bin ]; then \
			echo "install: /usr/local/bin is writable"; \
			cp bin/$(BINARY) /usr/local/bin/$(BINARY); \
			echo "✓ installed to /usr/local/bin/$(BINARY)"; \
		else \
			echo "install: /usr/local/bin not writable, using ~/.local/bin (run 'make install PREFIX=/usr/local/bin' with sudo for system-wide)"; \
			mkdir -p $(HOME)/.local/bin; \
			cp bin/$(BINARY) $(HOME)/.local/bin/$(BINARY); \
			echo "✓ installed to $(HOME)/.local/bin/$(BINARY)"; \
			if ! echo ":$$PATH:" | grep -q ":$(HOME)/.local/bin:"; then \
				echo "⚠ $(HOME)/.local/bin is not in PATH — add: export PATH=\"$$HOME/.local/bin:$$PATH\""; \
			fi; \
		fi; \
	else \
		mkdir -p $(PREFIX); \
		cp bin/$(BINARY) $(PREFIX)/$(BINARY); \
		echo "✓ installed to $(PREFIX)/$(BINARY)"; \
	fi

# Cross-compile for all platforms
dist:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		OS=$${platform%/*}; \
		ARCH=$${platform#*/}; \
		echo "Building $$OS/$$ARCH..."; \
		GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o dist/$(BINARY)-$$OS-$$ARCH ./cmd/tidegate; \
	done

# Quick smoke test
smoke: build
	./bin/$(BINARY) version
	./bin/$(BINARY) classify --help