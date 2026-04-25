# Project metadata
NAME     := nocloud-init
VERSION  := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
BUILT_BY ?= DemiCloud

# Install destination
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/sbin

# Base linker flags (dev builds — version only)
LDFLAGS := -X main.version=$(VERSION)

# Release linker flags (strip + trim + full metadata)
RELEASE_LDFLAGS := $(LDFLAGS) -s -w \
	-X main.commit=$(shell git rev-parse --short HEAD) \
	-X main.date=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") \
	-X main.builtBy=$(BUILT_BY)

# Target platforms for `make release`
PLATFORMS := linux/amd64 linux/arm64

.PHONY: build build-release test vet install release clean help

build: ## Development build → build/nocloud-init (debug symbols; version = "dev" if no tags)
	mkdir -p build
	go mod tidy
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o build/$(NAME) ./cmd/nocloud-init/

build-release: ## Release build for the local system → build/nocloud-init (stripped, trimpath, full metadata)
	mkdir -p build
	go mod tidy
	CGO_ENABLED=0 go build -trimpath -ldflags "$(RELEASE_LDFLAGS)" -o build/$(NAME) ./cmd/nocloud-init/

test: ## Run the test suite
	go test -count=1 ./...

vet: ## Run go vet static analysis
	go vet ./...

install: build-release ## Build release binary for local system and install to $(DESTDIR)$(BINDIR) (default: /usr/local/sbin)
	install -D -m 0755 build/$(NAME) $(DESTDIR)$(BINDIR)/$(NAME)

release: clean ## Stripped, trimpath, multi-arch release tarballs → dist/
	mkdir -p dist
	@set -e; for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d/ -f1); \
		ARCH=$$(echo $$platform | cut -d/ -f2); \
		echo "building $$OS/$$ARCH"; \
		GOOS=$$OS GOARCH=$$ARCH CGO_ENABLED=0 go build -trimpath \
			-ldflags "$(RELEASE_LDFLAGS)" \
			-o dist/$(NAME) ./cmd/nocloud-init/; \
		tar -czf dist/$(NAME)_$(VERSION)_$${OS}_$${ARCH}.tar.gz -C dist $(NAME); \
		rm dist/$(NAME); \
	done
	@echo "==> Checksums"
	cd dist && sha256sum *.tar.gz > checksums.txt && cat checksums.txt

clean: ## Remove build/ and dist/
	rm -rf build dist

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
	     /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
