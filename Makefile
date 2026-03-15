# Project metadata
NAME := nocloud-init
VERSION := $(shell git describe --tags --abbrev=0)
BUILT_BY ?= DemiCloud

# Base linker flags (used for dev builds)
LDFLAGS := -X main.version=$(VERSION)

# Release linker flags (strip symbols + trim paths)
RELEASE_LDFLAGS := $(LDFLAGS) -s -w \
	-X main.commit=$(shell git rev-parse --short HEAD) \
	-X main.date=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") \
	-X main.builtBy=$(BUILT_BY)

# Target platforms
PLATFORMS := linux/amd64 linux/arm64

# Default build (debug symbols kept)
build:
	mkdir -p build
	go mod tidy
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o build/$(NAME) ./cmd/nocloud-init/

# Release build (static, stripped, reproducible-ish)
release: clean
	mkdir -p dist
	go mod tidy
	$(foreach platform,$(PLATFORMS), \
		OS=$(word 1,$(subst /, ,$(platform))); \
		ARCH=$(word 2,$(subst /, ,$(platform))); \
		echo "Building $$OS/$$ARCH"; \
		GOOS=$$OS GOARCH=$$ARCH CGO_ENABLED=0 go build -trimpath -ldflags "$(RELEASE_LDFLAGS)" -o dist/$(NAME) ./cmd/nocloud-init/; \
		tar -czf dist/$(NAME)_$(VERSION)_$${OS}_$${ARCH}.tar.gz -C dist $(NAME); \
		rm dist/$(NAME); \
	)
	cd dist && sha256sum *.tar.gz > checksums.txt

clean:
	rm -rf build dist
