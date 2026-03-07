NAME := nocloud-init

# Extract version from the latest Git tag (e.g. v1.0.0)
VERSION := $(shell git describe --tags --abbrev=0)
LDFLAGS := -X main.version=$(VERSION)

BUILD := build
DIST := dist

# Platforms for release builds
PLATFORMS := linux/amd64 linux/arm64

# Default target: local build
all: build-local

# Local build for host platform
build-local:
	mkdir -p $(BUILD)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD)/$(NAME)

# Optional cross-compile:
# make build GOOS=linux GOARCH=arm64
build:
	mkdir -p $(BUILD)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BUILD)/$(NAME)

# Release: build and package all platforms
release: clean $(DIST) $(PLATFORMS)

$(DIST):
	mkdir -p $(DIST)

# Pattern rule for each platform in PLATFORMS
$(PLATFORMS):
	GOOS=$(word 1,$(subst /, ,$@)) \
	GOARCH=$(word 2,$(subst /, ,$@)) \
	go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(NAME)
	tar -czf $(DIST)/$(NAME)_$(VERSION)_$(word 1,$(subst /, ,$@))_$(word 2,$(subst /, ,$@)).tar.gz -C $(DIST) $(NAME)
	rm $(DIST)/$(NAME)

clean:
	rm -rf $(BUILD) $(DIST)
