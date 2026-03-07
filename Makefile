# Project settings
BINARY := nocloud-init
BUILD_DIR := build
SRC := main.go

.PHONY: all build clean tidy

all: build

build: tidy
	@echo "Ensuring build directory..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building..."
	@go build -o $(BUILD_DIR)/$(BINARY) $(SRC)
	@echo "Done. Compiled as $(BUILD_DIR)/$(BINARY)"

tidy:
	@echo "Tidying..."
	@go mod tidy

clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)

