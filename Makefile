APP_NAME := honey-postgres
VERSION  := $(shell git describe --tags --always --dirty)
BUILD_DIR := bin

GOOS_LIST := linux darwin windows
GOARCH_LIST := amd64 arm64

.PHONY: all clean

all: clean build

build:
	@mkdir -p $(BUILD_DIR)
	@for os in $(GOOS_LIST); do \
		for arch in $(GOARCH_LIST); do \
			ext=""; \
			if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
			echo "Building $$os/$$arch"; \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -ldflags "-s -w -X main.version=$(VERSION)" \
			-o $(BUILD_DIR)/$(APP_NAME)-$$os-$$arch$$ext ; \
		done \
	done

clean:
	rm -rf $(BUILD_DIR)
