TAG="$(shell git describe --tags --always)"
VERSION=$(shell echo $(TAG) | sed 's@^v@@' | sed 's@-@+@g' | tr -d '\n')
GOOS:=$(shell go env GOOS)
GOARCH:=$(shell go env GOARCH)

.PHONY: version
version: ## Print version
	@echo $(VERSION)

.PHONY: generate
generate: ## Echo version to file
	go generate

.PHONY: build
build: generate
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-s -w" -o createrepo_go