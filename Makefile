SHELL := /bin/bash
GO    ?= go
PKG   := ./...
BIN   := bin/mcp-gate

.PHONY: all build test vet fmt lint clean install e2e cover

all: vet test build

build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/mcp-gate

test:
	$(GO) test -race -count=1 $(PKG)

vet:
	$(GO) vet $(PKG)

fmt:
	$(GO) fmt $(PKG)

cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

e2e:
	$(GO) test -race -count=1 -tags=e2e ./internal/e2e/...

install: build
	install -m 0755 $(BIN) $(HOME)/.local/bin/mcp-gate

clean:
	rm -rf bin coverage.out
