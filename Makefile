GO ?= go

.PHONY: test build vet fmt devnet

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/b10coin ./cmd/b10coin

fmt:
	$(GO) fmt ./...

devnet: build
	./bin/b10coin devnet --blocks 100