GO ?= go

.PHONY: test race build vet fmt devnet

# -count=1 defeats the test result cache, so a flaky test cannot pass on
# the strength of an earlier run.
test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/b10coin ./cmd/b10coin

fmt:
	$(GO) fmt ./...

devnet: build
	./bin/b10coin devnet --blocks 100
