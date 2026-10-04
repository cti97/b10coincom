GO ?= go
# Everything the build targets place on disk goes under BIN (the deploy
# recipe and ci.yml both assert against $(BIN)/*-linux-arm64, so a change
# here is visible in the artifact checks, not silent).
BIN ?= bin

.PHONY: test race build arm64 vet fmt devnet

# -count=1 defeats the test result cache, so a flaky test cannot pass on
# the strength of an earlier run.
test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o $(BIN)/b10coin ./cmd/b10coin

# The M4 Pi target: cross-compile BOTH binaries for linux/arm64 (64-bit
# Raspberry Pi OS). This is deliberately the ONE target M4 needs — Task 9
# replaces it with the six-platform release matrix; until then any new
# platform gets its own narrow target here rather than flags added to it.
# The version stays whatever internal/version declares (0.1.0); no -ldflags
# injection here, so the binary cannot disagree with the source of truth.
# Building this on a laptop is not enough to call it supported: ci.yml
# builds these artifacts on every push, so the Pi binary cannot rot silently.
arm64:
	GOOS=linux GOARCH=arm64 $(GO) build -o $(BIN)/b10coin-linux-arm64 ./cmd/b10coin
	GOOS=linux GOARCH=arm64 $(GO) build -o $(BIN)/b10coin-relay-linux-arm64 ./cmd/b10coin-relay

fmt:
	$(GO) fmt ./...

devnet: build
	$(BIN)/b10coin devnet --blocks 100