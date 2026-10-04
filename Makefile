GO ?= go
# Everything the host build places on disk goes under BIN. The release build
# (any target) always goes to dist/ instead — scripts/build-release.sh owns
# that layout and its per-artifact assertions.
BIN ?= bin

.PHONY: test race build release vet fmt devnet

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

# `make release` — BOTH binaries for ALL six supported targets
# (darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64,
# windows/arm64) into dist/ with a SHA256SUMS covering every artifact. All
# build flags and all artifact assertions (count == target count, each
# artifact really reports its own architecture, .exe on Windows) live in
# scripts/build-release.sh, so there is ONE build story — this target
# replaced M4's early single-target `make arm64`; the deploy recipe's
# scripts/deploy/build.sh now routes through the same script. The version
# stays whatever internal/version declares; no -ldflags injection here, so
# the binary cannot disagree with the source of truth. CI runs this on every
# push, so no platform's artifact can rot silently.
release:
	./scripts/build-release.sh

fmt:
	$(GO) fmt ./...

devnet: build
	$(BIN)/b10coin devnet --blocks 100
