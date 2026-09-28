# Developer shortcuts; CI runs the same commands (.github/workflows/ci.yml).
# WBFT_SPEC_DIR names a checkout of github.com/0xmhha/wbft-spec at the
# commit of spec.lock.

.PHONY: all build test lint deps e2e vectors catalog-check

all: build test lint

build:
	go build -o bin/wbft-inspector ./cmd/wbft-inspector
	go build -o bin/self-adapter ./adapters/self

test:
	go vet ./...
	go test -race ./...

lint: deps
	golangci-lint run ./...
	cd test/e2e && golangci-lint run ./...

deps:
	scripts/check-deps.sh

# End-to-end: the wbft simulator (pinned in test/e2e/go.mod) writes event
# streams and the inspector checks them; with WBFT_SPEC_DIR also every
# public vector against the wbft adapter. Needs cgo.
e2e:
	cd test/e2e && WBFT_SPEC_DIR=$(WBFT_SPEC_DIR) go test -count=1 -timeout 30m -v ./...

# The inspector's own model against the vectors of the handlers it implements.
vectors: build
	bin/wbft-inspector vectors --impl bin/self-adapter --vectors $(WBFT_SPEC_DIR)/spec/vectors --runner timers --handler round_timeout --out /dev/null
	bin/wbft-inspector vectors --impl bin/self-adapter --vectors $(WBFT_SPEC_DIR)/spec/vectors --runner chain --handler config_at --out /dev/null

# The embedded requirement list against the specification, and a catalog
# row for every Observable requirement of A-05 and A-06.
catalog-check: build
	bin/wbft-inspector catalog coverage --spec $(WBFT_SPEC_DIR)/spec --chapters A-05,A-06
	WBFT_SPEC_VECTORS=$(WBFT_SPEC_DIR)/spec/vectors go test -count=1 -run TestParsesPublishedVectors ./internal/yamlsubset/
