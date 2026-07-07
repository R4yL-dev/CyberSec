# netscan-go — build and privilege management
BIN_DIR  := bin
BINS     := ns-discover ns-ingest ns-enrich ns-status
DISCOVER := $(BIN_DIR)/ns-discover
CAPS     := cap_net_raw,cap_net_admin=eip

.PHONY: all build test vet tidy setcap dropcap clean

all: build

## build: compile all binaries into bin/
build:
	@mkdir -p $(BIN_DIR)
	@for b in $(BINS); do echo "  build $$b"; go build -o $(BIN_DIR)/$$b ./cmd/$$b; done
	@echo "built into $(BIN_DIR)/"

## test: run the test suite
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## tidy: sync go.mod/go.sum
tidy:
	go mod tidy

## setcap: grant raw-socket/pcap capability to ns-discover (needs sudo).
## Rebuilding the binary clears it — re-run after every `make build`.
setcap: $(DISCOVER)
	sudo setcap $(CAPS) $(DISCOVER)
	@getcap $(DISCOVER)

## dropcap: remove the capability from ns-discover
dropcap:
	-sudo setcap -r $(DISCOVER)
	@getcap $(DISCOVER) || true

## clean: remove built binaries
clean:
	rm -rf $(BIN_DIR)
