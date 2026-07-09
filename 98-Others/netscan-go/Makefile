# netscan-go — build, privileges, install
BIN_DIR  := bin
BINS     := ns-discover ns-ingest ns-enrich ns-status
DISCOVER := $(BIN_DIR)/ns-discover
CAPS     := cap_net_raw,cap_net_admin=eip
PREFIX   ?= $(HOME)/.local

.PHONY: all build setup syn geoip test vet tidy setcap dropcap install uninstall clean help

all: build

## build: compile all binaries into bin/ (no sudo, no network)
build:
	@mkdir -p $(BIN_DIR)
	@for b in $(BINS); do echo "  build $$b"; go build -o $(BIN_DIR)/$$b ./cmd/$$b; done
	@echo "built into $(BIN_DIR)/"
	@getcap $(DISCOVER) 2>/dev/null | grep -q cap_net_raw || \
		echo "  note: SYN mode needs the raw-socket capability — run 'make setcap' (or 'make syn')"

## setup: build + download GeoIP databases (first-time "give me everything", no sudo)
setup: build geoip

## syn: build, then grant the SYN capability in one step
syn: build setcap

## geoip: download the free DB-IP lite country+ASN databases into data/ (idempotent)
geoip:
	@bash scripts/fetch-geoip.sh

## setcap: grant raw-socket/pcap capability to ns-discover (sudo). Cleared on each build.
setcap: $(DISCOVER)
	sudo setcap $(CAPS) $(DISCOVER)
	@getcap $(DISCOVER)

## dropcap: remove the capability from ns-discover
dropcap:
	-sudo setcap -r $(DISCOVER)
	@getcap $(DISCOVER) 2>/dev/null || true

## install: symlink the 'netscan' launcher onto PATH (PREFIX/bin, default ~/.local).
## For `sudo netscan`, install to a system dir in sudo's secure_path:
##   sudo make install PREFIX=/usr/local
install:
	@mkdir -p $(PREFIX)/bin
	@ln -sf $(abspath netscan) $(PREFIX)/bin/netscan
	@echo "linked $(PREFIX)/bin/netscan -> $(abspath netscan)"
	@case ":$$PATH:" in *":$(PREFIX)/bin:"*) ;; *) echo "  note: add $(PREFIX)/bin to your PATH";; esac
	@echo "  for 'sudo netscan' too: sudo make install PREFIX=/usr/local"

## uninstall: remove the launcher symlink
uninstall:
	rm -f $(PREFIX)/bin/netscan

## test: run the test suite
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## tidy: sync go.mod/go.sum
tidy:
	go mod tidy

## clean: remove built binaries
clean:
	rm -rf $(BIN_DIR)

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
