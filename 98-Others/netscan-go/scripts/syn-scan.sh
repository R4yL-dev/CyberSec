#!/usr/bin/env bash
#
# syn-scan.sh — run a SYN discovery scan with a scoped, auto-removed iptables
# guard. The guard drops only the kernel's stray RSTs for THIS scan's source
# port (not all RSTs system-wide), and is removed on exit even on Ctrl-C.
#
# Usage:
#   scripts/syn-scan.sh --targets 1.1.1.0/24 --ports 80,443 [extra ns-discover flags...]
#   scripts/syn-scan.sh --targets 1.1.1.0/24 | ns-ingest --db scan.db
#
# Override the source port with SRC_PORT=NNN. The scan itself runs unprivileged
# thanks to CAP_NET_RAW (see `make setcap`); only iptables add/remove uses sudo.
set -euo pipefail

SRC_PORT="${SRC_PORT:-44444}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HERE/bin/ns-discover"

if [[ ! -x "$BIN" ]]; then
  echo "syn-scan: $BIN not found — run 'make build' first" >&2
  exit 1
fi
if ! getcap "$BIN" | grep -q cap_net_raw; then
  echo "syn-scan: ns-discover lacks CAP_NET_RAW — run 'make setcap'" >&2
  exit 1
fi

RULE=(OUTPUT -p tcp --sport "$SRC_PORT" --tcp-flags RST RST -j DROP)
added=0
cleanup() {
  if [[ "$added" == 1 ]]; then
    sudo iptables -D "${RULE[@]}" 2>/dev/null || true
    echo "syn-scan: removed iptables RST guard (sport $SRC_PORT)" >&2
  fi
}
trap cleanup EXIT INT TERM

if ! sudo iptables -C "${RULE[@]}" 2>/dev/null; then
  sudo iptables -A "${RULE[@]}"
  added=1
  echo "syn-scan: added iptables RST guard (sport $SRC_PORT)" >&2
fi

"$BIN" --mode syn --src-port "$SRC_PORT" "$@"
