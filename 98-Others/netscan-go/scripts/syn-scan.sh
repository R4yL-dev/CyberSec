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
# The source port is randomized per run (so concurrent scans don't share a rule);
# override with SRC_PORT=NNN. The scan itself runs unprivileged thanks to
# CAP_NET_RAW (see `make setcap`); only iptables add/remove uses sudo. Each rule
# is tagged with the comment "netscan-rst-guard" so orphans from a killed run can
# be flushed with `netscan iptables-clean`.
set -euo pipefail

SRC_PORT="${SRC_PORT:-$(( (RANDOM % 20000) + 40000 ))}"
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

RULE=(OUTPUT -p tcp --sport "$SRC_PORT" --tcp-flags RST RST
      -m comment --comment netscan-rst-guard -j DROP)
added=0
KEEPALIVE_PID=""

cleanup() {
  if [[ -n "$KEEPALIVE_PID" ]]; then
    pkill -P "$KEEPALIVE_PID" 2>/dev/null || true # the inner sleep child
    kill "$KEEPALIVE_PID" 2>/dev/null || true
  fi
  [[ "$added" == 1 ]] || return 0
  # Remove every copy of our rule (guards against accidental accumulation).
  while sudo iptables -C "${RULE[@]}" 2>/dev/null; do
    sudo iptables -D "${RULE[@]}" 2>/dev/null || break
  done
  if sudo iptables -C "${RULE[@]}" 2>/dev/null; then
    echo "syn-scan: WARNING could not remove iptables RST guard (sport $SRC_PORT)." >&2
    echo "  remove manually:  sudo iptables -D ${RULE[*]}" >&2
    echo "  or clean all:     netscan iptables-clean" >&2
  else
    echo "syn-scan: removed iptables RST guard (sport $SRC_PORT)" >&2
  fi
}
trap cleanup EXIT INT TERM

# Authenticate once, then keep the sudo timestamp fresh for the whole (possibly
# long) scan so the cleanup -D at the end never re-prompts for a password.
# stdout/stderr are redirected so this background job does NOT inherit the
# NDJSON pipe — otherwise its `sleep` would hold the pipe open and downstream
# (ns-ingest) would never see EOF.
sudo -v
( while true; do sleep 50; sudo -n -v 2>/dev/null || exit; done ) >/dev/null 2>&1 &
KEEPALIVE_PID=$!

if ! sudo iptables -C "${RULE[@]}" 2>/dev/null; then
  sudo iptables -A "${RULE[@]}"
  added=1
  echo "syn-scan: added iptables RST guard (sport $SRC_PORT)" >&2
fi

"$BIN" --mode syn --src-port "$SRC_PORT" "$@"
