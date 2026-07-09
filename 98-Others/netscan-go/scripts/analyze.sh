#!/usr/bin/env bash
#
# analyze.sh — run a real SYN scan + a connect reference, and bundle a complete
# diagnostic into one file to hand off for analysis (report + run log + SYN-vs-
# connect diff + environment context).
#
# Usage:
#   scripts/analyze.sh <targets> [extra scan flags for the SYN scan...]
#
# Examples:
#   scripts/analyze.sh 195.202.193.0/26
#   scripts/analyze.sh 195.202.193.0/26 --all-ports 1-10000 --rate 5000
#
# SYN needs the capability: run `sudo make setcap` once first (or run this as root).
# Keep the range SMALL (a /26 or less) — the output is meant to be pasted.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETSCAN="$HERE/netscan"
DISC="$HERE/bin/ns-discover"

[[ $# -ge 1 ]] || { echo "usage: scripts/analyze.sh <targets> [extra scan flags...]" >&2; exit 1; }
TARGETS="$1"; shift
EXTRA=("$@")   # extra flags for the full SYN scan (e.g. --all-ports 1-10000)

# --- SYN availability check (capability or root) ---
if [[ "$(id -u)" -ne 0 ]] && ! getcap "$DISC" 2>/dev/null | grep -q cap_net_raw; then
	echo "analyze: SYN unavailable — run 'sudo make setcap' first (or run this as root)." >&2
	echo "         (SYN is the whole point of this comparison.)" >&2
	exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
DIR="ns-analysis-$TS"
mkdir -p "$DIR"
OUT="$DIR/analysis.txt"
SYN_DB="$DIR/syn.db"
SYNFAST_DB="$DIR/synfast.db"
CONNFAST_DB="$DIR/connfast.db"

echo "analyze: working in $DIR/ …" >&2

{
	echo "===================================================================="
	echo "netscan analysis · $TS"
	echo "===================================================================="
	echo "targets : $TARGETS"
	echo "extra   : ${EXTRA[*]:-(none)}"
	echo "host    : $(uname -a)"
	echo "getcap  : $(getcap "$DISC" 2>/dev/null || echo '(none)')  · uid=$(id -u)"
	command -v git >/dev/null && echo "commit  : $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null) $(git -C "$HERE" status --porcelain 2>/dev/null | grep -q . && echo '(dirty)')"
	echo
} > "$OUT"

# --- 1) Full SYN scan (adaptive + any extra flags): the rich report source ---
echo "analyze: [1/4] full SYN scan (report source)…" >&2
{
	echo "#################### RUN LOG — full SYN scan ####################"
	echo "\$ netscan scan --syn --targets $TARGETS ${EXTRA[*]:-} --db syn.db"
	echo
} >> "$OUT"
"$NETSCAN" scan --syn --targets "$TARGETS" "${EXTRA[@]}" --db "$SYN_DB" >> "$OUT" 2>&1
echo >> "$OUT"

# --- 2) Clean prober comparison: both --fast, same top-100, no ICMP/widen ---
echo "analyze: [2/4] SYN --fast (diff baseline)…" >&2
"$NETSCAN" scan --syn --fast --targets "$TARGETS" --db "$SYNFAST_DB" >/dev/null 2>&1
echo "analyze: [3/4] connect --fast (diff reference)…" >&2
"$NETSCAN" scan --connect --fast --targets "$TARGETS" --db "$CONNFAST_DB" >/dev/null 2>&1

# --- 3) Report on the full SYN scan ---
echo "analyze: [4/4] generating report + diff…" >&2
{
	echo "#################### REPORT — full SYN scan ####################"
	echo
} >> "$OUT"
"$NETSCAN" report --db "$SYN_DB" >> "$OUT" 2>&1

# --- 4) Diff: SYN --fast vs connect --fast (pure discovery false-negative check) ---
{
	echo
	echo "#################### DIFF — SYN --fast (A) vs connect --fast (B) ####################"
	echo "# A-only = SYN found, connect didn't (SYN reliability wins — good)"
	echo "# B-only = connect found, SYN MISSED  (potential false negative — the concern)"
	echo
} >> "$OUT"
"$NETSCAN" diff --db "$SYNFAST_DB" --db "$CONNFAST_DB" >> "$OUT" 2>&1

echo >&2
echo "analyze: done → $OUT" >&2
echo "analyze: paste the contents of that file for analysis." >&2
