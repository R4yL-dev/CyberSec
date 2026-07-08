#!/usr/bin/env bash
#
# fetch-geoip.sh — download the free DB-IP lite country + ASN databases (MaxMind
# .mmdb format) into data/. No account required; licensed CC BY 4.0 by db-ip.com.
# Idempotent: skips a DB that already exists and is fresh (< 30 days old).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="$ROOT/data"
BASE="https://download.db-ip.com/free"
FRESH_DAYS=30
mkdir -p "$DATA"

# fetch <kind> <outfile>: try the current month, fall back to the previous one.
fetch() {
	local kind="$1" out="$2"
	if [[ -f "$out" ]] && [[ -n "$(find "$out" -mtime -"$FRESH_DAYS" 2>/dev/null)" ]]; then
		echo "geoip: $out is fresh, skipping"
		return 0
	fi
	local m
	for m in "$(date +%Y-%m)" "$(date -d 'last month' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m)"; do
		local url="$BASE/dbip-$kind-lite-$m.mmdb.gz"
		echo "geoip: trying $url"
		if curl -fsSL "$url" -o "$out.gz"; then
			gunzip -f "$out.gz"
			echo "geoip: wrote $out"
			return 0
		fi
	done
	echo "geoip: FAILED to download dbip-$kind (tried this month and last)" >&2
	return 1
}

fetch country "$DATA/dbip-country.mmdb"
fetch asn "$DATA/dbip-asn.mmdb"

echo "geoip: databases ready in $DATA/"
echo "geoip: data © db-ip.com, licensed under CC BY 4.0 (https://db-ip.com)"
