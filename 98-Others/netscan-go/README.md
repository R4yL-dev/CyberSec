# netscan-go

A modular, internet-scale IPv4 port scanner written in Go. It is a two-stage pipeline:
**discovery** (fast, randomized SYN or connect scanning that finds hosts with open ports) feeds
**enrichment** (slower HTTP/TLS probing that runs off a re-entrant, SQLite-backed work queue).
It is a rewrite and expansion of the original `../netscan.py`.

The design goal is to scan chosen CIDR ranges — up to the whole public IPv4 space — while
collecting only **publicly exposed information** (open ports, HTTP headers, page titles, TLS
certificates). You are responsible for only scanning ranges you are authorized to scan; see
[Safety & legality](#safety--legality).

## Table of contents

- [Architecture](#architecture)
- [Design choices](#design-choices)
- [Components](#components)
- [Install & build](#install--build)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Data model & output](#data-model--output)
- [Safety & legality](#safety--legality)
- [Testing](#testing)
- [Limitations & roadmap](#limitations--roadmap)
- [Project layout](#project-layout)

## Architecture

The scanner is split into two domains with deliberately different communication models, because
the two halves have very different characteristics.

```
        Domain A — discovery (stream, forward-only)          Domain B — enrichment (re-entrant, stateful)
 CIDRs ─▶ ns-discover ──NDJSON──▶ ns-ingest ──▶ [ SQLite: hosts + work + runs ] ◀──▶ ns-enrich (pipeline)
          SYN / connect            upsert host,       per-host state + work queue          claim → detect/enrich →
          randomized order         enqueue("detect")  leases, backoff, dead-letter          update record → complete
          excludes reserved                           (any stage can (re)schedule            or reschedule (backward)
          rate-limited                                 work for any stage)
                                                              ▲
                                                       ns-status (read-only monitoring)
```

- **Domain A (discovery)** is a forward-only firehose. `ns-discover` walks the target address
  space in randomized order, probes each address, and emits one NDJSON record per host that
  answers. It holds no state and never touches the work queue. At internet scale this processes
  billions of addresses but only emits the tiny fraction that respond.

- **Domain B (enrichment)** is where responding hosts acquire durable, evolving state. Each host
  is a row in a SQLite store; enrichment stages ("paliers") are workers that pull items from a
  work queue, probe the host, and write results back. Because a host can disappear or change
  between stages, any stage can reschedule work for any other stage — including backward — with
  retries, backoff and dead-lettering.

The contract between the two domains is **NDJSON** (newline-delimited JSON) over stdout/stdin,
so they compose as an ordinary Unix pipeline (`ns-discover | ns-ingest`). Within domain B the
shared medium is the SQLite database.

Why the split: discovery is a fast packet firehose, enrichment is slow and network-bound
(HTTP/TLS handshakes per host). Decoupling them lets discovery run at full rate while
enrichment drains at its own pace, lets you replay enrichment without re-scanning, and keeps
per-host retry logic out of the firehose.

## Design choices

Short rationale for the decisions that shaped the code.

**Go.** Goroutines and channels map directly onto the staged pipeline (worker pools connected
by channels, back-pressure for free). The standard library covers the entire enrichment side —
`net/http`, `crypto/tls`, `crypto/x509` — with no external dependencies.

**One binary per stage + NDJSON.** Each stage is a separate program communicating via NDJSON.
This makes stages independently runnable, testable and replaceable; lets you persist the
discovery output and re-run enrichment later; and gives OS-level back-pressure through pipes.
It also cleanly separates privilege: only `ns-discover` needs raw-socket capability, and it
never touches the database.

**SQLite, pure-Go, single-writer.** The store uses `modernc.org/sqlite` (a pure-Go SQLite, **no
cgo**), so `ns-ingest`/`ns-enrich`/`ns-status` build and deploy anywhere. SQLite allows only one
writer at a time, so all writes go through a single connection (`SetMaxOpenConns(1)`) — they
serialize instead of contending, which avoids `database is locked`. Reads use a separate pool
and, thanks to WAL mode, never block on the writer. Only responding hosts enter the database
(tens of millions at internet scale, not billions), which is well within SQLite's range. The
store is defined as a `Store` interface, so a Postgres backend can be dropped in later for
multi-machine setups without touching the workers.

**Re-entrant queue instead of a linear pipeline.** A plain `A | B | C` pipe is one-directional
and stateless — it cannot express "this host was open at discovery but is down now, retry it
later" or "re-probe this host from an earlier stage". Real scan data flaps. So domain B is a
work queue plus a per-host state store: a stage claims an item, updates the host record, and can
schedule follow-up work for any stage (forward or backward). Leases give crash recovery, and
exponential backoff with a max-attempts dead-letter bounds retry loops.

**Stateless SYN discovery, with a connect fallback.** SYN mode (masscan/ZMap-style) sends bare
SYN packets from a raw L3 socket and validates replies with a cookie encoded in the TCP sequence
number, keeping no per-target kernel state; SYN-ACKs are captured with libpcap. It is fast but
needs `CAP_NET_RAW`. Connect mode does full TCP connects, needs no privilege, and serves as the
correctness reference. Same discovery interface, two backends.

**Randomized scan order.** Targets are emitted in a stateless pseudo-random order (a Feistel
permutation with cycle-walking) rather than sequentially. Sequential scanning of the internet
hammers one network at a time (abuse complaints, skewed coverage); randomization spreads packets
across the whole space so any single network sees only a trickle — the same reason masscan/ZMap
randomize. No address list is ever materialized; the permutation is computed per position.

**Reserved ranges excluded by default.** RFC 5735/6890 special-purpose ranges (private,
loopback, CGNAT, documentation, benchmarking, multicast, etc.) are filtered out unless you pass
`--no-skip-reserved`, plus any user `--exclude` ranges. The scanner covers **all** addresses in
a block (network and broadcast included, masscan-style), not just usable host addresses.

**cgo only where unavoidable.** libpcap (cgo) is required solely by `ns-discover` for SYN
capture — and that binary is inherently non-portable anyway (raw sockets, Linux, privileged).
Everything else stays pure Go.

## Components

Four binaries (`cmd/`):

| Binary        | Role                                                                                 |
|---------------|--------------------------------------------------------------------------------------|
| `ns-discover` | Domain A. Enumerates CIDRs in random order, scans (connect/SYN), emits NDJSON hosts.  |
| `ns-ingest`   | Reads discovery NDJSON, upserts hosts into the store, enqueues a `detect` work item. |
| `ns-enrich`   | Domain B worker. Claims items for a stage, runs the enrichment palier, writes results.|
| `ns-status`   | Read-only monitoring: counts, queue depth, recent hosts, per-binary heartbeats.       |

Internal packages (`internal/`):

| Package   | Responsibility                                                                          |
|-----------|-----------------------------------------------------------------------------------------|
| `model`   | Shared types: `WireRecord` (NDJSON), `HostRecord` (stored state), HTTP/TLS sub-records.  |
| `target`  | Indexable address space, reserved-range exclusion, stateless randomizing permutation.    |
| `scan`    | `Prober` interface with `ConnectProber` and `SYNProber`.                                  |
| `stream`  | NDJSON encode/decode over stdout/stdin.                                                   |
| `store`   | `Store` interface + SQLite implementation (host state + work queue + re-entrance).        |
| `enrich`  | `Enricher` interface + paliers: `detect` (protocol triage), `webinfo`, `crawl`, `tls-deep`, `ptr`. |

## Install & build

**Prerequisites**

- Go 1.23+ (the code uses `iter.Seq`; `go.mod` currently declares `go 1.25`).
- For **SYN mode only**: `libpcap-dev` and a C toolchain (gcc). Connect mode and all domain-B
  binaries build and run without these.

```bash
sudo apt install -y golang-go        # or a newer Go from go.dev
sudo apt install -y libpcap-dev      # only if you want SYN mode
```

**Make targets** (`make help` lists them):

```bash
make build      # compile all four binaries into bin/ (no sudo, no network)
make setup      # build + geoip (first-time "give me everything", no sudo)
make geoip      # download the free DB-IP lite country+ASN databases into data/ (idempotent)
make syn        # build, then grant the SYN capability (build + setcap) in one step
make setcap     # grant CAP_NET_RAW to bin/ns-discover (sudo)
make dropcap    # remove that capability
make install    # symlink the `netscan` launcher into ~/.local/bin (PREFIX= to change)
make test       # go test ./...
make vet
make clean
```

The GeoIP database is a data file in `data/` that **persists across rebuilds** (unlike the SYN
capability) — run `make geoip` once, or monthly to refresh.

**Capabilities (SYN mode).** SYN scanning needs to open raw sockets and capture packets. Rather
than running as root, grant the single binary two narrow file capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip bin/ns-discover
```

- `cap_net_raw` — open RAW/PACKET sockets (craft/send packets, pcap capture).
- `cap_net_admin` — network-admin operations pcap may use (e.g. promiscuous mode).
- `=eip` — put them in the effective/inheritable/permitted sets so they are active on exec.

This is far narrower than setuid-root, and reversible (`make dropcap`). **The capability is
attached to the binary file, so it is cleared every time you rebuild** — re-run `make setcap`
(or just use `make syn`) after each `make build`.

## Usage

The `netscan` launcher wraps the four binaries so a full scan is one command; each binary is
also exposed as a subcommand for advanced use.

```
netscan scan   --targets CIDR[,CIDR|@file] [--ports P] [--db FILE] [--syn] [ns-discover flags...]
netscan status [--db FILE] [--host IP] [--interval DUR]
netscan discover|ingest|enrich [flags...]     # pass through to the raw binary
```

**Connect workflow (no privilege):**

```bash
make build
./netscan scan --targets 1.1.1.0/24 --ports 80,443 --db scan.db
./netscan status --db scan.db
./netscan status --db scan.db --host 1.1.1.1     # full record for one host
```

`scan` runs the pipeline with discovery and enrichment **overlapped**: it starts an
`ns-enrich --follow` worker that drains the queue live while discovery is still running, and
exits once ingestion is done and the queue is empty. Watch progress with a live dashboard in
another pane: `netscan status --db scan.db --interval 2s`.

**SYN workflow (privileged, faster):**

```bash
make syn                                          # build + setcap (sudo, once per build)
./netscan scan --targets 1.1.1.0/24 --syn --db scan.db
SRC_PORT=55555 ./netscan scan --targets 1.1.1.0/24 --syn --db scan.db   # pin the source port
```

Under `--syn`, the launcher calls `scripts/syn-scan.sh`, which checks the capability and wraps
the scan in a **scoped, auto-removed iptables guard** (see [How it works](#the-kernel-rst-pitfall)).
It asks for your sudo password **once** (only for iptables — the scan runs unprivileged via the
capability) and keeps that credential fresh so the cleanup at the end never re-prompts, even on a
multi-hour scan. If a SYN scan is ever hard-killed before it can clean up, remove any leftover
guard with `netscan iptables-clean`.

**Composing the raw binaries** (streaming / long-running enrichment):

```bash
# discovery to a file, enrichment separately (replayable without re-scanning)
./bin/ns-discover --targets 1.1.1.0/24 > open.ndjson
./bin/ns-ingest --db scan.db < open.ndjson
./bin/ns-enrich --db scan.db --workers 50                    # drains the whole pipeline until interrupted

# or a live pipeline plus a long-running worker in another shell
./bin/ns-discover --targets 1.1.1.0/24 | ./bin/ns-ingest --db scan.db
./bin/ns-enrich --db scan.db                                 # add --drain to stop when empty
```

**`ns-discover` flags:**

| Flag                 | Default    | Meaning                                                     |
|----------------------|------------|-------------------------------------------------------------|
| `--targets`          | (required) | Comma-separated CIDRs, or `@file` (one per line).           |
| `--exclude`          | —          | Comma-separated CIDRs to exclude.                           |
| `--exclude-file`     | —          | File of CIDRs to exclude.                                   |
| `--no-skip-reserved` | `false`    | Do **not** skip reserved/private ranges.                   |
| `--ports`            | —          | Ports: list/ranges (`80,443,8000-8100`) or `all`; overrides `--top-ports`. |
| `--top-ports`        | `100`      | Scan the N most common ports (the discovery default; a host is found only if one of these is open, so a narrow set misses non-web-only hosts). |
| `--mode`             | `connect`  | `connect` or `syn`.                                        |
| `--rate`             | `1000`     | Max probes per second (`0` = unlimited).                   |
| `--workers`          | `-1` (auto)| Connect concurrency. Auto = `rate × timeout`, bounded by the FD limit and 4096; set `>0` to override. Reaching high rates needs this many concurrent dials — SYN mode avoids the ceiling. |
| `--timeout`          | `1.5s`     | Per-connection timeout (connect mode).                     |
| `--seed`             | `-1`       | Permutation seed for reproducible order (`-1` = random).   |
| `--retries`          | `1`        | SYN passes over the target set — retransmits are spaced across the whole scan, not back-to-back (syn mode). |
| `--grace`            | `3s`       | Wait for late replies after sending (syn mode).            |
| `--src-port`         | `0`        | SYN source port (`0` = random; pin to scope the iptables rule). |
| `--db`               | —          | Optional SQLite DB for progress/checkpoint reporting (for `ns-status`; never touches the work queue). |
| `--resume`           | `false`    | Resume from the last checkpoint in `--db` (same targets/seed).       |
| `--progress`         | `false`    | Live progress line on stderr (`\r`-updated on a TTY, periodic lines otherwise). |
| `--yes`              | `false`    | Confirm scans larger than 65536 addresses, or `--rate 0`.  |

**Resuming an interrupted scan.** With `--db`, discovery checkpoints its position every second.
If a long scan dies (crash, Ctrl-C, reboot), re-run the same command with `--resume` and it picks
up where it left off — the scan order is seed-deterministic, so it replays only the remaining
addresses (rewound slightly to overlap, never gap). The checkpoint is discarded on clean
completion. Works in both `connect` and `syn` modes; `netscan scan --resume ...` passes it through.

`ns-discover` also raises its soft open-file limit to the hard limit on startup so connect mode
can use enough workers; if the rate still can't be met it prints a one-line warning.

**`ns-enrich` flags:** `--db`, `--stage` (comma-separated stages to drain; default: the whole
pipeline), `--pipeline <file.yaml>` (custom pipeline; default: built-in graph), `--print-pipeline`
(dump the default YAML as a template), `--ports-deep` / `--ports-deep-timeout 2s` (portscan
breadth/timeout), `--workers 50`, `--timeout 10s`, `--max-attempts 5`,
`--lease 2m`, `--backoff 5s`, `--drain` (exit on first empty queue), `--follow` (drain until
ingestion is done, then exit — used by `netscan scan` for overlap).

**Scan profiles (custom pipelines).** The enrichment graph is described in YAML and resolved
against name registries (enrichers + selectors); the built-in default is embedded. Build a profile
by editing the template:

```bash
ns-enrich --print-pipeline > web-only.yaml   # then trim it to the stages you want
netscan scan --targets 1.1.1.0/24 --db scan.db --pipeline web-only.yaml
```

```yaml
# web-only.yaml — only fingerprint web ports, skip tls-deep/crawl/ptr
stages:
  detect:                       # entry is always "detect"
    next:
      - {to: webinfo, when: is_web}
  webinfo: {}
```

Selectors are named (`always`, `is_web`, `has_tls`, `needs_portscan`, `has_new_ports`);
enrichers/stages are `detect`, `webinfo`, `crawl`, `tls-deep`, `ptr`, `portscan`. `Load` validates
the graph (entry present, known names, edges resolve).

**Deep per-host port scan (`portscan`).** Discovery scans a small common port set across the whole
address space (fast); the `portscan` palier then sweeps a host's ports (the slow, per-host phase).
It's **opt-in** via the `profiles/deep.yaml` profile and the most aggressive palier (many connects
per host — heavy on NAT):

```bash
netscan scan --targets 1.1.1.0/24 --db scan.db --pipeline profiles/deep.yaml --ports-deep all
```

`--ports-deep` is `all` (1-65535), a spec like `1-1024,3306,8000-8100`, or empty (a curated common
set). `--ports-deep-timeout` (default `2s`) is the per-port connect timeout — short because it's a
sweep; raise it on high-latency/lossy networks to avoid missing slow-but-open ports (a filtered
port costs the full timeout). Newly-found ports are unioned into the host and **re-classified/
enriched by re-entering `detect`** — but only when portscan actually found new ports (the
`portscan → detect` edge is gated `has_new_ports`, so no wasteful double-enrichment otherwise; the
`needs_portscan` guard runs portscan once). `ns-discover --top-ports N` scans the N most common
ports for the discovery phase.
**`ns-status` flags:** `--db`, `--interval 0` (0 = one shot; `>0` = live dashboard with per-tool
rates, discovery %/pps, queue depth and enrichment throughput), `--host IP` (full record).
**`ns-ingest` flags:** `--db`.

## How it works

### Discovery

**Target space & order.** `internal/target` turns the given CIDRs into an indexable address
space (`Total()`, `AddrAt(i)`). Scan order is a stateless permutation of `[0, Total)`: a balanced
Feistel network sized to the next even power-of-two ≥ `Total`, with **cycle-walking** to fold it
onto exactly `Total`. This yields a bijection (every address exactly once) in pseudo-random order
without storing any list; `--seed` makes it reproducible. Reserved and excluded addresses are
skipped at emission, so nothing is materialized.

**Connect prober.** A worker pool dials each target port with `net.DialTimeout`. Simple, needs
no privilege, and is the reference implementation. Rate-limited by a token bucket.

**SYN prober.** Sends bare SYNs from an `IPPROTO_RAW` socket (packets crafted with gopacket);
the TCP sequence number is a keyed cookie derived from the destination and a per-run secret.
Incoming SYN-ACKs are captured with libpcap (BPF-filtered to the scan's source port) and
validated by checking `ack == cookie+1` — so no per-target state is kept. After sending, it
waits `--grace` for late replies. Responding hosts are streamed as their SYN-ACKs arrive (one
NDJSON record per open port, deduplicated), so enrichment overlaps discovery.

<a name="the-kernel-rst-pitfall"></a>**The kernel-RST pitfall.** When a SYN-ACK arrives for a
connection the kernel has no socket for, the kernel replies with a RST — harmless to capture (we
already saw the SYN-ACK via pcap), but it sends stray RSTs to every scanned host. `scripts/syn-scan.sh`
avoids this by adding an iptables rule that drops outbound RSTs **from the scan's source port
only**, and removing it on exit (via a shell `trap`, even on Ctrl-C). Pin `--src-port` (the
script uses `SRC_PORT`, default 44444) so the rule stays scoped instead of dropping all RSTs
system-wide.

### The work queue (re-entrance)

`internal/store` holds two operational tables — `hosts` (per-host state) and `work` (the queue) —
plus `runs` (heartbeats). Semantics:

- **`Ingest`** upserts the host and inserts a pending work item, idempotently: a partial unique
  index on `(ip, stage) WHERE state='pending'` means re-discovering a host never creates a
  duplicate item.
- **`Claim`** atomically leases up to N items for a stage (`UPDATE ... RETURNING`), selecting
  those that are `pending` **or** `leased` with an expired lease. So if a worker crashes
  mid-item, the lease expires and the item is reclaimed — free crash recovery.
- **`Complete`** writes the accumulated enrichment back to the host row and marks the item done.
- **`Fail`** reschedules with exponential backoff, or dead-letters the item once its attempts
  reach `--max-attempts`.
- **`Reschedule`** enqueues a pending item for any `(ip, stage)` — the "backward" primitive that
  lets a later palier re-arm an earlier one.

All writes go through the single-writer connection; `ns-status` reads concurrently via WAL.

### Enrichment (a composable pipeline of paliers)

Enrichment is a **graph of small paliers** (`internal/pipeline`), not a monolith. Each palier is
an `Enricher` (`internal/enrich`) for one **stage** = one network interaction; each edge carries a
**selector** deciding whether a host advances. `ns-enrich` drains the whole graph and, when a
stage completes, enqueues the next stages whose selector passes (via the re-entrant queue). Two
levels of composition: **stages** (gated, re-entrant, checkpointed) and, inside a fetch stage,
small **analyzers** (pure functions on the fetched artifact) — so a stage fetches once and only
small derived results are persisted (never raw bodies).

Built-in graph:

```
detect ──IsWeb───▶ webinfo
       ──IsWeb───▶ crawl
       ──HasTLS──▶ tls-deep
       ──Always──▶ ptr
```

- **`detect`** (entry): a **protocol-aware first contact** per open port, replacing the old
  HTTP-only triage. It classifies each port into `{protocol, tls, banner}` with a bounded (5s)
  sequence: peek for a server-speaks-first banner (SSH/FTP/SMTP…), else a TLS handshake (on **any**
  port — the definitive signal), else a plaintext HTTP GET. The port only **hints the probe order**;
  classification is by what actually answers, so **HTTPS on 8443 or SSH on 2222 are detected
  correctly**. It fills `Protocol` (`http`/`https`/`tls`/`ssh`/`ftp`/`smtp`/`banner`/`unknown`), the
  light HTTP summary, a TLS cert summary (any port), the raw banner, and a parsed `Service` from the
  banner. `InsecureSkipVerify` — the goal is to observe, not trust.
- **`webinfo`** (gated `IsWeb`): one richer fetch → all headers, cookies, detected technologies,
  security headers, a Shodan-style favicon hash, and **normalized services** — product+version
  parsed from `Server` / `X-Powered-By` / `<meta generator>`, with a **CPE**
  (`cpe:2.3:a:vendor:product:version`) when the vendor is known. The CVE-matching foundation
  (`PortInfo.Services`); version data is best-effort (headers are often stripped).
- **`crawl`** (gated `IsWeb`): probes a curated set of well-known paths (`robots.txt`,
  `sitemap.xml`, `.well-known/…`) and sensitive exposures (`/.git/HEAD`, `/.env`, `/server-status`,
  backups — signature-guarded against soft-404s), plus the `OPTIONS` methods. The most
  request-heavy palier; only for authorized targets.
- **`tls-deep`** (gated `HasTLS`, i.e. any TLS port): supported TLS versions + negotiated cipher
  per version, full cert chain, weak-crypto warnings, and a **JARM** active fingerprint (~15
  handshakes, hence gated).
- **`ptr`** (always): reverse DNS.

Non-web service banners (SSH/FTP/SMTP/MySQL…) are grabbed by `detect` itself and parsed into a
`Service` (source `banner`, with a CPE when known). To reach them, scan the relevant ports (e.g.
`--ports 22,21,25,3306,...`, or rely on the default `--top-ports 100` which includes them).

**GeoIP / ASN** is not a palier — it's a purely local lookup on the IP, done at **ingest** and
stored on the host (`geo`). It is **on by default when a database is present**: run `make geoip`
(downloads the free, account-free DB-IP lite country + ASN `.mmdb` into `data/`, CC BY db.ip.com),
and `netscan scan` auto-uses them. Override with `--geoip <file.mmdb> --asn <file.mmdb>` or disable
with `--geoip ""`; a missing DB is skipped silently. MaxMind GeoLite2 files work too (same format).

Concurrent paliers on the same host can't clobber each other: `store.Complete` re-reads and
**merges** under the single-writer lock (`HostRecord.Merge`).

New paliers = a new `Enricher` + a stage/edge in `pipeline.Default`; new analyzers = a function in
`internal/enrich/analyzers.go`.

## Data model & output

**Discovery output (`WireRecord`, one JSON object per line):**

```json
{"ip":"1.1.1.1","open_ports":[443],"discovered_at":"2026-07-07T21:43:12.756Z"}
```

**Stored host record (`ns-status --host`):**

```json
{
  "ip": "1.1.1.1",
  "open_ports": [443],
  "ports": {
    "443": {
      "port": 443,
      "protocol": "https",
      "http": {
        "url": "https://1.1.1.1:443/",
        "status": 200,
        "server": "cloudflare",
        "title": "1.1.1.1 — The free app that makes your Internet faster.",
        "redirects": [{"status": 301, "location": "https://one.one.one.one/"}]
      },
      "tls": {
        "tls_version": "TLS 1.3",
        "subject_cn": "cloudflare-dns.com",
        "san": ["cloudflare-dns.com", "*.cloudflare-dns.com", "one.one.one.one"],
        "issuer": "SSL.com SSL Intermediate CA ECC R2",
        "not_before": "2025-12-31T19:20:01Z",
        "not_after": "2026-12-21T19:20:01Z"
      }
    }
  },
  "status": {"detect": "ok", "webinfo": "ok", "tls-deep": "ok", "ptr": "ok"},
  "attempts": 1,
  "first_seen": "2026-07-07T21:43:12.756Z",
  "last_seen": "2026-07-07T21:43:13.021Z"
}
```

**SQLite tables:** `hosts` (ip PK, open_ports, accumulated enrichment JSON, per-stage status,
attempts, timestamps), `work` (id, ip, stage, state ∈ pending/leased/done/failed, attempts,
available_at, leased_until), `runs` (per-binary heartbeats for monitoring).

## Safety & legality

- **Authorization is on you.** Scanning hosts you do not own or are not authorized to test can
  violate laws and provider terms. This tool is for ranges you may scan; collect public
  information only.
- **Reserved ranges are skipped by default.** Disable only deliberately (`--no-skip-reserved`),
  e.g. for lab testing.
- **Rate limiting** (`--rate`, default 1000 pps) and a **big-scan gate** (`--yes` required above
  65536 addresses) reduce accidental blast radius.
- **iptables hygiene.** The SYN RST guard is scoped to the scan's source port and removed
  automatically; if you add rules manually, remember to remove them (`iptables -D ...`).

## Testing

```bash
make test        # go test ./...
```

Covered: reserved-range exclusion and user excludes (`internal/target`); the permutation is a
true bijection, including the tricky cases of a `/32` and non-power-of-two range sizes; and the
full store re-entrance semantics — claim/lease, dedup, complete, backoff, dead-letter, lease
expiry reclaim, reschedule, and concurrent ingest/claim without lock errors (`internal/store`).
SYN mode was validated live against public hosts (`1.1.1.1`, `8.8.8.8`), matching connect-mode
results with no false positives on closed ports.

## Limitations & roadmap

Anticipated by the architecture but not built in v1:

- **IPv6.** v1 is IPv4 only (`target` rejects IPv6 CIDRs).
- **Heavier enrichment paliers** and a targeted **`recheck`** stage. The `Enricher` interface and
  the multi-stage work queue already support them; a heavier palier is a new module drained by
  `ns-enrich --stage <name>`, gated by a selector.
- **Web dashboard.** Everything already flows through the store (the `runs` table exists for
  progress; a `control` table would drive interaction). `ns-status` covers monitoring on the CLI
  in the meantime.
- **Postgres / message broker.** The `Store` interface is the seam for a multi-machine backend
  when single-node SQLite is outgrown.
- *(done)* Streaming SYN output and `open_ports` union on ingest — SYN now emits hosts live as
  SYN-ACKs arrive, so enrichment overlaps discovery in SYN mode too.

## Project layout

```
netscan-go/
├── Makefile                 build / setcap / install targets
├── netscan                  launcher (scan/status/passthrough subcommands)
├── scripts/syn-scan.sh      guarded SYN discovery (scoped, auto-removed iptables RST rule)
├── cmd/
│   ├── ns-discover/         domain A: discovery firehose
│   ├── ns-ingest/           NDJSON → store
│   ├── ns-enrich/           domain B worker
│   └── ns-status/           monitoring CLI
└── internal/
    ├── model/               shared record types (the contract)
    ├── target/              address space, reserved exclusion, permutation
    ├── scan/                Prober: connect + SYN backends
    ├── stream/              NDJSON encode/decode
    ├── store/               Store interface + SQLite (state + work queue)
    └── enrich/              Enricher interface + paliers (detect, webinfo, crawl, tls-deep, ptr)
```
