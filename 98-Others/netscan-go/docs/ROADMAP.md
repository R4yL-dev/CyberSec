# netscan-go — Future work & handoff

This document is a self-contained handoff. Hand it to someone (or a fresh agent) with **no
prior context** and they should be able to continue the project faithfully. Read the
[README](../README.md) first for the current design and how to build/run; this document only
covers **what is not built yet**, why we want it, and how to build it the way we intended.

Each item below follows the same template: **What / Why (the rationale we agreed on) / Design /
Code seams / Done when**. Nothing here is started unless the status says so.

---

## 0. Invariants — do not break these while extending

These are load-bearing architectural decisions. New work must preserve them.

1. **Two domains.** Domain A = discovery (a forward-only stream, `ns-discover`, NDJSON out).
   Domain B = enrichment (a re-entrant work queue + per-host state in SQLite).
2. **`ns-discover` is forward-only and never touches the work queue.** There is deliberately **no
   `discover` stage** in the `work` table. All per-host re-probing lives in domain B (see the
   `recheck` stage, §1). It *may* write its own progress heartbeat to the `runs` table when given
   an optional `--db` (so `ns-status` shows a unified view); without `--db` it stays a pure NDJSON
   pipe. Writing a `runs` heartbeat is the only store access it is allowed — never `work`/`hosts`.
3. **Work-queue stages belong to domain B only.** A "stage" is a string in `work.stage`
   (`model.StageDetect` — the entry palier — then `webinfo`/`crawl`/`tls-deep`/`ptr`, and future
   `recheck`/`heavy`).
4. **All store writes go through the single-writer connection** (`SetMaxOpenConns(1)` in
   `internal/store/sqlite.go`). This is what prevents `database is locked`. Do not open a second
   writer.
5. **NDJSON is the A→B contract** (`model.WireRecord`). Keep it stable; it is what lets
   `ns-discover | ns-ingest` and file replay work.
6. **Reserved ranges are excluded by default** (`internal/target`, RFC 5735/6890 list). Only
   `--no-skip-reserved` disables it.
7. **Workers touch persistence only through the `store.Store` interface** — this is the seam that
   lets a Postgres backend drop in later (§4). Do not reach around it into SQLite directly.
8. **`HostRecord.Ports` accumulates across paliers.** Each enricher adds to it; it is never
   wholesale-replaced by a later stage.
9. **The SYN capability is attached to the binary and lost on every `make build`** — SYN work
   always needs a fresh `make setcap` (or `make syn`).

## Current state (baseline)

Built and verified: `target` (reserved exclusion + randomizing permutation), `ns-discover`
(connect + stateless SYN), the SQLite `store` with full re-entrance (claim/lease, dedup,
backoff, dead-letter, reschedule), `ns-ingest`, the modular enrichment **pipeline**
(`detect` → `webinfo`/`crawl`/`tls-deep`/`ptr`, protocol-gated), GeoIP annotation at ingest,
`ns-enrich` worker, `ns-status`, the `netscan` launcher, `Makefile`, and `scripts/syn-scan.sh`.
See the README for details.

---

## 1. `recheck` stage — targeted single-host re-probe

**Status:** not started. The queue primitive it needs (`Reschedule`) already exists.

**What.** A domain-B enrichment stage that re-probes the open ports of **one** host (a light
connect scan of that single host), updating its `open_ports` / marking it unreachable. It is the
concrete "backward" use case for the re-entrant queue.

**Why.** A host open at discovery can be down by the time enrichment runs (hosts flap; there is a
time gap between domains). We agreed the re-entrant design exists precisely so a later/expensive
palier can say "this host stopped answering — re-verify it before continuing" by scheduling a
`recheck`. Crucially this is a **domain-B worker**, not `ns-discover` (which is the bulk firehose
and never consumes the queue).

**Design.** A new `Enricher` whose `Enrich` does a targeted TCP connect to the host's known ports
(reuse the dial logic from `scan.ConnectProber`), and either refreshes `open_ports` or records an
"unreachable" status. On success it may `Reschedule` the host to `detect` (or the next palier).

**Code seams.**
- Add `StageRecheck = "recheck"` to `internal/model/model.go`.
- New `internal/enrich/recheck.go` implementing `enrich.Enricher`.
- Register it in `cmd/ns-enrich/main.go` `newEnricher()` switch.
- Run it with `ns-enrich --db scan.db --stage recheck`.
- Backward scheduling is already `store.Reschedule(ctx, ip, stage)`.

**Done when.** `ns-enrich --stage recheck` re-verifies hosts; a failing palier can enqueue a
recheck and the host is re-probed with backoff/dead-letter honored.

---

## 2. Heavier enrichment paliers + selectors (multi-tier)

**Status:** ✅ first increment done. Built the modular pipeline (`internal/pipeline`: a Go stage
graph with per-edge selectors; `ns-enrich` drains the whole graph and enqueues next stages on
completion), the two-level model (stages = one network interaction each, in-stage analyzers =
pure functions), and shipped `webinfo` (headers/cookies/tech-detect/security-headers/favicon-hash)
+ `ptr` + `tls-deep` (TLS versions/ciphers, cert chain, weak-crypto warnings, and a **JARM**
fingerprint via `github.com/hdm/jarm-go`) gated after `light`. Concurrent paliers merge via
`store.Complete`/`HostRecord.Merge` instead of clobbering. **GeoIP/ASN** is done but
**deliberately not a palier** — it's a local IP lookup annotated at ingest (`internal/geoip`,
`ns-ingest --geoip/--asn` default-on from `data/`, `make geoip` downloads DB-IP lite). Design note:
IP-only attributes annotate at ingest, not via the queue. **`crawl`** (well-known + sensitive
paths, signature-guarded, + OPTIONS methods) is done, gated on an HTTP response. **Service/version
extraction** is done as a webinfo analyzer: normalized `Service{product,version,cpe,source}` on
`PortInfo.Services`, parsed from Server/X-Powered-By/generator with best-effort CPE — the CVE
foundation.

**Detection layer** ✅ done — the HTTP-centric triage was replaced by a protocol-aware `detect`
palier (`internal/enrich/detect.go`): per port it peeks for a speak-first banner, then TLS
handshake (**any port**, definitive), then plaintext HTTP, filling `PortInfo.Protocol`
(`http/https/tls/ssh/ftp/smtp/banner/unknown`), TLS summary, banner + service. Port only hints
probe order; **HTTPS on 8443 and SSH on 2222 are now detected**. Selectors gate on protocol
(`IsWeb`, `HasTLS` any-port); the old `banner` palier was folded into `detect`; `light` removed.

**Config-driven wiring** ✅ done — the graph is described in YAML (`internal/pipeline/default.yaml`,
embedded as the built-in default), resolved against name registries (enrichers + **named
selectors** `always`/`is_web`/`has_tls`; no expression DSL yet). `ns-enrich --pipeline <file>` /
`--print-pipeline`, `netscan scan --pipeline` forward it; entry stays `detect`; `Load` validates.

**Deep per-host port scan** ✅ done — the `portscan` palier (`internal/enrich/portscan.go`,
connect, bounded concurrency) sweeps a host's ports (`--all-ports`: common set / spec / `all`),
unions newly-found ports, and re-enters `detect` to classify+enrich them (the re-entrant
"backward" edge, guarded by `needs_portscan` to run once). Opt-in via the single `--all-ports`
flag, which injects the palier via `pipeline.WithPortscan` (no profile file needed).
Required: `HostRecord.Merge` + `store.Complete` now union/persist `open_ports`. Per-palier config
flows via `pipeline.Options` (typed, from flags — not YAML). `ns-discover --top-ports N` for the
common-first discovery phase.

**Deep scan over SYN** 🔜 planned — the `--all-ports` sweep is connect-based today (unprivileged,
simple, correct). A SYN variant would keep scanning **the same hosts** (discovery already enumerated
them — SYN here finds *more ports*, never more machines), but:
- **Faster**: half-open (SYN → SYN-ACK, no 3rd ACK, no teardown) — a big win on `--all-ports all`
  (65535 ports/host), the same reason discovery already uses SYN.
- **Resource-light**: raw sockets bypass the conntrack table and ephemeral-port pool that `connect()`
  exhausts (the exact pressure `--all-ports-conc` exists to cap), so the sweep could run far more
  aggressively without destabilising the link.
- **More reliable at scale**: `connect()` can mark an open port closed when the *local* box runs out
  of fds/ephemeral ports under heavy concurrency; SYN doesn't hit that ceiling.
- **Stealthier**: half-open connections are less often logged by application services.

Cost (why connect is v1): raw sockets + `CAP_NET_RAW` + the iptables RST guard would move into
`ns-enrich` (today fully unprivileged), plus SYN-ACK↔port pairing per host and a receive loop.
Connect stays the default/fallback for the no-privilege path; SYN would be opt-in when capable.

**Remaining:** `recheck`, and a selector **expression DSL** if named selectors fall short.

## CVE chain (the end goal — sort/filter hosts by CVE)

**Status:** foundation + banners done — `PortInfo.Services` with CPEs, fed by the web analyzer
(Server/X-Powered-By/generator) **and** banner parsing in the `detect` palier (server-speaks-first
SSH/FTP/SMTP/DB…). Next:
- **More banner parsers / probes** if coverage needs it (v1 is server-speaks-first only).
- **CVE matching**: ingest NVD, match `Service.CPE` + version ranges → CVE list per host; then a
  query/filter surface (`ns-status`/`ns-query`) to sort hosts by CVE. Big separate step — the
  `Service.CPE` data it consumes is now in place.

**Mechanism (built).** The pipeline is an edge-gated graph (`internal/pipeline/pipeline.go`):
each `Stage{Enricher, Next []Edge}`, each `Edge{To, When Selector}`. After a worker `Complete`s an
item, it `Reschedule`s the host onto each `Next` stage whose selector passes — advancing **through
the queue** (re-entrant, crash-safe), never by in-process chaining. Add a new palier = a new
`Enricher` + a `model.Stage*` constant + a stage/edge in `pipeline.Default`; add an analyzer = a
function under `internal/enrich`. Concurrent paliers merge via `store.Complete`/`HostRecord.Merge`.

---

## 3. Web dashboard (`ns-web`)

**Status:** not started. The store is already the single source of truth; the `runs` table
exists; a `control` table needs adding.

**What.** A web UI to watch a scan (progress, throughput, queue depth, host list, per-host
drill-in) and interact with it (pause/resume workers, adjust rate, reschedule a host).

**Why.** We decided a dashboard was the right long-term tool but not needed for v1, and that the
architecture should make it **additive**: everything already flows through the SQLite store, so
the UI is just another reader/writer of it. `ns-status` (CLI) covers monitoring in the meantime.

**Design.**
- New binary `cmd/ns-web`: a Go `net/http` server, frontend embedded via `embed.FS` (single
  binary, no external assets). Live updates via SSE that polls the store.
- **Read** path: reuse `store.Stats` / `store.Host`; add any needed read methods to the `Store`
  interface. Progress comes from the existing `runs` heartbeat table (already written by
  `ns-ingest`/`ns-enrich`).
- **Interaction** path (keep it going through the store, consistent with everything else): add a
  `control` table (e.g. `paused`, desired `rate`) that workers poll; the UI writes to it.
  Rescheduling a host from the UI = `store.Reschedule`.

**Code seams.**
- New `cmd/ns-web/`.
- `internal/store`: add a `control` table to the `schema`, plus `Store` methods to get/set
  control settings; workers (`cmd/ns-enrich`, discovery rate) read them.
- `ns-discover` would need to consult the desired rate if live rate control is wanted.

**Done when.** `ns-web --db scan.db` serves a page showing live counts/host list, and can
pause/resume enrichment and reschedule a host via the `control` table.

---

## 4. Postgres backend / message broker (multi-machine)

**Status:** not started. The `store.Store` interface is the seam.

**What.** An alternative store/queue backend for when a single machine's SQLite is outgrown:
Postgres for real concurrent writes and multi-worker access, and/or a message broker (Redis
Streams / NATS) so multiple workers of one stage on different machines can drain the same queue.

**Why.** SQLite's ceiling is single-machine (one writer, no network access from other hosts). We
chose SQLite for v1 because it is zero-infra and handles the responding-host volume fine, and we
put persistence behind the `Store` interface specifically so this migration is a drop-in and does
**not** touch the workers. Only cross this bridge when you need multiple machines or write
throughput beyond a local SSD.

**Design.** Implement `store.Store` a second time (e.g. `internal/store/postgres.go`), select the
backend by DSN scheme or a `--store` flag. For horizontal workers, the queue semantics
(claim-with-lease, dedup, backoff, dead-letter) map onto Postgres `SELECT ... FOR UPDATE SKIP
LOCKED` or onto broker consumer groups; keep the same `Store` method contract.

**Code seams.**
- `internal/store/store.go` (interface — do not change its shape casually; it is the contract).
- New backend file(s) implementing it; a factory that picks the backend by config.
- Nothing in `cmd/ns-enrich`/`ns-ingest` should change beyond how the store is opened.

**Done when.** `ns-ingest`/`ns-enrich` run unchanged against a Postgres DSN, and multiple
`ns-enrich` instances (even on separate hosts) drain the same queue without double-processing.

---

## 5. Streaming SYN output + `open_ports` union on ingest — DONE

**Status:** ✅ implemented. `internal/scan/syn.go` now streams a `WireRecord` per open port as
each SYN-ACK is validated (deduplicated in the receiver), and `store.Ingest` unions `open_ports`
(read-merge-write in the write tx) instead of overwriting. SYN mode therefore overlaps enrichment
just like connect mode. Kept below for the record.

**What.** (a) Make the SYN prober emit hosts as replies arrive instead of buffering until the
grace period. (b) Make `ns-ingest` **union** a host's `open_ports` on re-ingest instead of
overwriting.

**Why.** v1's SYN prober collects responders in a map and emits them all after `--grace` — simple
and correct, but for long internet-wide scans you want results streaming out live, and you do not
want to lose hours of scanning if it is interrupted. Streaming per-`(host, port)` means a host's
two ports can arrive separately, so ingest must **accumulate** open ports rather than replace them
(otherwise the second record clobbers the first).

**Design.** Emit a `WireRecord` when a SYN-ACK is validated (per host or per host+port). Change
`store.Ingest` so `open_ports` is merged (set-union) with the existing row rather than replaced.
This also makes re-discovery additive, which is the correct behavior anyway.

**Code seams.**
- `internal/scan/syn.go`: emit on validation in the receiver loop instead of buffering to
  `openMap` and flushing at the end.
- `internal/store/sqlite.go` `Ingest`: union `open_ports` (read-merge-write within the write tx,
  or a SQL merge) instead of `open_ports = excluded.open_ports`.

**Done when.** A long SYN scan streams NDJSON continuously, and a host seen twice with different
open ports ends up with the union in the store.

---

## 6. Batched writes (throughput optimization)

**Status:** not started. Current store is single-writer but not batched.

**What.** A dedicated writer goroutine that funnels all mutations through a channel and commits
them in **batches** within transactions.

**Why.** The original design intent (see the implementation plan) was "single writer that groups
writes into batches." We implemented the single-writer part via `SetMaxOpenConns(1)` (which
already prevents lock contention) but not batching. Batching raises write throughput and matters
only if enrichment write rate ever approaches the SSD's per-transaction limit — currently
enrichment is network-bound and far below it, so this is a **latent optimization**, not a need.

**Code seams.** `internal/store/sqlite.go`: introduce a writer goroutine + a mutation channel;
`Ingest`/`Complete`/`Fail`/`Reschedule` enqueue onto it; commit in batches. Preserve the `Store`
interface exactly.

**Done when.** Sustained write throughput improves under load with no change to caller code and no
`database is locked`.

---

## 7. IPv6

**Status:** not started. `target` rejects IPv6 today.

**What.** Support IPv6 CIDR targets end to end.

**Why.** v1 is IPv4-only by explicit scope. IPv6 is a natural extension but a large one (address
space, packet crafting, exclusion lists all differ).

**Design / code seams.**
- `internal/target`: `parseV4Prefix` currently rejects non-IPv4; generalize the address space and
  the reserved list to IPv6. Note the address space is 128-bit — the `uint64` index/permutation
  math and the "enumerate all addresses" assumption do **not** hold for IPv6; IPv6 scanning is
  target-list / hitlist driven, not exhaustive. This is a design shift, not just a type change.
- `internal/scan/syn.go`: craft `layers.IPv6` packets; connect mode already works for IPv6.
- Connect mode is the low-effort path to "some IPv6 support"; exhaustive SYN sweeps do not apply.

**Done when.** Connect mode scans an explicit IPv6 target list; SYN IPv6 is a further step.

---

## 8. Adaptive two-pass discovery — maximise hosts found at reasonable cost

**Status:** not started. Discovery is a single fixed-port-set pass today (`ns-discover`, top-100 by
default or `--ports`/`--top-ports`). A host silent on that set is never found; `--all-ports` only
widens ports on **already-discovered** hosts, so it cannot rescue them.

**The problem.** Goal: find a maximum of machines while keeping scan time reasonable. No port count
*proves* a host dead — detection is probabilistic (a host is found iff ≥1 probed port responds).
Port popularity is a power law: top-100 catches the large majority of hosts with a public service,
top-1000 ~99%, and the tail is exponentially expensive. Cost is **addresses × ports** (linear in
ports): a /16 at 1000 pps ≈ 11 min (top-10), ~1.8 h (top-100), ~18 h (top-1000), ~50 days (all).
Raising N *uniformly* wastes billions of probes on the empty ~99% of the space.

**The idea.** Don't raise N uniformly — **spend the port budget where there's life**:
- **Pass 1 (wide addresses, narrow ports):** cheap top-N (e.g. top-10/top-100), plus an ICMP-echo
  liveness probe, across the whole space. Finds obvious hosts *and* reveals which blocks are
  populated. ICMP rescues "pingable but no common port" hosts → known-alive, flagged for widening.
- **Pass 2 (narrow addresses, wide ports):** top-1000+ (up to `all`) **only** on blocks that showed
  any life in pass 1. Because live blocks are a tiny fraction, the address count collapses, so many
  more ports become affordable exactly where hosts actually are.

**Open design questions (discuss before building).**
- **Widening unit:** the /24 of a live host? that /24 + neighbours? the whole ASN? This governs the
  real yield-per-second and needs its own discussion.
- **"Live block" threshold:** ≥1 responder, or ≥K, to avoid chasing single honeypots.
- **Mechanism:** pass 2 as a second `ns-discover` invocation fed a target list of live blocks (fits
  the NDJSON/Unix-stage model, no new domain), vs. an in-prober escalation. Prefer the former —
  keeps Domain A stateless and re-runnable.
- **ICMP:** raw ICMP needs `CAP_NET_RAW` (already required for SYN); pairs naturally with SYN mode.

**Done when.** A live-block target list from a cheap pass 1 drives a wider-port pass 2, finding
materially more hosts than a single top-100 pass at a fraction of a uniform top-1000's cost.

---

## Decisions already made — do not re-litigate

These were debated and settled this session. Re-opening them wastes effort; change them only with
a concrete new reason.

- **Go, multi-binary, NDJSON pipeline.** Chosen over a Python evolution and over a single
  monolith. Reasons: native concurrency, Unix-composable stages, independent replay, privilege
  separation.
- **SQLite (pure Go, `modernc.org/sqlite`) with a single-writer connection.** Chosen over
  Postgres-from-the-start (infra we do not need single-machine) and over cgo SQLite (keeps store
  binaries cgo-free). Postgres stays available behind the `Store` interface (§4).
- **libpcap for SYN capture**, not a pure-Go AF_PACKET path. We considered AF_PACKET to avoid the
  `libpcap-dev` dependency; rejected because the extra low-level code (hand-assembled BPF, ring
  handling) is fiddly and error-prone, the dependency is trivial on Kali, and `ns-discover` is the
  one binary where cgo-free buys nothing (it is already privileged/Linux-only).
- **Raw L3 send (`IPPROTO_RAW`) for SYN**, so the kernel routes and no ARP/gateway-MAC resolution
  is needed. Kernel RSTs are handled by the scoped, auto-removed iptables guard in
  `scripts/syn-scan.sh`.
- **Randomized scan order** (stateless Feistel + cycle-walk), on by default for internet-wide
  politeness/coverage.
- **Reserved ranges excluded by default**; scan **all** addresses in a block (masscan-style), not
  `.hosts()`.
- **Web UI deferred**, with the architecture kept UI-ready (store is the single source of truth,
  `runs` table exists, `control` table to be added).

## Conventions when extending

- Keep the `Store`, `Prober`, and `Enricher` interfaces stable; add behavior behind them.
- New enrichment work = a new `Enricher` module + a `model.Stage*` constant + a case in
  `cmd/ns-enrich/main.go`; drive it via `ns-enrich --stage <name>`; advance between stages through
  the queue (`store.Reschedule`), never by in-process chaining.
- Match the existing code style; port behavior from `../netscan.py` where relevant.
- Run `make test` (and `make vet`) — extend the `internal/target` and `internal/store` tests when
  you touch permutation/exclusion or queue semantics.

## Adjacent ideas (mentioned in passing, not yet designed)

Lower-priority and **not** yet agreed in detail — capture only, do not treat as committed scope:
- **Scan resume/checkpoint** — ✅ **done.** `ns-discover --db X` checkpoints the permutation
  position to `meta.discover.checkpoint` (with a target signature + seed) every second;
  `ns-discover --resume` reloads it, verifies the signature, and restarts from that position
  (rewound past the connect feed's in-flight window so it overlaps rather than gaps). The
  checkpoint is cleared on clean completion. See `target.RandomizedFrom` / `Signature`.
- **Pluggable output sinks** beyond the store (e.g. JSON file / Elasticsearch) behind a `Sink`-style
  interface.
- **Richer HTTP fidelity** (take `Server`/`title` from the first hop rather than the final
  response). *(TLS-on-any-port is now handled by the `detect` layer.)*
- **Launcher-owned live display** — make `netscan scan` suppress the sub-binaries' stderr and
  render its own single unified progress line (read from the store), instead of pointing users at
  `ns-status --interval` in another pane. This is the clean way to get inline progress *inside the
  launcher*, where `ns-discover`'s and `ns-enrich`'s stderr would otherwise collide with a live
  `\r` line. Complements the `--progress` opt-in on `ns-discover` (for direct/unpiped use).
- **Adaptive rate governor (`--rate auto`)** — a feedback loop that periodically health-checks its
  own connectivity (a fresh TCP connect to a known host, and/or a DNS lookup) and adjusts the rate
  AIMD-style: ramp up while healthy, cut hard (×0.5) when the probe fails/slows. `rate.Limiter`
  already supports live `SetLimit`, so the mechanism is cheap; the work is the governor + tuning.
  **Deliberately deferred:** its main value is surviving upstream **NAT** connection-table
  exhaustion, which is a dev-environment artifact (scanning from a NAT'd VM). In production on a
  public IP (no NAT) you set a deliberate fixed rate, like masscan/zmap — which have no adaptive
  mode. Revisit only if a production need for a self-throttling safety valve appears. A cheap
  interim guard already exists: `ns-discover` refuses `--rate 0` (unlimited) without `--yes`.
