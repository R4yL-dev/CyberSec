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
   (`model.StageLight`, and future `recheck`/`heavy`).
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
backoff, dead-letter, reschedule), `ns-ingest`, the `light` enrichment palier, `ns-enrich`
worker, `ns-status`, the `netscan` launcher, `Makefile`, and `scripts/syn-scan.sh`. See the
README for details.

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
"unreachable" status. On success it may `Reschedule` the host to `light` (or the next palier).

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

**Status:** not started. `Enricher` and `Selector` interfaces exist; `Selector` is unused.

**What.** Additional, heavier enrichment stages beyond `light` (e.g. full-body fetch and
crawling, deeper certificate/chain analysis, tech fingerprinting), each gated by a **selector**
so expensive work runs only on interesting hosts (tiered enrichment).

**Why.** We deliberately shipped only the cheap `light` palier in v1 but designed the
architecture to grow: discovery (tier 0) → light HTTP/TLS (tier 1) → heavy analysis (tier 2),
where a selector decides which hosts advance (e.g. only `200 OK`, or only a given `Server`).
`HostRecord.Ports` accumulates so each tier adds information without discarding earlier tiers.

**Design.** Model a pipeline as an ordered list of stages, each = `{Enricher, Select func(*HostRecord) bool, next stage}`.
After a worker `Complete`s an item, if the stage has a `next` and `Select(host)` passes, it
`Reschedule`s the host onto the next stage. Enrichment thus advances **through the queue**
(preserving re-entrance and crash recovery), not via in-process chaining. The `light` completion
would, for example, enqueue `heavy` for hosts whose HTTP status is 200.

**Code seams.**
- `internal/enrich/enricher.go` already defines `Enricher` and `Selector` — wire `Selector` in.
- Add stage constants in `internal/model/model.go`.
- New enricher modules `internal/enrich/heavy.go` etc.
- `cmd/ns-enrich/main.go`: after `store.Complete`, consult a stage→(selector,next) config and
  `store.Reschedule` to `next` when the selector passes. Keep the config small and explicit.

**Done when.** Running `ns-enrich --stage light` auto-advances qualifying hosts to `heavy`, and
`ns-enrich --stage heavy` (possibly a separate process/worker) enriches only those hosts.

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
  response; configurable TLS ports instead of the hardcoded `{443}`).
- **Adaptive rate governor (`--rate auto`)** — a feedback loop that periodically health-checks its
  own connectivity (a fresh TCP connect to a known host, and/or a DNS lookup) and adjusts the rate
  AIMD-style: ramp up while healthy, cut hard (×0.5) when the probe fails/slows. `rate.Limiter`
  already supports live `SetLimit`, so the mechanism is cheap; the work is the governor + tuning.
  **Deliberately deferred:** its main value is surviving upstream **NAT** connection-table
  exhaustion, which is a dev-environment artifact (scanning from a NAT'd VM). In production on a
  public IP (no NAT) you set a deliberate fixed rate, like masscan/zmap — which have no adaptive
  mode. Revisit only if a production need for a self-throttling safety valve appears. A cheap
  interim guard already exists: `ns-discover` refuses `--rate 0` (unlimited) without `--yes`.
