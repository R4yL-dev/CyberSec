package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"netscan/internal/model"
)

// maxBackoff caps the exponential retry delay.
const maxBackoff = time.Hour

// SQLite implements Store on a local SQLite database. Writes go through a
// single connection (MaxOpenConns(1)) so they serialize instead of contending
// — SQLite only allows one writer at a time. Reads use a separate WAL pool and
// never block on the writer.
type SQLite struct {
	w *sql.DB // single-writer connection
	r *sql.DB // read pool
}

// Open creates/opens the database at path and applies the schema.
func Open(path string) (*SQLite, error) {
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(on)"

	// The writer uses BEGIN IMMEDIATE so every transaction takes the write lock
	// up front. Without this, a read-then-write transaction (e.g. Ingest's
	// SELECT + INSERT) can fail with SQLITE_BUSY when another process writes in
	// between — busy_timeout does not retry that upgrade deadlock.
	w, err := sql.Open("sqlite", dsn+"&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)

	r, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)

	s := &SQLite{w: w, r: r}
	if _, err := w.Exec(schema); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return s, nil
}

func (s *SQLite) Close() error {
	err1 := s.w.Close()
	err2 := s.r.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	ip         TEXT PRIMARY KEY,
	open_ports TEXT NOT NULL,
	data       TEXT NOT NULL DEFAULT '{}',
	status     TEXT NOT NULL DEFAULT '{}',
	ptr        TEXT NOT NULL DEFAULT '',
	geo        TEXT NOT NULL DEFAULT '',
	attempts   INTEGER NOT NULL DEFAULT 0,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS work (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ip           TEXT NOT NULL,
	stage        TEXT NOT NULL,
	state        TEXT NOT NULL DEFAULT 'pending',
	attempts     INTEGER NOT NULL DEFAULT 0,
	available_at INTEGER NOT NULL,
	leased_until INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS work_pending_uniq ON work(ip, stage) WHERE state='pending';
CREATE INDEX IF NOT EXISTS work_claim ON work(stage, state, available_at);
CREATE TABLE IF NOT EXISTS runs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	tool       TEXT NOT NULL,
	pid        INTEGER NOT NULL,
	counter    INTEGER NOT NULL DEFAULT 0,
	total      INTEGER NOT NULL DEFAULT 0,
	note       TEXT,
	updated_at INTEGER NOT NULL,
	UNIQUE(tool, pid)
);
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

func nowMS() int64             { return time.Now().UnixMilli() }
func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func (s *SQLite) Ingest(ctx context.Context, rec model.WireRecord, stage string, geo *model.GeoInfo) error {
	now := ms(rec.DiscoveredAt)
	if now == 0 {
		now = nowMS()
	}
	geoJSON := ""
	if geo != nil {
		if b, err := json.Marshal(geo); err == nil {
			geoJSON = string(b)
		}
	}

	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Union the new open ports with any already recorded — SYN discovery streams
	// a host's ports in separate records, so re-ingest must accumulate, not replace.
	merged := rec.OpenPorts
	prevLen := 0
	var existing string
	switch err := tx.QueryRowContext(ctx, `SELECT open_ports FROM hosts WHERE ip=?`,
		rec.IP.String()).Scan(&existing); err {
	case nil:
		var prev []uint16
		if json.Unmarshal([]byte(existing), &prev) == nil {
			prevLen = len(prev)
			merged = model.UnionPorts(prev, rec.OpenPorts)
		}
	case sql.ErrNoRows:
		// new host
	default:
		return err
	}
	if merged == nil {
		merged = []uint16{} // marshal a portless (ICMP-alive) host as "[]", never "null"
	}
	ports, err := json.Marshal(merged)
	if err != nil {
		return err
	}

	// geo is written on first insert only; the conflict update leaves it intact
	// (it's a property of the IP and doesn't change between re-ingests).
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO hosts(ip, open_ports, geo, first_seen, last_seen)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			open_ports = excluded.open_ports,
			last_seen  = excluded.last_seen`,
		rec.IP.String(), string(ports), geoJSON, now, now); err != nil {
		return err
	}
	// Enqueue enrichment only when this ingest added NEW ports. A later discovery
	// pass (widen, deep) or the ICMP sweep re-reporting a host with the same ports
	// must NOT re-run the whole detect→enrich chain; and a portless ICMP-alive
	// record (no ports at all) just refreshes the row for live-block selection.
	if len(merged) > prevLen {
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO work(ip, stage, state, attempts, available_at)
			VALUES(?, ?, 'pending', 0, ?)`,
			rec.IP.String(), stage, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) Claim(ctx context.Context, stage string, n int, lease time.Duration) ([]WorkItem, error) {
	now := nowMS()
	leasedUntil := now + lease.Milliseconds()

	rows, err := s.w.QueryContext(ctx, `
		UPDATE work SET state='leased', leased_until=?, attempts=attempts+1
		WHERE id IN (
			SELECT id FROM work
			WHERE stage=? AND available_at<=?
			  AND (state='pending' OR (state='leased' AND leased_until IS NOT NULL AND leased_until<?))
			ORDER BY available_at
			LIMIT ?
		)
		RETURNING id, ip, attempts`,
		leasedUntil, stage, now, now, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []WorkItem
	for rows.Next() {
		var (
			id       int64
			ipStr    string
			attempts int
		)
		if err := rows.Scan(&id, &ipStr, &attempts); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil, fmt.Errorf("bad ip in work row: %w", err)
		}
		items = append(items, WorkItem{ID: id, IP: addr, Stage: stage, Attempts: attempts})
	}
	return items, rows.Err()
}

func (s *SQLite) Host(ctx context.Context, ip netip.Addr) (*model.HostRecord, error) {
	var (
		portsJSON, dataJSON, statusJSON, ptrJSON, geoJSON string
		attempts                                          int
		firstSeen, lastSeen                               int64
	)
	err := s.r.QueryRowContext(ctx, `
		SELECT open_ports, data, status, ptr, geo, attempts, first_seen, last_seen
		FROM hosts WHERE ip=?`, ip.String()).
		Scan(&portsJSON, &dataJSON, &statusJSON, &ptrJSON, &geoJSON, &attempts, &firstSeen, &lastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	h := &model.HostRecord{IP: ip, Attempts: attempts, FirstSeen: fromMS(firstSeen), LastSeen: fromMS(lastSeen)}
	if err := json.Unmarshal([]byte(portsJSON), &h.OpenPorts); err != nil {
		return nil, err
	}
	unmarshalJSON(dataJSON, &h.Ports)
	unmarshalJSON(statusJSON, &h.Status)
	unmarshalJSON(ptrJSON, &h.PTR)
	if geoJSON != "" {
		unmarshalJSON(geoJSON, &h.Geo)
	}
	return h, nil
}

// AllHosts loads every host record (for `netscan report` / `diff`). Intended for
// diagnostic-sized scans; it materializes all rows (see ROADMAP note on paging).
func (s *SQLite) AllHosts(ctx context.Context) ([]*model.HostRecord, error) {
	rows, err := s.r.QueryContext(ctx, `
		SELECT ip, open_ports, data, status, ptr, geo, attempts, first_seen, last_seen
		FROM hosts ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.HostRecord
	for rows.Next() {
		var (
			ipStr, portsJSON, dataJSON, statusJSON, ptrJSON, geoJSON string
			attempts                                                int
			firstSeen, lastSeen                                     int64
		)
		if err := rows.Scan(&ipStr, &portsJSON, &dataJSON, &statusJSON, &ptrJSON, &geoJSON,
			&attempts, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		h := &model.HostRecord{IP: addr, Attempts: attempts, FirstSeen: fromMS(firstSeen), LastSeen: fromMS(lastSeen)}
		_ = json.Unmarshal([]byte(portsJSON), &h.OpenPorts)
		unmarshalJSON(dataJSON, &h.Ports)
		unmarshalJSON(statusJSON, &h.Status)
		unmarshalJSON(ptrJSON, &h.PTR)
		if geoJSON != "" {
			unmarshalJSON(geoJSON, &h.Geo)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// FailedItems returns work items that are dead-lettered (failed) or currently
// leased (potentially stuck), for the report's queue-health / anomalies section.
func (s *SQLite) FailedItems(ctx context.Context) ([]WorkItem, error) {
	rows, err := s.r.QueryContext(ctx, `
		SELECT ip, stage, state, attempts FROM work
		WHERE state IN ('failed','leased') ORDER BY state, stage, ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []WorkItem
	for rows.Next() {
		var ipStr string
		var it WorkItem
		if err := rows.Scan(&ipStr, &it.Stage, &it.State, &it.Attempts); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		it.IP = addr
		out = append(out, it)
	}
	return out, rows.Err()
}

// unmarshalJSON decodes s into v unless s is empty/blank JSON.
func unmarshalJSON(s string, v any) {
	if s == "" || s == "{}" || s == "[]" || s == "null" {
		return
	}
	_ = json.Unmarshal([]byte(s), v)
}

func (s *SQLite) Complete(ctx context.Context, id int64, host *model.HostRecord) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Re-read the current enrichment under the write lock and merge into it, so
	// paliers that ran concurrently on the same host don't clobber each other.
	cur := &model.HostRecord{IP: host.IP}
	var portsJSON, dataJSON, statusJSON, ptrJSON string
	switch err := tx.QueryRowContext(ctx, `SELECT open_ports, data, status, ptr FROM hosts WHERE ip=?`,
		host.IP.String()).Scan(&portsJSON, &dataJSON, &statusJSON, &ptrJSON); err {
	case nil:
		unmarshalJSON(portsJSON, &cur.OpenPorts)
		unmarshalJSON(dataJSON, &cur.Ports)
		unmarshalJSON(statusJSON, &cur.Status)
		unmarshalJSON(ptrJSON, &cur.PTR)
	case sql.ErrNoRows:
		// no row yet (shouldn't happen post-ingest); merge into an empty record
	default:
		return err
	}
	cur.Merge(host) // unions OpenPorts too (portscan discovers new ports)

	openPorts, _ := json.Marshal(cur.OpenPorts)
	data, _ := json.Marshal(cur.Ports)
	status, _ := json.Marshal(cur.Status)
	ptr, _ := json.Marshal(cur.PTR)
	if _, err := tx.ExecContext(ctx, `
		UPDATE hosts SET open_ports=?, data=?, status=?, ptr=?, attempts=?, last_seen=? WHERE ip=?`,
		string(openPorts), string(data), string(status), string(ptr), cur.Attempts, nowMS(), host.IP.String()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE work SET state='done', leased_until=NULL WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// Touch extends a leased item's deadline. A worker calls it periodically while a
// slow palier (e.g. a large portscan sweep) is still running, so the item isn't
// reclaimed and re-run by another worker mid-flight. If the worker dies, Touch
// stops and the lease expires normally, restoring crash recovery.
func (s *SQLite) Touch(ctx context.Context, id int64, lease time.Duration) error {
	_, err := s.w.ExecContext(ctx, `
		UPDATE work SET leased_until=? WHERE id=? AND state='leased'`,
		nowMS()+lease.Milliseconds(), id)
	return err
}

func (s *SQLite) Fail(ctx context.Context, id int64, maxAttempts int, base time.Duration) error {
	var attempts int
	if err := s.w.QueryRowContext(ctx, `SELECT attempts FROM work WHERE id=?`, id).Scan(&attempts); err != nil {
		return err
	}

	if attempts >= maxAttempts {
		_, err := s.w.ExecContext(ctx, `
			UPDATE work SET state='failed', leased_until=NULL WHERE id=?`, id)
		return err
	}
	available := nowMS() + backoff(attempts, base).Milliseconds()
	_, err := s.w.ExecContext(ctx, `
		UPDATE work SET state='pending', available_at=?, leased_until=NULL WHERE id=?`,
		available, id)
	return err
}

// backoff grows exponentially with attempts, capped at maxBackoff.
func backoff(attempts int, base time.Duration) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := base
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func (s *SQLite) Reschedule(ctx context.Context, ip netip.Addr, stage string) error {
	_, err := s.w.ExecContext(ctx, `
		INSERT OR IGNORE INTO work(ip, stage, state, attempts, available_at)
		VALUES(?, ?, 'pending', 0, ?)`, ip.String(), stage, nowMS())
	return err
}

func (s *SQLite) Heartbeat(ctx context.Context, r RunStat) error {
	_, err := s.w.ExecContext(ctx, `
		INSERT INTO runs(tool, pid, counter, total, note, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(tool, pid) DO UPDATE SET
			counter=excluded.counter, total=excluded.total,
			note=excluded.note, updated_at=excluded.updated_at`,
		r.Tool, r.PID, r.Counter, r.Total, r.Note, ms(r.UpdatedAt))
	return err
}

func (s *SQLite) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.w.ExecContext(ctx, `
		INSERT INTO meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *SQLite) GetMeta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.r.QueryRowContext(ctx, `SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *SQLite) Summary(ctx context.Context) (Summary, error) {
	sm := Summary{
		WorkByState:   map[string]int64{},
		QueueByStage:  map[string]map[string]int64{},
		StageCoverage: map[string]int64{},
	}

	if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM hosts`).Scan(&sm.Hosts); err != nil {
		return sm, err
	}
	if err := scanCounts(ctx, s.r, `SELECT state, count(*) FROM work GROUP BY state`, sm.WorkByState); err != nil {
		return sm, err
	}
	if err := s.scanQueueByStage(ctx, sm.QueueByStage); err != nil {
		return sm, err
	}
	// Per-stage host coverage: keys present in each host's status map = completed stages.
	if err := scanCounts(ctx, s.r,
		`SELECT jt.key, count(*) FROM hosts, json_each(hosts.status) jt WHERE jt.key IS NOT NULL GROUP BY jt.key`,
		sm.StageCoverage); err != nil {
		return sm, err
	}

	runs, err := s.r.QueryContext(ctx, `
		SELECT tool, pid, counter, total, note, updated_at FROM runs ORDER BY updated_at DESC LIMIT 20`)
	if err != nil {
		return sm, err
	}
	defer runs.Close()
	for runs.Next() {
		var (
			rs   RunStat
			note sql.NullString
			upd  int64
		)
		if err := runs.Scan(&rs.Tool, &rs.PID, &rs.Counter, &rs.Total, &note, &upd); err != nil {
			return sm, err
		}
		rs.Note = note.String
		rs.UpdatedAt = fromMS(upd)
		sm.Runs = append(sm.Runs, rs)
	}
	if err := runs.Err(); err != nil {
		return sm, err
	}

	hosts, err := s.r.QueryContext(ctx, `
		SELECT ip, open_ports, last_seen FROM hosts ORDER BY last_seen DESC LIMIT 10`)
	if err != nil {
		return sm, err
	}
	defer hosts.Close()
	for hosts.Next() {
		var (
			ipStr, portsJSON string
			last             int64
		)
		if err := hosts.Scan(&ipStr, &portsJSON, &last); err != nil {
			return sm, err
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return sm, err
		}
		hs := HostSummary{IP: addr, LastSeen: fromMS(last)}
		_ = json.Unmarshal([]byte(portsJSON), &hs.OpenPorts)
		sm.RecentHosts = append(sm.RecentHosts, hs)
	}
	if err := hosts.Err(); err != nil {
		return sm, err
	}

	if err := s.scanFindings(ctx, &sm); err != nil {
		return sm, err
	}
	return sm, nil
}

// LiveBlocks groups every discovered host into its /prefixBits block and returns
// the blocks holding at least minHosts hosts, sorted. Used by the adaptive scan
// to build the pass-2 target list (widen ports only where there's life).
func (s *SQLite) LiveBlocks(ctx context.Context, prefixBits, minHosts int) ([]netip.Prefix, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT ip FROM hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[netip.Prefix]int{}
	for rows.Next() {
		var ipStr string
		if err := rows.Scan(&ipStr); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		counts[netip.PrefixFrom(addr, prefixBits).Masked()]++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []netip.Prefix
	for pfx, n := range counts {
		if n >= minHosts {
			out = append(out, pfx)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out, nil
}

// scanQueueByStage fills dst[stage][state] = count over the whole work table.
func (s *SQLite) scanQueueByStage(ctx context.Context, dst map[string]map[string]int64) error {
	rows, err := s.r.QueryContext(ctx, `SELECT stage, state, count(*) FROM work GROUP BY stage, state`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var stage, state string
		var n int64
		if err := rows.Scan(&stage, &state, &n); err != nil {
			return err
		}
		if dst[stage] == nil {
			dst[stage] = map[string]int64{}
		}
		dst[stage][state] = n
	}
	return rows.Err()
}

// scanFindings aggregates the per-host enrichment JSON (SQLite JSON1). Each query
// is small; the json_tree scans walk hosts.data, which is fine for authorized-
// range scans (see ROADMAP note on gating this at internet scale).
func (s *SQLite) scanFindings(ctx context.Context, sm *Summary) error {
	var err error
	// Top open ports (by number of hosts exposing each).
	if sm.TopPorts, err = s.topPorts(ctx, 12); err != nil {
		return err
	}
	// Protocol breakdown across all classified ports.
	if sm.Protocols, err = s.labelCounts(ctx, `
		SELECT proto, count(*) FROM (
			SELECT json_extract(p.value,'$.protocol') AS proto FROM hosts, json_each(hosts.data) p
		) WHERE proto IS NOT NULL AND proto != '' GROUP BY proto ORDER BY 2 DESC`); err != nil {
		return err
	}
	// Country breakdown (top 6).
	if sm.Countries, err = s.labelCounts(ctx, `
		SELECT c, count(*) FROM (
			SELECT json_extract(geo,'$.country') AS c FROM hosts WHERE geo != ''
		) WHERE c IS NOT NULL AND c != '' GROUP BY c ORDER BY 2 DESC LIMIT 6`); err != nil {
		return err
	}
	scalar := func(q string) (int64, error) {
		var n int64
		return n, s.r.QueryRowContext(ctx, q).Scan(&n)
	}
	if sm.WebServers, err = scalar(`SELECT count(*) FROM hosts, json_each(hosts.data) p WHERE json_extract(p.value,'$.http') IS NOT NULL`); err != nil {
		return err
	}
	if sm.TLSPorts, err = scalar(`SELECT count(*) FROM hosts, json_each(hosts.data) p WHERE json_extract(p.value,'$.tls') IS NOT NULL OR json_extract(p.value,'$.tls_deep') IS NOT NULL`); err != nil {
		return err
	}
	// Findings via recursive json_tree: the fields are omitempty, so key-presence
	// already means the finding fired (expired=true, non-empty warnings array).
	if sm.TLSExpired, err = scalar(`SELECT count(DISTINCT ip) FROM hosts, json_tree(hosts.data) jt WHERE jt.key='expired'`); err != nil {
		return err
	}
	if sm.TLSWeak, err = scalar(`SELECT count(DISTINCT ip) FROM hosts, json_tree(hosts.data) jt WHERE jt.key='warnings'`); err != nil {
		return err
	}
	if sm.SensitivePaths, err = scalar(`SELECT count(*) FROM hosts, json_tree(hosts.data) jt WHERE jt.key='category' AND jt.value='sensitive'`); err != nil {
		return err
	}
	return nil
}

// topPorts returns the most-common open ports across hosts, most-frequent first.
func (s *SQLite) topPorts(ctx context.Context, limit int) ([]PortCount, error) {
	// A portless (ICMP-alive) host has open_ports = "null"; json_each on a JSON
	// null yields one NULL-value row — filter it so the port scan doesn't hit NULL.
	rows, err := s.r.QueryContext(ctx, `
		SELECT p.value, count(*) FROM hosts, json_each(hosts.open_ports) p
		WHERE p.value IS NOT NULL
		GROUP BY p.value ORDER BY 2 DESC, p.value LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PortCount
	for rows.Next() {
		var port, n int64
		if err := rows.Scan(&port, &n); err != nil {
			return nil, err
		}
		out = append(out, PortCount{Port: uint16(port), Count: n})
	}
	return out, rows.Err()
}

// labelCounts runs a (label, count) query, skipping empty labels.
func (s *SQLite) labelCounts(ctx context.Context, query string, args ...any) ([]LabelCount, error) {
	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabelCount
	for rows.Next() {
		var (
			label sql.NullString
			n     int64
		)
		if err := rows.Scan(&label, &n); err != nil {
			return nil, err
		}
		if label.String == "" {
			continue
		}
		out = append(out, LabelCount{Label: label.String, Count: n})
	}
	return out, rows.Err()
}

func scanCounts(ctx context.Context, db *sql.DB, query string, dst map[string]int64) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			key string
			n   int64
		)
		if err := rows.Scan(&key, &n); err != nil {
			return err
		}
		dst[key] = n
	}
	return rows.Err()
}
