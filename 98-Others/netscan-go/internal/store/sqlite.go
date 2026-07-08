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

// unionPorts merges two port lists into a sorted, de-duplicated slice.
func unionPorts(a, b []uint16) []uint16 {
	set := make(map[uint16]struct{}, len(a)+len(b))
	for _, p := range a {
		set[p] = struct{}{}
	}
	for _, p := range b {
		set[p] = struct{}{}
	}
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

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
	var existing string
	switch err := tx.QueryRowContext(ctx, `SELECT open_ports FROM hosts WHERE ip=?`,
		rec.IP.String()).Scan(&existing); err {
	case nil:
		var prev []uint16
		if json.Unmarshal([]byte(existing), &prev) == nil {
			merged = unionPorts(prev, rec.OpenPorts)
		}
	case sql.ErrNoRows:
		// new host
	default:
		return err
	}
	ports, err := json.Marshal(merged)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO hosts(ip, open_ports, first_seen, last_seen)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			open_ports = excluded.open_ports,
			last_seen  = excluded.last_seen`,
		rec.IP.String(), string(ports), now, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO work(ip, stage, state, attempts, available_at)
		VALUES(?, ?, 'pending', 0, ?)`,
		rec.IP.String(), stage, now); err != nil {
		return err
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
		portsJSON, dataJSON, statusJSON, ptrJSON string
		attempts                                 int
		firstSeen, lastSeen                      int64
	)
	err := s.r.QueryRowContext(ctx, `
		SELECT open_ports, data, status, ptr, attempts, first_seen, last_seen
		FROM hosts WHERE ip=?`, ip.String()).
		Scan(&portsJSON, &dataJSON, &statusJSON, &ptrJSON, &attempts, &firstSeen, &lastSeen)
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
	return h, nil
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
	var dataJSON, statusJSON, ptrJSON string
	switch err := tx.QueryRowContext(ctx, `SELECT data, status, ptr FROM hosts WHERE ip=?`,
		host.IP.String()).Scan(&dataJSON, &statusJSON, &ptrJSON); err {
	case nil:
		unmarshalJSON(dataJSON, &cur.Ports)
		unmarshalJSON(statusJSON, &cur.Status)
		unmarshalJSON(ptrJSON, &cur.PTR)
	case sql.ErrNoRows:
		// no row yet (shouldn't happen post-ingest); merge into an empty record
	default:
		return err
	}
	cur.Merge(host)

	data, _ := json.Marshal(cur.Ports)
	status, _ := json.Marshal(cur.Status)
	ptr, _ := json.Marshal(cur.PTR)
	if _, err := tx.ExecContext(ctx, `
		UPDATE hosts SET data=?, status=?, ptr=?, attempts=?, last_seen=? WHERE ip=?`,
		string(data), string(status), string(ptr), cur.Attempts, nowMS(), host.IP.String()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE work SET state='done', leased_until=NULL WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
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

func (s *SQLite) Stats(ctx context.Context) (Stats, error) {
	st := Stats{WorkByState: map[string]int64{}, PendingByStage: map[string]int64{}}

	if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM hosts`).Scan(&st.Hosts); err != nil {
		return st, err
	}

	if err := scanCounts(ctx, s.r, `SELECT state, count(*) FROM work GROUP BY state`, st.WorkByState); err != nil {
		return st, err
	}
	if err := scanCounts(ctx, s.r, `SELECT stage, count(*) FROM work WHERE state='pending' GROUP BY stage`, st.PendingByStage); err != nil {
		return st, err
	}

	runs, err := s.r.QueryContext(ctx, `
		SELECT tool, pid, counter, total, note, updated_at FROM runs ORDER BY updated_at DESC LIMIT 20`)
	if err != nil {
		return st, err
	}
	defer runs.Close()
	for runs.Next() {
		var (
			rs   RunStat
			note sql.NullString
			upd  int64
		)
		if err := runs.Scan(&rs.Tool, &rs.PID, &rs.Counter, &rs.Total, &note, &upd); err != nil {
			return st, err
		}
		rs.Note = note.String
		rs.UpdatedAt = fromMS(upd)
		st.Runs = append(st.Runs, rs)
	}
	if err := runs.Err(); err != nil {
		return st, err
	}

	hosts, err := s.r.QueryContext(ctx, `
		SELECT ip, open_ports, last_seen FROM hosts ORDER BY last_seen DESC LIMIT 10`)
	if err != nil {
		return st, err
	}
	defer hosts.Close()
	for hosts.Next() {
		var (
			ipStr, portsJSON string
			last             int64
		)
		if err := hosts.Scan(&ipStr, &portsJSON, &last); err != nil {
			return st, err
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return st, err
		}
		hs := HostSummary{IP: addr, LastSeen: fromMS(last)}
		_ = json.Unmarshal([]byte(portsJSON), &hs.OpenPorts)
		st.RecentHosts = append(st.RecentHosts, hs)
	}
	return st, hosts.Err()
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
