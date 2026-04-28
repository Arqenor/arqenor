package store

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// dbFilePerm is the on-disk permission applied to the SQLite DB and any
// auxiliary files (-wal / -shm) it creates. The store may contain
// alert messages that quote process command lines — privileged data —
// so 0o600 is enforced even if the host umask is permissive.
const dbFilePerm os.FileMode = 0o600

type Alert struct {
	ID         string    `json:"id"`
	Severity   string    `json:"severity"`
	Kind       string    `json:"kind"`
	Message    string    `json:"message"`
	OccurredAt time.Time `json:"occurred_at"`
	RuleID     string    `json:"rule_id,omitempty"`
	AttackID   string    `json:"attack_id,omitempty"`
}

type Scan struct {
	ID        string     `json:"id"`
	CIDR      string     `json:"cidr"`
	Status    string     `json:"status"` // "running" | "done" | "error"
	HostsUp   int        `json:"hosts_up"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

type Host struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	LastSeen string `json:"last_seen"`
}

const schema = `
CREATE TABLE IF NOT EXISTS alerts (
	id          TEXT PRIMARY KEY,
	severity    TEXT NOT NULL,
	kind        TEXT NOT NULL,
	message     TEXT NOT NULL,
	occurred_at TEXT NOT NULL,
	rule_id     TEXT,
	attack_id   TEXT
);
CREATE TABLE IF NOT EXISTS scans (
	id         TEXT PRIMARY KEY,
	cidr       TEXT NOT NULL,
	status     TEXT NOT NULL,
	hosts_up   INTEGER NOT NULL DEFAULT 0,
	started_at TEXT NOT NULL,
	ended_at   TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
	ip        TEXT PRIMARY KEY,
	hostname  TEXT,
	last_seen TEXT NOT NULL
);`

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Tighten perms after sql.Open has materialised the file. modernc.org/sqlite
	// honours the process umask on first create, which on a default Linux
	// container is 022 → 0644 file mode. Force 0600 here. Best-effort:
	// on Windows the chmod is a no-op for group/other bits, which is fine.
	if _, statErr := os.Stat(path); statErr == nil {
		_ = os.Chmod(path, dbFilePerm)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ── Alerts ───────────────────────────────────────────────────────────────────

func (s *Store) InsertAlert(a Alert) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO alerts (id, severity, kind, message, occurred_at, rule_id, attack_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Severity, a.Kind, a.Message,
		a.OccurredAt.UTC().Format(time.RFC3339),
		nullableString(a.RuleID), nullableString(a.AttackID),
	)
	return err
}

func (s *Store) ListAlerts() ([]Alert, error) {
	rows, err := s.db.Query(
		`SELECT id, severity, kind, message, occurred_at, COALESCE(rule_id,''), COALESCE(attack_id,'')
		 FROM alerts ORDER BY occurred_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		var occurredAt string
		if err := rows.Scan(&a.ID, &a.Severity, &a.Kind, &a.Message, &occurredAt, &a.RuleID, &a.AttackID); err != nil {
			return nil, err
		}
		a.OccurredAt, _ = time.Parse(time.RFC3339, occurredAt)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ── Scans ────────────────────────────────────────────────────────────────────

func (s *Store) InsertScan(scan Scan) error {
	_, err := s.db.Exec(
		`INSERT INTO scans (id, cidr, status, hosts_up, started_at) VALUES (?, ?, ?, ?, ?)`,
		scan.ID, scan.CIDR, scan.Status, scan.HostsUp, scan.StartedAt.Format(time.RFC3339),
	)
	return err
}

func (s *Store) UpdateScan(id, status string, hostsUp int) error {
	_, err := s.db.Exec(
		`UPDATE scans SET status = ?, hosts_up = ?, ended_at = ? WHERE id = ?`,
		status, hostsUp, time.Now().Format(time.RFC3339), id,
	)
	return err
}

func (s *Store) ListScans() ([]Scan, error) {
	rows, err := s.db.Query(
		`SELECT id, cidr, status, hosts_up, started_at, ended_at FROM scans ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var sc Scan
		var startedAt string
		var endedAt *string
		if err := rows.Scan(&sc.ID, &sc.CIDR, &sc.Status, &sc.HostsUp, &startedAt, &endedAt); err != nil {
			return nil, err
		}
		sc.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if endedAt != nil {
			t, _ := time.Parse(time.RFC3339, *endedAt)
			sc.EndedAt = &t
		}
		scans = append(scans, sc)
	}
	return scans, rows.Err()
}

// ── Hosts ────────────────────────────────────────────────────────────────────

func (s *Store) UpsertHost(ip, hostname string) error {
	_, err := s.db.Exec(
		`INSERT INTO hosts (ip, hostname, last_seen) VALUES (?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET hostname = excluded.hostname, last_seen = excluded.last_seen`,
		ip, hostname, time.Now().Format(time.RFC3339),
	)
	return err
}

func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT ip, hostname, last_seen FROM hosts ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var hostname *string
		if err := rows.Scan(&h.IP, &hostname, &h.LastSeen); err != nil {
			return nil, err
		}
		if hostname != nil {
			h.Hostname = *hostname
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}
