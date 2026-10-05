// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	_ "modernc.org/sqlite"
)

// StageAccepted is the stage every freshly registered incident starts in.
const StageAccepted = "受理"

// TimelineEntry is one recorded stage of an incident's history.
type TimelineEntry struct {
	Stage string `json:"stage"`
	Owner string `json:"owner"`
	At    string `json:"at"`
}

// Incident is the full registered record returned to callers.
type Incident struct {
	ID       string          `json:"id"`
	Severity string          `json:"severity"`
	Assets   []string        `json:"assets"`
	Stage    string          `json:"stage"`
	Owner    string          `json:"owner"`
	Timeline []TimelineEntry `json:"timeline"`
}

// IncidentConflictError reports a re-registration whose payload differs from
// the record already stored under the same id.
type IncidentConflictError struct {
	ID string
}

func (e *IncidentConflictError) Error() string {
	return fmt.Sprintf("incident %q already registered with different details", e.ID)
}

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Ping reports whether the storage layer is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// RegisterIncident stores a new incident together with its initial timeline
// entry in a single transaction. Re-registering the same id with identical
// severity, assets (order included) and owner returns the stored record
// untouched; any difference yields an *IncidentConflictError.
func (s *Store) RegisterIncident(inc Incident) (Incident, bool, error) {
	existing, err := s.GetIncident(inc.ID)
	if err != nil {
		return Incident{}, false, err
	}
	if existing != nil {
		return replayExisting(*existing, inc)
	}
	if err := s.insertIncident(inc); err != nil {
		// A concurrent registration may have won the race; settle it as a replay.
		existing, lookupErr := s.GetIncident(inc.ID)
		if lookupErr == nil && existing != nil {
			return replayExisting(*existing, inc)
		}
		return Incident{}, false, err
	}
	return inc, true, nil
}

// replayExisting decides whether a repeated registration matches the stored record.
func replayExisting(stored, incoming Incident) (Incident, bool, error) {
	if stored.Severity == incoming.Severity &&
		stored.Owner == incoming.Owner &&
		slices.Equal(stored.Assets, incoming.Assets) {
		return stored, false, nil
	}
	return Incident{}, false, &IncidentConflictError{ID: incoming.ID}
}

// insertIncident writes the incident row and its timeline entries atomically.
func (s *Store) insertIncident(inc Incident) error {
	assetsJSON, err := json.Marshal(inc.Assets)
	if err != nil {
		return fmt.Errorf("encode assets: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO incidents (id, severity, assets, stage, owner) VALUES (?, ?, ?, ?, ?)`,
		inc.ID, inc.Severity, string(assetsJSON), inc.Stage, inc.Owner,
	); err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	for seq, entry := range inc.Timeline {
		if _, err := tx.Exec(
			`INSERT INTO incident_timeline (incident_id, seq, stage, owner, at) VALUES (?, ?, ?, ?, ?)`,
			inc.ID, seq, entry.Stage, entry.Owner, entry.At,
		); err != nil {
			return fmt.Errorf("insert timeline: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit incident: %w", err)
	}
	return nil
}

// GetIncident loads one incident by id, or returns nil when the id is unknown.
func (s *Store) GetIncident(id string) (*Incident, error) {
	row := s.db.QueryRow(
		`SELECT id, severity, assets, stage, owner FROM incidents WHERE id = ?`, id)
	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	timeline, err := s.loadTimeline(id)
	if err != nil {
		return nil, err
	}
	inc.Timeline = timeline
	return inc, nil
}

// ListIncidents returns every incident matching the optional severity and
// stage filters, ordered by id in UTF-8 byte order (SQLite BINARY collation).
func (s *Store) ListIncidents(severity, stage string) ([]Incident, error) {
	query := `SELECT id, severity, assets, stage, owner FROM incidents`
	var conditions []string
	var args []any
	if severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}
	if stage != "" {
		conditions = append(conditions, "stage = ?")
		args = append(args, stage)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	incidents := []Incident{}
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, *inc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	for i := range incidents {
		timeline, err := s.loadTimeline(incidents[i].ID)
		if err != nil {
			return nil, err
		}
		incidents[i].Timeline = timeline
	}
	return incidents, nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanIncident(row scanner) (*Incident, error) {
	var inc Incident
	var assetsJSON string
	if err := row.Scan(&inc.ID, &inc.Severity, &assetsJSON, &inc.Stage, &inc.Owner); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(assetsJSON), &inc.Assets); err != nil {
		return nil, fmt.Errorf("decode assets: %w", err)
	}
	return &inc, nil
}

func (s *Store) loadTimeline(incidentID string) ([]TimelineEntry, error) {
	rows, err := s.db.Query(
		`SELECT stage, owner, at FROM incident_timeline WHERE incident_id = ? ORDER BY seq`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("load timeline: %w", err)
	}
	defer rows.Close()

	entries := []TimelineEntry{}
	for rows.Next() {
		var entry TimelineEntry
		if err := rows.Scan(&entry.Stage, &entry.Owner, &entry.At); err != nil {
			return nil, fmt.Errorf("load timeline: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load timeline: %w", err)
	}
	return entries, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS service_metadata (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
	id       TEXT PRIMARY KEY,
	severity TEXT NOT NULL,
	assets   TEXT NOT NULL,
	stage    TEXT NOT NULL,
	owner    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_timeline (
	incident_id TEXT NOT NULL REFERENCES incidents (id),
	seq         INTEGER NOT NULL,
	stage       TEXT NOT NULL,
	owner       TEXT NOT NULL,
	at          TEXT NOT NULL,
	PRIMARY KEY (incident_id, seq)
);
`
