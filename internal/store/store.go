// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// InitialStage is the stage every incident starts in when it is registered.
const InitialStage = "受理"

// stageOrder lists the stages in the only order an incident may advance.
// Transitions move exactly one step forward along this list.
var stageOrder = []string{"受理", "遏制", "清除", "恢复", "关闭"}

// nextStage returns the stage that immediately follows current, or false when
// current is the final stage (or otherwise has no successor).
func nextStage(current string) (string, bool) {
	for i, stage := range stageOrder[:len(stageOrder)-1] {
		if stage == current {
			return stageOrder[i+1], true
		}
	}
	return "", false
}

// TimelineEntry records one stage of an incident's life together with the
// owner responsible at that point and the UTC time the entry was created.
type TimelineEntry struct {
	Stage string `json:"stage"`
	Owner string `json:"owner"`
	At    string `json:"at"`
}

// Incident is a registered ticket together with its full transition history.
type Incident struct {
	ID       string          `json:"id"`
	Severity string          `json:"severity"`
	Assets   []string        `json:"assets"`
	Stage    string          `json:"stage"`
	Owner    string          `json:"owner"`
	Timeline []TimelineEntry `json:"timeline"`
}

// ErrIncidentConflict is returned when an id is registered again with
// different severity, assets, or owner.
var ErrIncidentConflict = errors.New("incident id already registered with different attributes")

// ErrIncidentNotFound is returned when no incident exists for an id.
var ErrIncidentNotFound = errors.New("incident not found")

// ErrInvalidTransition is returned when a transition does not advance the
// incident exactly one stage forward: requesting the current stage, going
// backward, skipping a stage, or moving on from the final stage.
var ErrInvalidTransition = errors.New("transition does not advance exactly one stage")

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
	// SQLite admits a single writer, so funnel every call through one
	// connection: transactions then serialize instead of failing with
	// SQLITE_BUSY, and a transaction never waits on a pool connection its
	// own goroutine is holding.
	db.SetMaxOpenConns(1)
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

// Register stores a new incident and its initial timeline entry in one
// transaction. Re-registering the same id with identical severity, assets
// (order included), and owner returns the stored record unchanged; any
// difference yields ErrIncidentConflict.
func (s *Store) Register(id, severity, owner string, assets []string) (Incident, error) {
	existing, err := s.find(id)
	if err != nil {
		return Incident{}, err
	}
	if existing != nil {
		return resolveDuplicate(existing, severity, owner, assets)
	}

	encoded, err := json.Marshal(assets)
	if err != nil {
		return Incident{}, fmt.Errorf("encode assets: %w", err)
	}
	at := time.Now().UTC().Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return Incident{}, fmt.Errorf("begin register: %w", err)
	}
	if _, err = tx.Exec(
		"INSERT INTO incidents (id, severity, assets, stage, owner) VALUES (?, ?, ?, ?, ?)",
		id, severity, string(encoded), InitialStage, owner,
	); err == nil {
		if _, err = tx.Exec(
			"INSERT INTO incident_timeline (incident_id, seq, stage, owner, at) VALUES (?, 0, ?, ?, ?)",
			id, InitialStage, owner, at,
		); err == nil {
			err = tx.Commit()
		}
	}
	if err != nil {
		// Roll back before re-reading: the store runs on a single
		// connection, which the open transaction is still holding.
		tx.Rollback()
		// A concurrent register of the same id may have won the race.
		if existing, findErr := s.find(id); findErr == nil && existing != nil {
			return resolveDuplicate(existing, severity, owner, assets)
		}
		return Incident{}, fmt.Errorf("register incident: %w", err)
	}

	return Incident{
		ID:       id,
		Severity: severity,
		Assets:   assets,
		Stage:    InitialStage,
		Owner:    owner,
		Timeline: []TimelineEntry{{Stage: InitialStage, Owner: owner, At: at}},
	}, nil
}

// Transition advances the incident registered under id to stage, which must
// be the immediate successor of the current stage, and appends a timeline
// entry with owner and a service-generated UTC timestamp. The stage, owner,
// and history entry commit in one transaction: either all are stored or none
// is. A concurrent transition of the same incident loses the race and
// returns ErrInvalidTransition; a missing id returns ErrIncidentNotFound.
func (s *Store) Transition(id, stage, owner string) (Incident, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Incident{}, fmt.Errorf("begin transition: %w", err)
	}
	defer tx.Rollback()

	incident, err := scanIncident(tx.QueryRow(
		"SELECT id, severity, assets, stage, owner FROM incidents WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, ErrIncidentNotFound
	}
	if err != nil {
		return Incident{}, fmt.Errorf("load incident: %w", err)
	}

	next, ok := nextStage(incident.Stage)
	if !ok || next != stage {
		return Incident{}, ErrInvalidTransition
	}

	at := time.Now().UTC().Format(time.RFC3339)
	result, err := tx.Exec(
		"UPDATE incidents SET stage = ?, owner = ? WHERE id = ? AND stage = ?",
		stage, owner, id, incident.Stage)
	if err != nil {
		return Incident{}, fmt.Errorf("update stage: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		// Another transition moved the incident between our read and write.
		return Incident{}, ErrInvalidTransition
	}

	var seq int
	if err := tx.QueryRow(
		"SELECT COALESCE(MAX(seq), -1) + 1 FROM incident_timeline WHERE incident_id = ?", id,
	).Scan(&seq); err != nil {
		return Incident{}, fmt.Errorf("read timeline seq: %w", err)
	}
	if _, err := tx.Exec(
		"INSERT INTO incident_timeline (incident_id, seq, stage, owner, at) VALUES (?, ?, ?, ?, ?)",
		id, seq, stage, owner, at,
	); err != nil {
		return Incident{}, fmt.Errorf("append timeline: %w", err)
	}

	timeline, err := queryTimeline(tx, id)
	if err != nil {
		return Incident{}, err
	}
	if err := tx.Commit(); err != nil {
		return Incident{}, fmt.Errorf("commit transition: %w", err)
	}

	incident.Stage = stage
	incident.Owner = owner
	incident.Timeline = timeline
	return incident, nil
}

// Get returns the incident registered under id, or ErrIncidentNotFound.
func (s *Store) Get(id string) (Incident, error) {
	incident, err := s.find(id)
	if err != nil {
		return Incident{}, err
	}
	if incident == nil {
		return Incident{}, ErrIncidentNotFound
	}
	return *incident, nil
}

// List returns every incident matching the optional severity and stage
// filters, ordered by id in UTF-8 byte order. Empty filters match everything.
func (s *Store) List(severity, stage string) ([]Incident, error) {
	query := "SELECT id, severity, assets, stage, owner FROM incidents"
	var clauses []string
	var args []any
	if severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, severity)
	}
	if stage != "" {
		clauses = append(clauses, "stage = ?")
		args = append(args, stage)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY id"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	incidents := []Incident{}
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		incidents = append(incidents, incident)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	rows.Close()

	for i := range incidents {
		timeline, err := s.timeline(incidents[i].ID)
		if err != nil {
			return nil, err
		}
		incidents[i].Timeline = timeline
	}
	return incidents, nil
}

// find loads one incident by id, returning nil when it does not exist.
func (s *Store) find(id string) (*Incident, error) {
	row := s.db.QueryRow(
		"SELECT id, severity, assets, stage, owner FROM incidents WHERE id = ?", id)
	incident, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	timeline, err := s.timeline(id)
	if err != nil {
		return nil, err
	}
	incident.Timeline = timeline
	return &incident, nil
}

// timeline loads the transition history of one incident in entry order.
func (s *Store) timeline(id string) ([]TimelineEntry, error) {
	return queryTimeline(s.db, id)
}

// queryTimeline is timeline against any handle, so a transaction can read
// history through its own connection instead of waiting on the pool.
func queryTimeline(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}, id string) ([]TimelineEntry, error) {
	rows, err := q.Query(
		"SELECT stage, owner, at FROM incident_timeline WHERE incident_id = ? ORDER BY seq", id)
	if err != nil {
		return nil, fmt.Errorf("read timeline: %w", err)
	}
	defer rows.Close()

	entries := []TimelineEntry{}
	for rows.Next() {
		var entry TimelineEntry
		if err := rows.Scan(&entry.Stage, &entry.Owner, &entry.At); err != nil {
			return nil, fmt.Errorf("read timeline: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read timeline: %w", err)
	}
	return entries, nil
}

// resolveDuplicate decides whether a repeated registration is the same
// incident (returned unchanged) or a conflicting one.
func resolveDuplicate(existing *Incident, severity, owner string, assets []string) (Incident, error) {
	if existing.Severity == severity && existing.Owner == owner && slices.Equal(existing.Assets, assets) {
		return *existing, nil
	}
	return Incident{}, ErrIncidentConflict
}

// scanner is the common shape of QueryRow/Query results over the incidents table.
type scanner interface {
	Scan(dest ...any) error
}

func scanIncident(row scanner) (Incident, error) {
	var incident Incident
	var encoded string
	if err := row.Scan(&incident.ID, &incident.Severity, &encoded, &incident.Stage, &incident.Owner); err != nil {
		return Incident{}, err
	}
	if err := json.Unmarshal([]byte(encoded), &incident.Assets); err != nil {
		return Incident{}, fmt.Errorf("decode assets: %w", err)
	}
	return incident, nil
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
	incident_id TEXT NOT NULL REFERENCES incidents(id),
	seq         INTEGER NOT NULL,
	stage       TEXT NOT NULL,
	owner       TEXT NOT NULL,
	at          TEXT NOT NULL,
	PRIMARY KEY (incident_id, seq)
);
`
