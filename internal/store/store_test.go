package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestOpenCreatesUsableStore(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestRegisterReturnsInitialTimeline(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	incident, err := st.Register("INC-1", "high", "alice", []string{"db-1", "web-2"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if incident.Stage != InitialStage {
		t.Fatalf("stage = %q, want %q", incident.Stage, InitialStage)
	}
	if len(incident.Timeline) != 1 {
		t.Fatalf("timeline length = %d, want 1", len(incident.Timeline))
	}
	entry := incident.Timeline[0]
	if entry.Stage != incident.Stage || entry.Owner != incident.Owner {
		t.Fatalf("timeline entry = %+v, want stage/owner of incident", entry)
	}
	at, err := time.Parse(time.RFC3339, entry.At)
	if err != nil {
		t.Fatalf("at %q is not RFC3339: %v", entry.At, err)
	}
	if at.Location() != time.UTC {
		t.Fatalf("at location = %v, want UTC", at.Location())
	}
}

func TestRegisterSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	registered, err := st.Register("INC-1", "medium", "bob", []string{"api", "worker"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	got, err := reopened.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(got, registered) {
		t.Fatalf("got %+v, want %+v", got, registered)
	}
}

func TestRegisterDuplicateIsIdempotent(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	first, err := st.Register("INC-1", "low", "carol", []string{"a", "b"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	time.Sleep(time.Second) // a rewritten timestamp would be visible
	again, err := st.Register("INC-1", "low", "carol", []string{"a", "b"})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if !reflect.DeepEqual(again, first) {
		t.Fatalf("duplicate register = %+v, want original %+v", again, first)
	}
}

func TestRegisterConflict(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "high", "alice", []string{"a", "b"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	cases := []struct {
		name     string
		severity string
		owner    string
		assets   []string
	}{
		{"severity differs", "low", "alice", []string{"a", "b"}},
		{"owner differs", "high", "bob", []string{"a", "b"}},
		{"asset order differs", "high", "alice", []string{"b", "a"}},
		{"asset set differs", "high", "alice", []string{"a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := st.Register("INC-1", tc.severity, tc.owner, tc.assets); !errors.Is(err, ErrIncidentConflict) {
				t.Fatalf("err = %v, want ErrIncidentConflict", err)
			}
		})
	}

	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Severity != "high" || got.Owner != "alice" || !reflect.DeepEqual(got.Assets, []string{"a", "b"}) {
		t.Fatalf("conflicting register mutated the incident: %+v", got)
	}
	if len(got.Timeline) != 1 {
		t.Fatalf("timeline length = %d, want 1", len(got.Timeline))
	}
}

func TestGetMissingIncident(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Get("nope"); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("err = %v, want ErrIncidentNotFound", err)
	}
}

func TestListOrdersByIDBytesAndFilters(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Byte order: "INC-10" sorts before "INC-2".
	for _, item := range []struct {
		id       string
		severity string
	}{
		{"INC-2", "low"},
		{"INC-10", "high"},
		{"INC-1", "high"},
	} {
		if _, err := st.Register(item.id, item.severity, "owner", []string{"a"}); err != nil {
			t.Fatalf("register %s: %v", item.id, err)
		}
	}

	all, err := st.List("", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	ids := make([]string, len(all))
	for i, incident := range all {
		ids[i] = incident.ID
	}
	if want := []string{"INC-1", "INC-10", "INC-2"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}

	high, err := st.List("high", "")
	if err != nil {
		t.Fatalf("list high: %v", err)
	}
	if len(high) != 2 || high[0].ID != "INC-1" || high[1].ID != "INC-10" {
		t.Fatalf("high filter = %+v", high)
	}

	accepted, err := st.List("", InitialStage)
	if err != nil {
		t.Fatalf("list stage: %v", err)
	}
	if len(accepted) != 3 {
		t.Fatalf("stage filter matched %d incidents, want 3", len(accepted))
	}

	combo, err := st.List("high", InitialStage)
	if err != nil {
		t.Fatalf("list combo: %v", err)
	}
	if len(combo) != 2 {
		t.Fatalf("combo filter matched %d incidents, want 2", len(combo))
	}

	none, err := st.List("critical", "")
	if err != nil {
		t.Fatalf("list none: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected empty result, got %+v", none)
	}
}
