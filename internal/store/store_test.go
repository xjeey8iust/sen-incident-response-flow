package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
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

func sampleIncident() Incident {
	return Incident{
		ID:       "INC-1",
		Severity: "high",
		Assets:   []string{"db-01", "db-02"},
		Stage:    StageAccepted,
		Owner:    "alice",
		Timeline: []TimelineEntry{{Stage: StageAccepted, Owner: "alice", At: "2026-10-05T08:00:00Z"}},
	}
}

func TestRegisterPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	want := sampleIncident()
	stored, created, err := st.RegisterIncident(want)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !created {
		t.Fatal("first registration should report created")
	}
	if !reflect.DeepEqual(stored, want) {
		t.Fatalf("stored = %+v, want %+v", stored, want)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.GetIncident("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("incident missing after reopen")
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("got %+v, want %+v", *got, want)
	}
}

func TestRegisterReplayReturnsStoredRecordUntouched(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	first := sampleIncident()
	if _, _, err := st.RegisterIncident(first); err != nil {
		t.Fatalf("register: %v", err)
	}

	replay := sampleIncident()
	replay.Timeline = []TimelineEntry{{Stage: StageAccepted, Owner: "alice", At: "2026-10-05T09:30:00Z"}}
	stored, created, err := st.RegisterIncident(replay)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if created {
		t.Fatal("replay must not report created")
	}
	if !reflect.DeepEqual(stored, first) {
		t.Fatalf("stored = %+v, want original %+v", stored, first)
	}
	if stored.Timeline[0].At != "2026-10-05T08:00:00Z" {
		t.Fatalf("replay must not rewrite the timeline, got at=%s", stored.Timeline[0].At)
	}
}

func TestRegisterConflictOnDifferentDetails(t *testing.T) {
	cases := map[string]func(Incident) Incident{
		"severity": func(i Incident) Incident { i.Severity = "low"; return i },
		"owner":    func(i Incident) Incident { i.Owner = "bob"; return i },
		"assets":   func(i Incident) Incident { i.Assets = []string{"db-02", "db-01"}; return i },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			st, err := Open(filepath.Join(t.TempDir(), "store.db"))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer st.Close()

			if _, _, err := st.RegisterIncident(sampleIncident()); err != nil {
				t.Fatalf("register: %v", err)
			}
			_, _, err = st.RegisterIncident(mutate(sampleIncident()))
			var conflict *IncidentConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("err = %v, want IncidentConflictError", err)
			}
		})
	}
}

func TestGetIncidentReturnsNilForUnknownID(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.GetIncident("missing")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

func TestListIncidentsOrdersByIDAndFilters(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	seed := []Incident{
		{ID: "INC-2", Severity: "low", Assets: []string{"a"}, Stage: StageAccepted, Owner: "o1", Timeline: []TimelineEntry{{Stage: StageAccepted, Owner: "o1", At: "2026-10-05T08:00:00Z"}}},
		{ID: "INC-10", Severity: "high", Assets: []string{"b"}, Stage: StageAccepted, Owner: "o2", Timeline: []TimelineEntry{{Stage: StageAccepted, Owner: "o2", At: "2026-10-05T08:01:00Z"}}},
		{ID: "INC-1", Severity: "high", Assets: []string{"c"}, Stage: StageAccepted, Owner: "o3", Timeline: []TimelineEntry{{Stage: StageAccepted, Owner: "o3", At: "2026-10-05T08:02:00Z"}}},
	}
	for _, inc := range seed {
		if _, _, err := st.RegisterIncident(inc); err != nil {
			t.Fatalf("register %s: %v", inc.ID, err)
		}
	}

	all, err := st.ListIncidents("", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	gotIDs := []string{all[0].ID, all[1].ID, all[2].ID}
	wantIDs := []string{"INC-1", "INC-10", "INC-2"} // UTF-8 byte order
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("ids = %v, want %v", gotIDs, wantIDs)
	}

	high, err := st.ListIncidents("high", "")
	if err != nil {
		t.Fatalf("list severity: %v", err)
	}
	if len(high) != 2 || high[0].ID != "INC-1" || high[1].ID != "INC-10" {
		t.Fatalf("severity filter = %+v", high)
	}

	combo, err := st.ListIncidents("low", StageAccepted)
	if err != nil {
		t.Fatalf("list combo: %v", err)
	}
	if len(combo) != 1 || combo[0].ID != "INC-2" {
		t.Fatalf("combo filter = %+v", combo)
	}

	none, err := st.ListIncidents("critical", "")
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("empty filter = %+v", none)
	}
}
