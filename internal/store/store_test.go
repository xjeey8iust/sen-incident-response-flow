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

func TestTransitionAdvancesOneStage(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	registered, err := st.Register("INC-1", "high", "alice", []string{"db-1", "web-2"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	incident, err := st.Transition("INC-1", "遏制", "bob")
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if incident.Stage != "遏制" || incident.Owner != "bob" {
		t.Fatalf("stage/owner = %q/%q, want 遏制/bob", incident.Stage, incident.Owner)
	}
	if incident.ID != registered.ID || incident.Severity != registered.Severity ||
		!reflect.DeepEqual(incident.Assets, registered.Assets) {
		t.Fatalf("transition changed fixed fields: %+v vs %+v", incident, registered)
	}
	if len(incident.Timeline) != 2 {
		t.Fatalf("timeline length = %d, want 2", len(incident.Timeline))
	}
	if incident.Timeline[0] != registered.Timeline[0] {
		t.Fatalf("transition rewrote history: %+v vs %+v", incident.Timeline[0], registered.Timeline[0])
	}
	entry := incident.Timeline[1]
	if entry.Stage != "遏制" || entry.Owner != "bob" {
		t.Fatalf("new entry = %+v, want 遏制/bob", entry)
	}
	at, err := time.Parse(time.RFC3339, entry.At)
	if err != nil || at.Location() != time.UTC {
		t.Fatalf("at %q is not UTC RFC3339: %v", entry.At, err)
	}

	// The stored record matches what the transition returned.
	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(got, incident) {
		t.Fatalf("stored %+v, want %+v", got, incident)
	}
}

func TestTransitionWalksEveryStage(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "low", "alice", []string{"a"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	stages := []string{"遏制", "清除", "恢复", "关闭"}
	var incident Incident
	for i, stage := range stages {
		owner := string(rune('a' + i))
		incident, err = st.Transition("INC-1", stage, owner)
		if err != nil {
			t.Fatalf("transition to %s: %v", stage, err)
		}
		if incident.Stage != stage || incident.Owner != owner {
			t.Fatalf("stage/owner = %q/%q, want %q/%q", incident.Stage, incident.Owner, stage, owner)
		}
		if len(incident.Timeline) != i+2 {
			t.Fatalf("timeline length = %d, want %d", len(incident.Timeline), i+2)
		}
	}
	for i, entry := range incident.Timeline {
		want := append([]string{InitialStage}, stages...)[i]
		if entry.Stage != want {
			t.Fatalf("timeline[%d].Stage = %q, want %q", i, entry.Stage, want)
		}
	}
}

func TestTransitionRejectsInvalidMoves(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	before, err := st.Register("INC-1", "medium", "alice", []string{"a"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Same stage, skipping ahead, and the initial stage are all illegal.
	for _, stage := range []string{"受理", "清除", "恢复", "关闭"} {
		if _, err := st.Transition("INC-1", stage, "bob"); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("transition to %s: err = %v, want ErrInvalidTransition", stage, err)
		}
	}
	if _, err := st.Transition("INC-1", "遏制", "bob"); err != nil {
		t.Fatalf("transition to 遏制: %v", err)
	}
	// Backwards and repeated moves are illegal too.
	for _, stage := range []string{"受理", "遏制", "恢复", "关闭"} {
		if _, err := st.Transition("INC-1", stage, "bob"); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("transition to %s: err = %v, want ErrInvalidTransition", stage, err)
		}
	}

	// Failed transitions changed nothing beyond the one accepted move.
	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Stage != "遏制" || got.Owner != "bob" || len(got.Timeline) != 2 {
		t.Fatalf("failed transitions mutated the incident: %+v", got)
	}
	if got.Timeline[0] != before.Timeline[0] {
		t.Fatalf("history rewritten: %+v vs %+v", got.Timeline[0], before.Timeline[0])
	}
}

func TestTransitionFromClosedIsInvalid(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "low", "alice", []string{"a"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, stage := range []string{"遏制", "清除", "恢复", "关闭"} {
		if _, err := st.Transition("INC-1", stage, "bob"); err != nil {
			t.Fatalf("transition to %s: %v", stage, err)
		}
	}
	for _, stage := range []string{"受理", "遏制", "清除", "恢复", "关闭"} {
		if _, err := st.Transition("INC-1", stage, "carol"); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("transition from 关闭 to %s: err = %v, want ErrInvalidTransition", stage, err)
		}
	}
	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Stage != "关闭" || len(got.Timeline) != 5 {
		t.Fatalf("closed incident changed: %+v", got)
	}
}

func TestTransitionMissingIncident(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Transition("nope", "遏制", "alice"); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("err = %v, want ErrIncidentNotFound", err)
	}
}

func TestTransitionConcurrentOnlyOneWins(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "high", "alice", []string{"a"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	const racers = 8
	results := make(chan error, racers)
	for i := 0; i < racers; i++ {
		go func(i int) {
			owner := string(rune('a' + i))
			_, err := st.Transition("INC-1", "遏制", owner)
			results <- err
		}(i)
	}
	wins := 0
	for i := 0; i < racers; i++ {
		err := <-results
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("err = %v, want nil or ErrInvalidTransition", err)
		}
	}
	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}

	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Stage != "遏制" || len(got.Timeline) != 2 {
		t.Fatalf("stage = %q timeline = %d, want 遏制 and 2", got.Stage, len(got.Timeline))
	}
	if got.Timeline[1].Owner != got.Owner {
		t.Fatalf("owner %q does not match timeline owner %q", got.Owner, got.Timeline[1].Owner)
	}
}

func TestTransitionSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.Register("INC-1", "critical", "alice", []string{"a", "b"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	moved, err := st.Transition("INC-1", "遏制", "bob")
	if err != nil {
		t.Fatalf("transition: %v", err)
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
	if !reflect.DeepEqual(got, moved) {
		t.Fatalf("got %+v, want %+v", got, moved)
	}
}
