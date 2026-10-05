package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
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

func TestRegisterReplayAfterTransitionsUsesRegistrationOwner(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "high", "alice", []string{"db-1", "web-2"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	moved, err := st.Transition("INC-1", "遏制", "bob")
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	time.Sleep(time.Second) // a rewritten timestamp would be visible

	// Replaying the original create content returns the current record with
	// its transitions, not a rollback to 受理.
	replayed, err := st.Register("INC-1", "high", "alice", []string{"db-1", "web-2"})
	if err != nil {
		t.Fatalf("replay register: %v", err)
	}
	if !reflect.DeepEqual(replayed, moved) {
		t.Fatalf("replay = %+v, want current record %+v", replayed, moved)
	}
	if replayed.Stage != "遏制" || replayed.Owner != "bob" {
		t.Fatalf("replay rolled back stage/owner: %q/%q", replayed.Stage, replayed.Owner)
	}
	if len(replayed.Timeline) != 2 {
		t.Fatalf("replay changed timeline: %+v", replayed.Timeline)
	}

	// An owner equal to the current transition owner but different from the
	// registration owner is still a conflict.
	if _, err := st.Register("INC-1", "high", "bob", []string{"db-1", "web-2"}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("current-owner replay: err = %v, want ErrIncidentConflict", err)
	}

	// Severity, asset content, and asset order changes conflict as well.
	for _, tc := range []struct {
		name     string
		severity string
		owner    string
		assets   []string
	}{
		{"severity differs", "low", "alice", []string{"db-1", "web-2"}},
		{"asset content differs", "high", "alice", []string{"db-1", "web-3"}},
		{"asset added", "high", "alice", []string{"db-1", "web-2", "db-2"}},
		{"asset removed", "high", "alice", []string{"db-1"}},
		{"asset order differs", "high", "alice", []string{"web-2", "db-1"}},
		{"asset duplicates differ", "high", "alice", []string{"db-1", "db-1", "web-2"}},
		{"owner differs", "high", "carol", []string{"db-1", "web-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := st.Register("INC-1", tc.severity, tc.owner, tc.assets); !errors.Is(err, ErrIncidentConflict) {
				t.Fatalf("err = %v, want ErrIncidentConflict", err)
			}
		})
	}

	// Neither the replay nor the conflicts wrote anything.
	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(got, moved) {
		t.Fatalf("record changed: got %+v, want %+v", got, moved)
	}
}

func TestRegisterReplayWalksFullFlowAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.Register("INC-1", "high", "alice", []string{"db-1", "web-2"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	owners := []string{"bob", "carol", "dave", "erin"}
	for i, stage := range []string{"遏制", "清除", "恢复", "关闭"} {
		if _, err := st.Transition("INC-1", stage, owners[i]); err != nil {
			t.Fatalf("transition to %s: %v", stage, err)
		}
	}
	closed, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// The rule also covers a closed incident, with the current owner erin.
	replayed, err := st.Register("INC-1", "high", "alice", []string{"db-1", "web-2"})
	if err != nil {
		t.Fatalf("replay on closed: %v", err)
	}
	if !reflect.DeepEqual(replayed, closed) {
		t.Fatalf("replay = %+v, want %+v", replayed, closed)
	}
	// The current owner (erin) is not the registration owner (alice).
	if _, err := st.Register("INC-1", "high", "erin", []string{"db-1", "web-2"}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("current-owner replay on closed: err = %v, want ErrIncidentConflict", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// After a restart the registration owner is read from the persisted
	// initial timeline entry; no re-registration is required.
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	replayed, err = reopened.Register("INC-1", "high", "alice", []string{"db-1", "web-2"})
	if err != nil {
		t.Fatalf("replay after reopen: %v", err)
	}
	if !reflect.DeepEqual(replayed, closed) {
		t.Fatalf("replay after reopen = %+v, want %+v", replayed, closed)
	}
	if _, err := reopened.Register("INC-1", "high", "erin", []string{"db-1", "web-2"}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("current-owner replay after reopen: err = %v, want ErrIncidentConflict", err)
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

func TestTransitionAdvancesOneStageAtATime(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "high", "alice", []string{"db-1", "web-2"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	stages := []string{"遏制", "清除", "恢复", "关闭"}
	owners := []string{"bob", "carol", "  dave  ", "erin"}
	for i, stage := range stages {
		incident, err := st.Transition("INC-1", stage, owners[i])
		if err != nil {
			t.Fatalf("transition to %s: %v", stage, err)
		}
		if incident.ID != "INC-1" || incident.Severity != "high" {
			t.Fatalf("identity changed: %+v", incident)
		}
		if !reflect.DeepEqual(incident.Assets, []string{"db-1", "web-2"}) {
			t.Fatalf("assets changed: %v", incident.Assets)
		}
		if incident.Stage != stage || incident.Owner != owners[i] {
			t.Fatalf("stage/owner = %q/%q, want %q/%q", incident.Stage, incident.Owner, stage, owners[i])
		}
		if len(incident.Timeline) != i+2 {
			t.Fatalf("timeline length = %d, want %d", len(incident.Timeline), i+2)
		}
		entry := incident.Timeline[len(incident.Timeline)-1]
		if entry.Stage != stage || entry.Owner != owners[i] {
			t.Fatalf("last entry = %+v, want %q/%q", entry, stage, owners[i])
		}
		at, err := time.Parse(time.RFC3339, entry.At)
		if err != nil || at.Location() != time.UTC {
			t.Fatalf("at %q is not UTC RFC3339 (%v)", entry.At, err)
		}
	}

	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Stage != "关闭" || got.Owner != "erin" || len(got.Timeline) != 5 {
		t.Fatalf("stored incident = %+v", got)
	}
}

func TestTransitionRejectsInvalidMoves(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	registered, err := st.Register("INC-1", "medium", "alice", []string{"a"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	cases := map[string]string{
		"current stage": "受理",
		"skip a stage":  "清除",
		"jump to end":   "关闭",
		"unknown stage": "unknown",
	}
	for name, stage := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := st.Transition("INC-1", stage, "bob"); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("err = %v, want ErrInvalidTransition", err)
			}
		})
	}

	if _, err := st.Transition("INC-1", "遏制", "bob"); err != nil {
		t.Fatalf("transition: %v", err)
	}
	if _, err := st.Transition("INC-1", "受理", "bob"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("backward: err = %v, want ErrInvalidTransition", err)
	}

	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Stage != "遏制" || got.Owner != "bob" || len(got.Timeline) != 2 {
		t.Fatalf("failed transitions mutated the incident: %+v", got)
	}
	if got.Timeline[0] != registered.Timeline[0] {
		t.Fatalf("history rewritten: %+v vs %+v", got.Timeline[0], registered.Timeline[0])
	}
}

func TestTransitionFromFinalStageFails(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "low", "alice", []string{"a"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, stage := range []string{"遏制", "清除", "恢复", "关闭"} {
		if _, err := st.Transition("INC-1", stage, "alice"); err != nil {
			t.Fatalf("transition to %s: %v", stage, err)
		}
	}
	for _, stage := range []string{"关闭", "受理", "遏制"} {
		if _, err := st.Transition("INC-1", stage, "alice"); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("from closed to %s: err = %v, want ErrInvalidTransition", stage, err)
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

func TestTransitionSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.Register("INC-1", "high", "alice", []string{"a", "b"}); err != nil {
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

	// The flow resumes from the stored stage after a restart.
	again, err := reopened.Transition("INC-1", "清除", "carol")
	if err != nil {
		t.Fatalf("transition after reopen: %v", err)
	}
	if len(again.Timeline) != 3 || again.Timeline[2].Stage != "清除" {
		t.Fatalf("timeline after reopen = %+v", again.Timeline)
	}
}

func TestTransitionConcurrentSameStage(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "high", "alice", []string{"a"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	const racers = 8
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = st.Transition("INC-1", "遏制", "racer")
		}()
	}
	wg.Wait()

	succeeded := 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrInvalidTransition):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("succeeded = %d, want exactly 1", succeeded)
	}

	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Stage != "遏制" || got.Owner != "racer" || len(got.Timeline) != 2 {
		t.Fatalf("incident = %+v, want one transition and two entries", got)
	}
}

// flowExpectation describes the committed states one incident walks through:
// stageFlow[i] is reached from stageFlow[i-1] by a transition that appends a
// timeline entry owned by ownerFlow[i].
var (
	stageFlow = []string{"受理", "遏制", "清除", "恢复", "关闭"}
	ownerFlow = []string{"alice", "bob", "carol", "dave", "erin"}
)

// checkConsistent fails the test unless incident is internally consistent:
// the body matches the last timeline entry, the timeline has exactly one
// entry per stage up to the current one, and every entry carries the stage
// and owner the flow assigned to it. A body read from one committed state
// paired with a history read from another violates every one of these.
func checkConsistent(t *testing.T, incident Incident) {
	t.Helper()
	idx := slices.Index(stageFlow, incident.Stage)
	if idx < 0 {
		t.Fatalf("stage = %q, not on the flow", incident.Stage)
	}
	if len(incident.Timeline) != idx+1 {
		t.Fatalf("stage %q with %d timeline entries, want %d: %+v",
			incident.Stage, len(incident.Timeline), idx+1, incident)
	}
	if incident.Owner != ownerFlow[idx] {
		t.Fatalf("stage %q with owner %q, want %q: %+v",
			incident.Stage, incident.Owner, ownerFlow[idx], incident)
	}
	for i, entry := range incident.Timeline {
		if entry.Stage != stageFlow[i] || entry.Owner != ownerFlow[i] {
			t.Fatalf("timeline entry %d = %+v, want %q/%q: %+v",
				i, entry, stageFlow[i], ownerFlow[i], incident)
		}
		if entry.At == "" {
			t.Fatalf("timeline entry %d lost its timestamp: %+v", i, incident)
		}
	}
	last := incident.Timeline[len(incident.Timeline)-1]
	if last.Stage != incident.Stage || last.Owner != incident.Owner {
		t.Fatalf("body %q/%q disagrees with last entry %+v",
			incident.Stage, incident.Owner, last)
	}
}

func TestGetConsistentWhileTransitionsCommit(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.Register("INC-1", "high", ownerFlow[0], []string{"a"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Readers hammer Get while the writer walks the incident through every
	// stage. Each read must land entirely before or entirely after a commit:
	// either the 受理/alice body with one entry, a later stage with its full
	// history, but never a mixture of two states.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				incident, err := st.Get("INC-1")
				if err != nil {
					t.Errorf("get: %v", err)
					return
				}
				checkConsistent(t, incident)
			}
		}()
	}

	timestamps := make([]string, 0, len(stageFlow))
	first, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	timestamps = append(timestamps, first.Timeline[0].At)
	for i := 1; i < len(stageFlow); i++ {
		moved, err := st.Transition("INC-1", stageFlow[i], ownerFlow[i])
		if err != nil {
			t.Fatalf("transition to %s: %v", stageFlow[i], err)
		}
		timestamps = append(timestamps, moved.Timeline[len(moved.Timeline)-1].At)
	}
	close(stop)
	wg.Wait()

	// After the last transition returned, the stored record is the complete
	// 关闭 state with every original timestamp preserved.
	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	checkConsistent(t, got)
	for i, entry := range got.Timeline {
		if entry.At != timestamps[i] {
			t.Fatalf("entry %d at = %q, want the original %q", i, entry.At, timestamps[i])
		}
	}
}

func TestListConsistentWhileTransitionsCommit(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// INC-1 and INC-2 share a severity and advance through the flow; INC-3
	// stays in 受理 so the 受理 filter never goes empty.
	for _, item := range []struct {
		id       string
		severity string
	}{
		{"INC-1", "high"},
		{"INC-2", "high"},
		{"INC-3", "low"},
	} {
		if _, err := st.Register(item.id, item.severity, ownerFlow[0], []string{"a"}); err != nil {
			t.Fatalf("register %s: %v", item.id, err)
		}
	}

	filters := []struct {
		severity string
		stage    string
	}{
		{"", ""},
		{"high", ""},
		{"", "受理"},
		{"high", "受理"},
		{"high", "遏制"},
		{"low", "受理"},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, filter := range filters {
					incidents, err := st.List(filter.severity, filter.stage)
					if err != nil {
						t.Errorf("list %q/%q: %v", filter.severity, filter.stage, err)
						return
					}
					for _, incident := range incidents {
						// Every member matches the filter in the state its
						// own body and history came from, and the combination
						// of filters is an intersection.
						if filter.severity != "" && incident.Severity != filter.severity {
							t.Errorf("severity filter %q returned %+v", filter.severity, incident)
						}
						if filter.stage != "" && incident.Stage != filter.stage {
							t.Errorf("stage filter %q returned %+v", filter.stage, incident)
						}
						checkConsistent(t, incident)
					}
				}
			}
		}()
	}

	for _, id := range []string{"INC-1", "INC-2"} {
		for i := 1; i < len(stageFlow); i++ {
			if _, err := st.Transition(id, stageFlow[i], ownerFlow[i]); err != nil {
				t.Fatalf("transition %s to %s: %v", id, stageFlow[i], err)
			}
		}
	}
	close(stop)
	wg.Wait()

	// With no writes in flight, each filter reflects the final state.
	final, err := st.List("high", "关闭")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(final) != 2 || final[0].ID != "INC-1" || final[1].ID != "INC-2" {
		t.Fatalf("final high/关闭 list = %+v", final)
	}
	for _, incident := range final {
		checkConsistent(t, incident)
	}
	accepted, err := st.List("", "受理")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(accepted) != 1 || accepted[0].ID != "INC-3" {
		t.Fatalf("final 受理 list = %+v", accepted)
	}
	checkConsistent(t, accepted[0])
}
