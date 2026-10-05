package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
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

// inconsistent describes how an incident mixes committed states, or returns
// "" when it is internally consistent: the history must walk the stage order
// from 受理 and the body's stage and owner must match the last history entry.
func inconsistent(incident Incident) string {
	if len(incident.Timeline) == 0 || len(incident.Timeline) > len(stageOrder) {
		return fmt.Sprintf("timeline length %d: %+v", len(incident.Timeline), incident)
	}
	for i, entry := range incident.Timeline {
		if entry.Stage != stageOrder[i] {
			return fmt.Sprintf("history entry %d is %q, want %q: %+v", i, entry.Stage, stageOrder[i], incident)
		}
	}
	last := incident.Timeline[len(incident.Timeline)-1]
	if incident.Stage != last.Stage || incident.Owner != last.Owner {
		return fmt.Sprintf("body stage/owner %q/%q but last history entry is %+v",
			incident.Stage, incident.Owner, last)
	}
	return ""
}

func TestGetReadsSingleCommittedState(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	registered, err := st.Register("INC-1", "high", "alice", []string{"a"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Readers race a walk through every stage; each read must show one
	// committed state, never an old body with a new history or vice versa.
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				incident, err := st.Get("INC-1")
				if err != nil {
					t.Errorf("get: %v", err)
					return
				}
				if msg := inconsistent(incident); msg != "" {
					t.Errorf("mixed committed states: %s", msg)
					return
				}
			}
		}()
	}

	owners := []string{"bob", "carol", "dave", "erin"}
	for i, stage := range stageOrder[1:] {
		if _, err := st.Transition("INC-1", stage, owners[i]); err != nil {
			t.Fatalf("transition to %s: %v", stage, err)
		}
	}
	close(done)
	wg.Wait()

	// A read after the transitions returned shows the final state with the
	// complete, unmodified history.
	got, err := st.Get("INC-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Stage != "关闭" || got.Owner != "erin" || len(got.Timeline) != 5 {
		t.Fatalf("final incident = %+v, want 关闭/erin with five entries", got)
	}
	for i, entry := range got.Timeline {
		if entry.Stage != stageOrder[i] {
			t.Fatalf("history entry %d = %q, want %q", i, entry.Stage, stageOrder[i])
		}
	}
	if got.Timeline[0] != registered.Timeline[0] {
		t.Fatalf("initial history entry changed: %+v vs %+v", got.Timeline[0], registered.Timeline[0])
	}
}

func TestListReadsSingleCommittedState(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	for _, item := range []struct{ id, severity, owner string }{
		{"INC-1", "high", "alice"},
		{"INC-2", "high", "bob"},
		{"INC-3", "low", "carol"},
	} {
		if _, err := st.Register(item.id, item.severity, item.owner, []string{"a"}); err != nil {
			t.Fatalf("register %s: %v", item.id, err)
		}
	}

	// Filtered and unfiltered lists race transitions: every item must be
	// internally consistent, satisfy the filter, and keep id byte order.
	filters := []struct{ severity, stage string }{
		{"", ""},
		{"", "受理"},
		{"high", "受理"},
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for _, filter := range filters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				incidents, err := st.List(filter.severity, filter.stage)
				if err != nil {
					t.Errorf("list %q/%q: %v", filter.severity, filter.stage, err)
					return
				}
				for i, incident := range incidents {
					if msg := inconsistent(incident); msg != "" {
						t.Errorf("list %q/%q: %s", filter.severity, filter.stage, msg)
						return
					}
					if filter.severity != "" && incident.Severity != filter.severity {
						t.Errorf("list %q/%q returned severity %q: %+v",
							filter.severity, filter.stage, incident.Severity, incident)
						return
					}
					if filter.stage != "" && incident.Stage != filter.stage {
						t.Errorf("list %q/%q returned stage %q: %+v",
							filter.severity, filter.stage, incident.Stage, incident)
						return
					}
					if i > 0 && incidents[i-1].ID >= incident.ID {
						t.Errorf("list %q/%q ids out of order: %+v",
							filter.severity, filter.stage, incidents)
						return
					}
				}
			}
		}()
	}

	for _, id := range []string{"INC-1", "INC-2"} {
		if _, err := st.Transition(id, "遏制", "owner-"+id); err != nil {
			t.Fatalf("transition %s: %v", id, err)
		}
	}
	close(done)
	wg.Wait()

	// Lists issued after the transitions returned reflect the new stages.
	accepted, err := st.List("", "受理")
	if err != nil {
		t.Fatalf("list 受理: %v", err)
	}
	if len(accepted) != 1 || accepted[0].ID != "INC-3" {
		t.Fatalf("受理 filter = %+v, want only INC-3", accepted)
	}

	contained, err := st.List("high", "遏制")
	if err != nil {
		t.Fatalf("list high/遏制: %v", err)
	}
	if len(contained) != 2 || contained[0].ID != "INC-1" || contained[1].ID != "INC-2" {
		t.Fatalf("high/遏制 filter = %+v, want INC-1 and INC-2", contained)
	}
	for _, incident := range contained {
		if len(incident.Timeline) != 2 || incident.Timeline[1].Stage != "遏制" ||
			incident.Timeline[1].Owner != incident.Owner {
			t.Fatalf("contained incident = %+v, want two entries ending at its stage/owner", incident)
		}
	}
}
