package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xjeey8iust/sen-incident-response-flow/internal/store"
)

func newTestRouter(t *testing.T) (*store.Store, http.Handler) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, NewRouter(st)
}

func serve(router http.Handler, method, target, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, reader)
	router.ServeHTTP(recorder, request)
	return recorder
}

func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, recorder.Body.String())
	}
	if payload.Error.Message == "" {
		t.Fatalf("error message is empty: %s", recorder.Body.String())
	}
	return payload.Error.Code
}

func TestHealthzReportsOK(t *testing.T) {
	_, router := newTestRouter(t)

	recorder := serve(router, http.MethodGet, "/healthz", "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Body.String(); got != `{"database":"ok","status":"ok"}` {
		t.Fatalf("body = %s", got)
	}
}

func TestUnknownRouteUsesPublishedErrorShape(t *testing.T) {
	_, router := newTestRouter(t)

	recorder := serve(router, http.MethodGet, "/missing", "")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if code := errorCode(t, recorder); code != "route_not_found" {
		t.Fatalf("code = %s, want route_not_found", code)
	}
}

const validBody = `{"id":"INC-1","severity":"high","assets":["db-01","db-02"],"owner":"alice"}`

func TestCreateIncidentReturnsCreatedRecord(t *testing.T) {
	_, router := newTestRouter(t)

	before := time.Now().UTC()
	recorder := serve(router, http.MethodPost, "/incidents", validBody)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (%s)", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var incident store.Incident
	if err := json.Unmarshal(recorder.Body.Bytes(), &incident); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if incident.ID != "INC-1" || incident.Severity != "high" || incident.Owner != "alice" {
		t.Fatalf("incident = %+v", incident)
	}
	if incident.Stage != "受理" {
		t.Fatalf("stage = %q, want 受理", incident.Stage)
	}
	if len(incident.Assets) != 2 || incident.Assets[0] != "db-01" || incident.Assets[1] != "db-02" {
		t.Fatalf("assets = %v", incident.Assets)
	}
	if len(incident.Timeline) != 1 {
		t.Fatalf("timeline = %+v", incident.Timeline)
	}
	entry := incident.Timeline[0]
	if entry.Stage != "受理" || entry.Owner != "alice" {
		t.Fatalf("timeline entry = %+v", entry)
	}
	at, err := time.Parse(time.RFC3339, entry.At)
	if err != nil {
		t.Fatalf("at is not RFC3339: %q", entry.At)
	}
	if at.Before(before.Add(-time.Second)) || at.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("at = %s is not a service-generated current time", entry.At)
	}
}

func TestCreateIncidentRejectsInvalidBodies(t *testing.T) {
	cases := map[string]string{
		"not an object":    `[{"id":"INC-1"}]`,
		"trailing data":    `{"id":"INC-1","severity":"high","assets":["a"],"owner":"o"} {"x":1}`,
		"unknown field":    `{"id":"INC-1","severity":"high","assets":["a"],"owner":"o","note":"x"}`,
		"missing id":       `{"severity":"high","assets":["a"],"owner":"o"}`,
		"null id":          `{"id":null,"severity":"high","assets":["a"],"owner":"o"}`,
		"blank id":         `{"id":"   ","severity":"high","assets":["a"],"owner":"o"}`,
		"id wrong type":    `{"id":7,"severity":"high","assets":["a"],"owner":"o"}`,
		"missing severity": `{"id":"INC-1","assets":["a"],"owner":"o"}`,
		"null severity":    `{"id":"INC-1","severity":null,"assets":["a"],"owner":"o"}`,
		"unknown severity": `{"id":"INC-1","severity":"urgent","assets":["a"],"owner":"o"}`,
		"missing assets":   `{"id":"INC-1","severity":"high","owner":"o"}`,
		"null assets":      `{"id":"INC-1","severity":"high","assets":null,"owner":"o"}`,
		"empty assets":     `{"id":"INC-1","severity":"high","assets":[],"owner":"o"}`,
		"blank asset":      `{"id":"INC-1","severity":"high","assets":["  "],"owner":"o"}`,
		"asset wrong type": `{"id":"INC-1","severity":"high","assets":[1],"owner":"o"}`,
		"assets not array": `{"id":"INC-1","severity":"high","assets":"db","owner":"o"}`,
		"missing owner":    `{"id":"INC-1","severity":"high","assets":["a"]}`,
		"null owner":       `{"id":"INC-1","severity":"high","assets":["a"],"owner":null}`,
		"blank owner":      `{"id":"INC-1","severity":"high","assets":["a"],"owner":" "}`,
		"malformed json":   `{"id":`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, router := newTestRouter(t)
			recorder := serve(router, http.MethodPost, "/incidents", body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (%s)", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			if code := errorCode(t, recorder); code != "invalid_request" {
				t.Fatalf("code = %s, want invalid_request", code)
			}
		})
	}
}

func TestCreateIncidentFailureWritesNothing(t *testing.T) {
	_, router := newTestRouter(t)

	serve(router, http.MethodPost, "/incidents", `{"id":"INC-9","severity":"urgent","assets":["a"],"owner":"o"}`)

	recorder := serve(router, http.MethodGet, "/incidents?id=INC-9", "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestCreateIncidentReplayIsIdempotent(t *testing.T) {
	_, router := newTestRouter(t)

	first := serve(router, http.MethodPost, "/incidents", validBody)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d", first.Code)
	}
	time.Sleep(10 * time.Millisecond)
	second := serve(router, http.MethodPost, "/incidents", validBody)

	if second.Code != http.StatusCreated {
		t.Fatalf("replay status = %d, want %d", second.Code, http.StatusCreated)
	}
	if second.Body.String() != first.Body.String() {
		t.Fatalf("replay body = %s, want identical to %s", second.Body.String(), first.Body.String())
	}
}

func TestCreateIncidentConflict(t *testing.T) {
	_, router := newTestRouter(t)

	serve(router, http.MethodPost, "/incidents", validBody)
	recorder := serve(router, http.MethodPost, "/incidents",
		`{"id":"INC-1","severity":"high","assets":["db-02","db-01"],"owner":"alice"}`)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	if code := errorCode(t, recorder); code != "incident_conflict" {
		t.Fatalf("code = %s, want incident_conflict", code)
	}
}

func TestCreateIncidentValidatesBeforeConflictCheck(t *testing.T) {
	_, router := newTestRouter(t)

	serve(router, http.MethodPost, "/incidents", validBody)
	recorder := serve(router, http.MethodPost, "/incidents",
		`{"id":"INC-1","severity":"urgent","assets":["db-01","db-02"],"owner":"alice"}`)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if code := errorCode(t, recorder); code != "invalid_request" {
		t.Fatalf("code = %s, want invalid_request", code)
	}
}

func seedIncidents(t *testing.T, router http.Handler) {
	t.Helper()
	bodies := []string{
		`{"id":"INC-2","severity":"low","assets":["a"],"owner":"o1"}`,
		`{"id":"INC-10","severity":"high","assets":["b"],"owner":"o2"}`,
		`{"id":"INC-1","severity":"high","assets":["c"],"owner":"o3"}`,
	}
	for _, body := range bodies {
		if rec := serve(router, http.MethodPost, "/incidents", body); rec.Code != http.StatusCreated {
			t.Fatalf("seed %s: status %d", body, rec.Code)
		}
	}
}

func TestListIncidentsDefaultsToByteOrder(t *testing.T) {
	_, router := newTestRouter(t)
	seedIncidents(t, router)

	recorder := serve(router, http.MethodGet, "/incidents", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var incidents []store.Incident
	if err := json.Unmarshal(recorder.Body.Bytes(), &incidents); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := []string{incidents[0].ID, incidents[1].ID, incidents[2].ID}
	want := []string{"INC-1", "INC-10", "INC-2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

func TestListIncidentsFilters(t *testing.T) {
	_, router := newTestRouter(t)
	seedIncidents(t, router)

	recorder := serve(router, http.MethodGet, "/incidents?severity=high", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var incidents []store.Incident
	if err := json.Unmarshal(recorder.Body.Bytes(), &incidents); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(incidents) != 2 || incidents[0].ID != "INC-1" || incidents[1].ID != "INC-10" {
		t.Fatalf("severity filter = %+v", incidents)
	}

	recorder = serve(router, http.MethodGet, "/incidents?severity=low&stage=受理", "")
	var combo []store.Incident
	if err := json.Unmarshal(recorder.Body.Bytes(), &combo); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(combo) != 1 || combo[0].ID != "INC-2" {
		t.Fatalf("combo filter = %+v", combo)
	}

	recorder = serve(router, http.MethodGet, "/incidents?severity=critical", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Body.String(); got != "[]" {
		t.Fatalf("empty result = %s, want []", got)
	}
}

func TestGetIncidentByID(t *testing.T) {
	_, router := newTestRouter(t)
	seedIncidents(t, router)

	recorder := serve(router, http.MethodGet, "/incidents?id=INC-2", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var incident store.Incident
	if err := json.Unmarshal(recorder.Body.Bytes(), &incident); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if incident.ID != "INC-2" || incident.Severity != "low" {
		t.Fatalf("incident = %+v", incident)
	}

	recorder = serve(router, http.MethodGet, "/incidents?id=INC-99", "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if code := errorCode(t, recorder); code != "incident_not_found" {
		t.Fatalf("code = %s, want incident_not_found", code)
	}
}

func TestListIncidentsRejectsInvalidQueries(t *testing.T) {
	cases := map[string]string{
		"empty id":         "/incidents?id=",
		"empty severity":   "/incidents?severity=",
		"unknown severity": "/incidents?severity=urgent",
		"unknown stage":    "/incidents?stage=未知",
		"duplicate param":  "/incidents?severity=low&severity=high",
		"unknown param":    "/incidents?owner=alice",
		"id with severity": "/incidents?id=INC-1&severity=low",
		"id with stage":    "/incidents?id=INC-1&stage=受理",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			_, router := newTestRouter(t)
			recorder := serve(router, http.MethodGet, target, "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (%s)", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			if code := errorCode(t, recorder); code != "invalid_query" {
				t.Fatalf("code = %s, want invalid_query", code)
			}
		})
	}
}

func TestStorageUnavailableMapsTo503(t *testing.T) {
	st, router := newTestRouter(t)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, target := range []struct{ method, path, body string }{
		{http.MethodGet, "/healthz", ""},
		{http.MethodPost, "/incidents", validBody},
		{http.MethodGet, "/incidents", ""},
		{http.MethodGet, "/incidents?id=INC-1", ""},
	} {
		recorder := serve(router, target.method, target.path, target.body)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: status = %d, want %d", target.method, target.path, recorder.Code, http.StatusServiceUnavailable)
		}
		if code := errorCode(t, recorder); code != "storage_unavailable" {
			t.Fatalf("%s %s: code = %s, want storage_unavailable", target.method, target.path, code)
		}
	}
}
