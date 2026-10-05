package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xjeey8iust/sen-incident-response-flow/internal/store"
)

func newTestRouter(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	server := httptest.NewServer(NewRouter(st))
	t.Cleanup(server.Close)
	return server, st
}

func doRequest(t *testing.T, method, url, body string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer response.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response.StatusCode, decoded
}

func errorCode(t *testing.T, body map[string]any) string {
	t.Helper()
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no top-level error object: %v", body)
	}
	if _, ok := errObj["message"].(string); !ok {
		t.Fatalf("error object has no string message: %v", errObj)
	}
	code, ok := errObj["code"].(string)
	if !ok {
		t.Fatalf("error object has no string code: %v", errObj)
	}
	return code
}

func TestHealthzReportsOK(t *testing.T) {
	server, _ := newTestRouter(t)
	status, body := doRequest(t, http.MethodGet, server.URL+"/healthz", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if body["status"] != "ok" || body["database"] != "ok" {
		t.Fatalf("body = %v", body)
	}
}

func TestUnknownRouteUsesPublishedErrorShape(t *testing.T) {
	server, _ := newTestRouter(t)
	status, body := doRequest(t, http.MethodGet, server.URL+"/missing", "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", status, http.StatusNotFound)
	}
	if code := errorCode(t, body); code != "route_not_found" {
		t.Fatalf("code = %q, want route_not_found", code)
	}
}

const validBody = `{"id":"INC-1","severity":"high","assets":["db-1","web-2"],"owner":"alice"}`

func TestCreateIncidentReturnsCreated(t *testing.T) {
	server, _ := newTestRouter(t)
	status, body := doRequest(t, http.MethodPost, server.URL+"/incidents", validBody)
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body %v)", status, http.StatusCreated, body)
	}
	if body["id"] != "INC-1" || body["severity"] != "high" || body["owner"] != "alice" {
		t.Fatalf("unexpected incident fields: %v", body)
	}
	if body["stage"] != "受理" {
		t.Fatalf("stage = %v, want 受理", body["stage"])
	}
	assets, ok := body["assets"].([]any)
	if !ok || len(assets) != 2 || assets[0] != "db-1" || assets[1] != "web-2" {
		t.Fatalf("assets = %v, want [db-1 web-2]", body["assets"])
	}
	timeline, ok := body["timeline"].([]any)
	if !ok || len(timeline) != 1 {
		t.Fatalf("timeline = %v, want one entry", body["timeline"])
	}
	entry := timeline[0].(map[string]any)
	if entry["stage"] != "受理" || entry["owner"] != "alice" {
		t.Fatalf("timeline entry = %v", entry)
	}
	at, err := time.Parse(time.RFC3339, entry["at"].(string))
	if err != nil || at.Location() != time.UTC {
		t.Fatalf("at = %v, want UTC RFC3339 (%v)", entry["at"], err)
	}
}

func TestCreateIncidentRejectsInvalidBodies(t *testing.T) {
	server, _ := newTestRouter(t)
	cases := map[string]string{
		"empty body":       "",
		"not json":         `nope`,
		"json array":       `[]`,
		"json scalar":      `42`,
		"trailing object":  validBody + ` {}`,
		"unknown field":    `{"id":"INC-1","severity":"high","assets":["a"],"owner":"x","extra":1}`,
		"missing id":       `{"severity":"high","assets":["a"],"owner":"x"}`,
		"null id":          `{"id":null,"severity":"high","assets":["a"],"owner":"x"}`,
		"blank id":         `{"id":"   ","severity":"high","assets":["a"],"owner":"x"}`,
		"id wrong type":    `{"id":7,"severity":"high","assets":["a"],"owner":"x"}`,
		"unknown severity": `{"id":"INC-1","severity":"urgent","assets":["a"],"owner":"x"}`,
		"severity null":    `{"id":"INC-1","severity":null,"assets":["a"],"owner":"x"}`,
		"assets missing":   `{"id":"INC-1","severity":"high","owner":"x"}`,
		"assets empty":     `{"id":"INC-1","severity":"high","assets":[],"owner":"x"}`,
		"asset blank":      `{"id":"INC-1","severity":"high","assets":["a","  "],"owner":"x"}`,
		"asset wrong type": `{"id":"INC-1","severity":"high","assets":[1],"owner":"x"}`,
		"owner blank":      `{"id":"INC-1","severity":"high","assets":["a"],"owner":" "}`,
		"owner null":       `{"id":"INC-1","severity":"high","assets":["a"],"owner":null}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status, decoded := doRequest(t, http.MethodPost, server.URL+"/incidents", body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body %v)", status, http.StatusBadRequest, decoded)
			}
			if code := errorCode(t, decoded); code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", code)
			}
		})
	}

	// Nothing may have been written by the rejected requests.
	status, items := listIncidents(t, server.URL+"/incidents")
	if status != http.StatusOK {
		t.Fatalf("list status = %d", status)
	}
	if len(items) != 0 {
		t.Fatalf("rejected requests wrote incidents: %v", items)
	}
}

// escapeName returns name with every character written as a JSON unicode
// escape, so tests can send field names that only decode to the whitelisted
// ones inside the service's JSON parser.
func escapeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

func TestCreateIncidentAcceptsEscapedFieldNames(t *testing.T) {
	server, _ := newTestRouter(t)

	// id decodes to "id" and is accepted as the plain name.
	escaped := `{"` + escapeName("id") + `":"INC-1","severity":"high","assets":["db-1"],"owner":"alice"}`
	status, body := doRequest(t, http.MethodPost, server.URL+"/incidents", escaped)
	if status != http.StatusCreated {
		t.Fatalf("escaped id: status = %d, want 201 (body %v)", status, body)
	}
	if body["id"] != "INC-1" {
		t.Fatalf("escaped id: id = %v", body["id"])
	}

	// Every field name may be escaped; field order and legal whitespace
	// around the object do not matter either.
	reordered := "  {\n\t\"" + escapeName("owner") + `":"bob", "` +
		escapeName("assets") + `":["web-1","db-2"],"` +
		escapeName("severity") + `":"low","` +
		escapeName("id") + `":"INC-2"}` + "\n"
	status, body = doRequest(t, http.MethodPost, server.URL+"/incidents", reordered)
	if status != http.StatusCreated {
		t.Fatalf("escaped names: status = %d, want 201 (body %v)", status, body)
	}
	assets := body["assets"].([]any)
	if body["id"] != "INC-2" || body["owner"] != "bob" || len(assets) != 2 || assets[0] != "web-1" {
		t.Fatalf("escaped names: body = %v", body)
	}
}

func TestCreateIncidentRejectsCaseVariants(t *testing.T) {
	server, _ := newTestRouter(t)
	cases := map[string]string{
		"id upper":       `{"ID":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		"id mixed":       `{"Id":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		"severity upper": `{"id":"INC-1","SEVERITY":"high","assets":["a"],"owner":"x"}`,
		"severity mixed": `{"id":"INC-1","Severity":"high","assets":["a"],"owner":"x"}`,
		"assets upper":   `{"id":"INC-1","severity":"high","ASSETS":["a"],"owner":"x"}`,
		"assets mixed":   `{"id":"INC-1","severity":"high","Assets":["a"],"owner":"x"}`,
		"owner upper":    `{"id":"INC-1","severity":"high","assets":["a"],"OWNER":"x"}`,
		"owner mixed":    `{"id":"INC-1","severity":"high","assets":["a"],"Owner":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status, decoded := doRequest(t, http.MethodPost, server.URL+"/incidents", body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body %v)", status, http.StatusBadRequest, decoded)
			}
			if code := errorCode(t, decoded); code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", code)
			}
		})
	}

	status, items := listIncidents(t, server.URL+"/incidents")
	if status != http.StatusOK || len(items) != 0 {
		t.Fatalf("rejected case variants wrote incidents: %v", items)
	}
}

func TestCreateIncidentRejectsDuplicateFields(t *testing.T) {
	server, _ := newTestRouter(t)
	cases := map[string]string{
		"id same value":          `{"id":"INC-1","id":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		"id different value":     `{"id":"INC-1","id":"INC-2","severity":"high","assets":["a"],"owner":"x"}`,
		"id null then valid":     `{"id":null,"id":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		"id valid then null":     `{"id":"INC-1","id":null,"severity":"high","assets":["a"],"owner":"x"}`,
		"id invalid then valid":  `{"id":7,"id":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		"id valid then invalid":  `{"id":"INC-1","id":7,"severity":"high","assets":["a"],"owner":"x"}`,
		"id escaped duplicate":   `{"id":"INC-1","` + escapeName("id") + `":"INC-2","severity":"high","assets":["a"],"owner":"x"}`,
		"id case variant plus":   `{"ID":"INC-9","id":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		"severity duplicate":     `{"id":"INC-1","severity":"low","severity":"high","assets":["a"],"owner":"x"}`,
		"severity null then set": `{"id":"INC-1","severity":null,"severity":"high","assets":["a"],"owner":"x"}`,
		"assets duplicate":       `{"id":"INC-1","severity":"high","assets":["a"],"assets":["b"],"owner":"x"}`,
		"assets null then set":   `{"id":"INC-1","severity":"high","assets":null,"assets":["a"],"owner":"x"}`,
		"owner duplicate":        `{"id":"INC-1","severity":"high","assets":["a"],"owner":"x","owner":"y"}`,
		"owner null then set":    `{"id":"INC-1","severity":"high","assets":["a"],"owner":null,"owner":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status, decoded := doRequest(t, http.MethodPost, server.URL+"/incidents", body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body %v)", status, http.StatusBadRequest, decoded)
			}
			if len(decoded) != 1 {
				t.Fatalf("error response must hold only the top-level error object: %v", decoded)
			}
			if code := errorCode(t, decoded); code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", code)
			}
		})
	}

	status, items := listIncidents(t, server.URL+"/incidents")
	if status != http.StatusOK || len(items) != 0 {
		t.Fatalf("rejected duplicates wrote incidents: %v", items)
	}
}

func TestCreateIncidentKeepsRepeatedValues(t *testing.T) {
	server, _ := newTestRouter(t)
	// The same string in several fields and repeated asset names are values,
	// not duplicate fields, and are preserved as-is.
	body := `{"id":"alice","severity":"high","assets":["alice","alice"],"owner":"alice"}`
	status, created := doRequest(t, http.MethodPost, server.URL+"/incidents", body)
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %v)", status, created)
	}
	assets := created["assets"].([]any)
	if len(assets) != 2 || assets[0] != "alice" || assets[1] != "alice" {
		t.Fatalf("assets = %v, want [alice alice]", created["assets"])
	}
	if created["owner"] != "alice" || created["id"] != "alice" {
		t.Fatalf("body = %v", created)
	}
}

func TestCreateInvalidBodyLeavesExistingIncidentUntouched(t *testing.T) {
	server, _ := newTestRouter(t)
	status, first := doRequest(t, http.MethodPost, server.URL+"/incidents", validBody)
	if status != http.StatusCreated {
		t.Fatalf("first status = %d", status)
	}

	// Existing id plus an invalid body: validation wins over the conflict
	// check and nothing is written.
	invalid := []string{
		`{"id":"INC-1","ID":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		`{"id":"INC-1","id":"INC-1","severity":"high","assets":["a"],"owner":"x"}`,
		`{"id":"INC-1","severity":"high","assets":["a"],"owner":"x","owner":"y"}`,
		`{"id":"INC-1","severity":"high","assets":["a"],"owner":"x","extra":1}`,
	}
	for _, body := range invalid {
		status, decoded := doRequest(t, http.MethodPost, server.URL+"/incidents", body)
		if status != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", body, status)
		}
		if code := errorCode(t, decoded); code != "invalid_request" {
			t.Fatalf("%s: code = %q, want invalid_request", body, code)
		}
	}

	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("fetch status = %d, want 200", status)
	}
	firstTimeline := first["timeline"].([]any)
	fetchedTimeline := fetched["timeline"].([]any)
	if fetched["severity"] != first["severity"] || fetched["owner"] != first["owner"] ||
		len(fetchedTimeline) != 1 ||
		fetchedTimeline[0].(map[string]any)["at"] != firstTimeline[0].(map[string]any)["at"] {
		t.Fatalf("rejected requests changed the incident: %v vs %v", fetched, first)
	}

	_, items := listIncidents(t, server.URL+"/incidents")
	if len(items) != 1 {
		t.Fatalf("rejected requests created incidents: %v", items)
	}
}

func TestCreateValidationPrecedesStorage(t *testing.T) {
	server, st := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")
	st.Close()

	// Invalid bodies are rejected even while the store is down.
	invalid := []string{
		`{"ID":"INC-2","severity":"high","assets":["a"],"owner":"x"}`,
		`{"id":"INC-2","id":"INC-2","severity":"high","assets":["a"],"owner":"x"}`,
		`{"id":"INC-2","severity":"urgent","assets":["a"],"owner":"x"}`,
	}
	for _, body := range invalid {
		status, decoded := doRequest(t, http.MethodPost, server.URL+"/incidents", body)
		if status != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", body, status)
		}
		if code := errorCode(t, decoded); code != "invalid_request" {
			t.Fatalf("%s: code = %q, want invalid_request", body, code)
		}
	}

	// A valid body still surfaces the storage failure.
	valid := `{"id":"INC-2","severity":"high","assets":["a"],"owner":"x"}`
	status, decoded := doRequest(t, http.MethodPost, server.URL+"/incidents", valid)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if code := errorCode(t, decoded); code != "storage_unavailable" {
		t.Fatalf("code = %q, want storage_unavailable", code)
	}
}

func TestCreateDuplicateReturnsOriginal(t *testing.T) {
	server, _ := newTestRouter(t)
	status, first := doRequest(t, http.MethodPost, server.URL+"/incidents", validBody)
	if status != http.StatusCreated {
		t.Fatalf("first status = %d", status)
	}
	time.Sleep(time.Second)
	status, again := doRequest(t, http.MethodPost, server.URL+"/incidents", validBody)
	if status != http.StatusCreated {
		t.Fatalf("duplicate status = %d, want 201", status)
	}
	firstTimeline := first["timeline"].([]any)
	againTimeline := again["timeline"].([]any)
	if len(againTimeline) != 1 {
		t.Fatalf("duplicate appended history: %v", againTimeline)
	}
	if firstTimeline[0].(map[string]any)["at"] != againTimeline[0].(map[string]any)["at"] {
		t.Fatalf("duplicate rewrote timestamp: %v vs %v", firstTimeline, againTimeline)
	}
}

func TestCreateConflictReturns409(t *testing.T) {
	server, _ := newTestRouter(t)
	if status, _ := doRequest(t, http.MethodPost, server.URL+"/incidents", validBody); status != http.StatusCreated {
		t.Fatalf("first status = %d", status)
	}
	conflicting := `{"id":"INC-1","severity":"low","assets":["db-1","web-2"],"owner":"alice"}`
	status, body := doRequest(t, http.MethodPost, server.URL+"/incidents", conflicting)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409", status)
	}
	if code := errorCode(t, body); code != "incident_conflict" {
		t.Fatalf("code = %q, want incident_conflict", code)
	}

	// Asset order is significant.
	reordered := `{"id":"INC-1","severity":"high","assets":["web-2","db-1"],"owner":"alice"}`
	if status, _ := doRequest(t, http.MethodPost, server.URL+"/incidents", reordered); status != http.StatusConflict {
		t.Fatalf("reordered assets status = %d, want 409", status)
	}
}

func TestCreateValidatesBeforeConflictCheck(t *testing.T) {
	server, _ := newTestRouter(t)
	if status, _ := doRequest(t, http.MethodPost, server.URL+"/incidents", validBody); status != http.StatusCreated {
		t.Fatalf("first status = %d", status)
	}
	// Existing id but invalid body: validation wins over the conflict check.
	invalid := `{"id":"INC-1","severity":"urgent","assets":["a"],"owner":"x"}`
	status, body := doRequest(t, http.MethodPost, server.URL+"/incidents", invalid)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if code := errorCode(t, body); code != "invalid_request" {
		t.Fatalf("code = %q, want invalid_request", code)
	}
}

func registerIncident(t *testing.T, baseURL, id, severity, owner string) {
	t.Helper()
	body := `{"id":"` + id + `","severity":"` + severity + `","assets":["a"],"owner":"` + owner + `"}`
	if status, decoded := doRequest(t, http.MethodPost, baseURL+"/incidents", body); status != http.StatusCreated {
		t.Fatalf("register %s: status %d (%v)", id, status, decoded)
	}
}

func listIncidents(t *testing.T, url string) (int, []any) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer response.Body.Close()
	var decoded []any
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return response.StatusCode, decoded
}

func TestListIncidentsOrdersAndFilters(t *testing.T) {
	server, _ := newTestRouter(t)

	// Empty list is an array, not null or an error object.
	status, items := listIncidents(t, server.URL+"/incidents")
	if status != http.StatusOK || len(items) != 0 {
		t.Fatalf("empty list: status %d items %v", status, items)
	}

	registerIncident(t, server.URL, "INC-2", "low", "bob")
	registerIncident(t, server.URL, "INC-10", "high", "carol")
	registerIncident(t, server.URL, "INC-1", "high", "alice")

	_, items = listIncidents(t, server.URL+"/incidents")
	ids := make([]any, len(items))
	for i, item := range items {
		ids[i] = item.(map[string]any)["id"]
	}
	want := []any{"INC-1", "INC-10", "INC-2"}
	if len(ids) != 3 || ids[0] != want[0] || ids[1] != want[1] || ids[2] != want[2] {
		t.Fatalf("ids = %v, want %v", ids, want)
	}

	_, items = listIncidents(t, server.URL+"/incidents?severity=high")
	if len(items) != 2 {
		t.Fatalf("severity filter matched %d, want 2", len(items))
	}

	_, items = listIncidents(t, server.URL+"/incidents?stage="+url.QueryEscape("受理"))
	if len(items) != 3 {
		t.Fatalf("stage filter matched %d, want 3", len(items))
	}

	_, items = listIncidents(t, server.URL+"/incidents?severity=low&stage="+url.QueryEscape("受理"))
	if len(items) != 1 || items[0].(map[string]any)["id"] != "INC-2" {
		t.Fatalf("combined filter = %v", items)
	}

	_, items = listIncidents(t, server.URL+"/incidents?severity=critical")
	if len(items) != 0 {
		t.Fatalf("no-match filter = %v, want empty", items)
	}
}

func TestGetIncidentByID(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")

	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body["id"] != "INC-1" || body["stage"] != "受理" {
		t.Fatalf("body = %v", body)
	}

	status, body = doRequest(t, http.MethodGet, server.URL+"/incidents?id=nope", "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	if code := errorCode(t, body); code != "incident_not_found" {
		t.Fatalf("code = %q, want incident_not_found", code)
	}
}

func TestQueryRejectsInvalidParameters(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")

	cases := []string{
		"?id=INC-1&severity=medium",   // id must be used alone
		"?id=",                        // empty id
		"?severity=",                  // empty severity
		"?severity=urgent",            // unknown severity
		"?stage=unknown",              // unknown stage
		"?severity=low&severity=high", // repeated parameter
		"?foo=bar",                    // unknown parameter
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			status, body := doRequest(t, http.MethodGet, server.URL+"/incidents"+query, "")
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
			if code := errorCode(t, body); code != "invalid_query" {
				t.Fatalf("code = %q, want invalid_query", code)
			}
		})
	}
}

func TestQueryRejectsMalformedQueryString(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")

	cases := []string{
		"?severity=%ZZ",                 // broken escape in value
		"?%ZZ=high",                     // broken escape in name
		"?severity=%2",                  // truncated escape
		"?severity=%",                   // lone percent
		"?id=INC-1&stage=%ZZ",           // valid id must not rescue a bad segment
		"?stage=%ZZ&id=INC-1",           // segment order is irrelevant
		"?severity=medium&stage=%ZZ",    // valid filter plus bad segment
		"?foo=%ZZ",                      // bad escape on an unknown parameter
		"?severity=%ZZ&severity=medium", // bad escape on a repeated parameter
		"?id=INC-1;severity=medium",     // unescaped semicolon between segments
		"?severity=medium;",             // trailing semicolon
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			status, body := doRequest(t, http.MethodGet, server.URL+"/incidents"+query, "")
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %v)", status, body)
			}
			if len(body) != 1 {
				t.Fatalf("error response must hold only the top-level error object: %v", body)
			}
			if code := errorCode(t, body); code != "invalid_query" {
				t.Fatalf("code = %q, want invalid_query", code)
			}
		})
	}

	// The rejected requests must not have touched the stored incident.
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	timeline := body["timeline"].([]any)
	if len(timeline) != 1 || body["stage"] != "受理" {
		t.Fatalf("rejected queries changed the incident: %v", body)
	}
}

func TestQueryDecodesNamesOnce(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")

	// %73everity decodes to severity and is recognized as the filter name.
	status, items := listIncidents(t, server.URL+"/incidents?%73everity=high")
	if status != http.StatusOK || len(items) != 1 {
		t.Fatalf("encoded name: status %d items %v", status, items)
	}

	// The decoded name collapses with the literal one into a repetition.
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?%73everity=high&severity=high", "")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if code := errorCode(t, body); code != "invalid_query" {
		t.Fatalf("code = %q, want invalid_query", code)
	}
}

func TestGetIncidentWithEncodedSpecialCharacters(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1;A&B+C", "low", "alice")
	registerIncident(t, server.URL, "INC 7", "low", "bob")

	// %3B, %26 and %2B match a literal semicolon, ampersand and plus in the
	// id instead of splitting the query into more parameters.
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1%3BA%26B%2BC", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %v)", status, body)
	}
	if body["id"] != "INC-1;A&B+C" {
		t.Fatalf("id = %v", body["id"])
	}

	// A plain + still decodes to a space.
	status, body = doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC+7", "")
	if status != http.StatusOK || body["id"] != "INC 7" {
		t.Fatalf("plus-as-space: status %d body %v", status, body)
	}

	// %2B is a literal plus and must not match the space-containing id.
	status, body = doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC%2B7", "")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	if code := errorCode(t, body); code != "incident_not_found" {
		t.Fatalf("code = %q, want incident_not_found", code)
	}
}

func TestQueryValidationPrecedesStorage(t *testing.T) {
	server, st := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")
	st.Close()

	// Malformed queries are rejected even while the store is down.
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?severity=%ZZ", "")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if code := errorCode(t, body); code != "invalid_query" {
		t.Fatalf("code = %q, want invalid_query", code)
	}

	// Well-formed queries still surface the storage failure.
	status, body = doRequest(t, http.MethodGet, server.URL+"/incidents?severity=medium", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if code := errorCode(t, body); code != "storage_unavailable" {
		t.Fatalf("code = %q, want storage_unavailable", code)
	}
}

func TestIncidentsPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first := httptest.NewServer(NewRouter(st))
	status, created := doRequest(t, http.MethodPost, first.URL+"/incidents", validBody)
	if status != http.StatusCreated {
		t.Fatalf("create status = %d", status)
	}
	first.Close()
	st.Close()

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	second := httptest.NewServer(NewRouter(reopened))
	defer second.Close()

	status, fetched := doRequest(t, http.MethodGet, second.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("fetch after restart: status %d", status)
	}
	createdTimeline := created["timeline"].([]any)
	fetchedTimeline := fetched["timeline"].([]any)
	if fetched["stage"] != created["stage"] ||
		fetchedTimeline[0].(map[string]any)["at"] != createdTimeline[0].(map[string]any)["at"] {
		t.Fatalf("restart changed the record: %v vs %v", fetched, created)
	}
}

func transition(t *testing.T, baseURL, id, body string) (int, map[string]any) {
	t.Helper()
	return doRequest(t, http.MethodPost, baseURL+"/incidents/"+id+"/transition", body)
}

func TestTransitionWalksThroughAllStages(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")

	stages := []string{"遏制", "清除", "恢复", "关闭"}
	owners := []string{"alice", "bob", "  carol  ", "dave"}
	for i, stage := range stages {
		body := `{"stage":"` + stage + `","owner":"` + owners[i] + `"}`
		status, incident := transition(t, server.URL, "INC-1", body)
		if status != http.StatusOK {
			t.Fatalf("to %s: status = %d, want 200 (%v)", stage, status, incident)
		}
		if incident["id"] != "INC-1" || incident["severity"] != "high" {
			t.Fatalf("identity changed: %v", incident)
		}
		assets := incident["assets"].([]any)
		if len(assets) != 1 || assets[0] != "a" {
			t.Fatalf("assets changed: %v", assets)
		}
		if incident["stage"] != stage || incident["owner"] != owners[i] {
			t.Fatalf("stage/owner = %v/%v, want %v/%v", incident["stage"], incident["owner"], stage, owners[i])
		}
		timeline := incident["timeline"].([]any)
		if len(timeline) != i+2 {
			t.Fatalf("timeline length = %d, want %d", len(timeline), i+2)
		}
		entry := timeline[len(timeline)-1].(map[string]any)
		if entry["stage"] != stage || entry["owner"] != owners[i] {
			t.Fatalf("last entry = %v", entry)
		}
		at, err := time.Parse(time.RFC3339, entry["at"].(string))
		if err != nil || at.Location() != time.UTC {
			t.Fatalf("at = %v, want UTC RFC3339 (%v)", entry["at"], err)
		}
	}

	// The flow ends at 关闭: every further move is a conflict.
	for _, stage := range []string{"关闭", "受理", "遏制"} {
		status, body := transition(t, server.URL, "INC-1", `{"stage":"`+stage+`","owner":"x"}`)
		if status != http.StatusConflict {
			t.Fatalf("from closed to %s: status = %d, want 409", stage, status)
		}
		if code := errorCode(t, body); code != "invalid_transition" {
			t.Fatalf("code = %q, want invalid_transition", code)
		}
	}
}

func TestTransitionRejectsInvalidBodies(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")

	cases := map[string]string{
		"empty body":          "",
		"not json":            `nope`,
		"json array":          `[]`,
		"json scalar":         `42`,
		"trailing object":     `{"stage":"遏制","owner":"bob"} {}`,
		"unknown field":       `{"stage":"遏制","owner":"bob","extra":1}`,
		"register field":      `{"stage":"遏制","owner":"bob","severity":"high"}`,
		"missing stage":       `{"owner":"bob"}`,
		"missing owner":       `{"stage":"遏制"}`,
		"null stage":          `{"stage":null,"owner":"bob"}`,
		"null owner":          `{"stage":"遏制","owner":null}`,
		"stage wrong type":    `{"stage":1,"owner":"bob"}`,
		"owner wrong type":    `{"stage":"遏制","owner":["bob"]}`,
		"blank owner":         `{"stage":"遏制","owner":"   "}`,
		"empty owner":         `{"stage":"遏制","owner":""}`,
		"unknown stage":       `{"stage":"unknown","owner":"bob"}`,
		"stage upper field":   `{"Stage":"遏制","owner":"bob"}`,
		"owner upper field":   `{"stage":"遏制","OWNER":"bob"}`,
		"stage duplicate":     `{"stage":"遏制","stage":"清除","owner":"bob"}`,
		"owner duplicate":     `{"stage":"遏制","owner":"bob","owner":"carol"}`,
		"owner null then set": `{"stage":"遏制","owner":null,"owner":"bob"}`,
		"escaped duplicate":   `{"stage":"遏制","owner":"bob","` + escapeName("owner") + `":"carol"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status, decoded := transition(t, server.URL, "INC-1", body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%v)", status, decoded)
			}
			if len(decoded) != 1 {
				t.Fatalf("error response must hold only the top-level error object: %v", decoded)
			}
			if code := errorCode(t, decoded); code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", code)
			}
		})
	}

	// Nothing may have been written by the rejected requests.
	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("fetch status = %d", status)
	}
	if fetched["stage"] != "受理" || fetched["owner"] != "alice" || len(fetched["timeline"].([]any)) != 1 {
		t.Fatalf("rejected requests changed the incident: %v", fetched)
	}
}

func TestTransitionAcceptsEscapedFieldNames(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "low", "alice")

	body := `{"` + escapeName("stage") + `":"遏制","` + escapeName("owner") + `":"bob"}`
	status, incident := transition(t, server.URL, "INC-1", body)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, incident)
	}
	if incident["stage"] != "遏制" || incident["owner"] != "bob" {
		t.Fatalf("incident = %v", incident)
	}
}

func TestTransitionValidatesBeforeLookup(t *testing.T) {
	server, _ := newTestRouter(t)

	// Invalid bodies are rejected before the id is ever looked up.
	invalid := []string{
		`{"stage":"unknown","owner":"bob"}`,
		`{"Stage":"遏制","owner":"bob"}`,
		`{"stage":"遏制","owner":"bob","owner":"carol"}`,
		`{"stage":"遏制"}`,
	}
	for _, body := range invalid {
		status, decoded := transition(t, server.URL, "nope", body)
		if status != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", body, status)
		}
		if code := errorCode(t, decoded); code != "invalid_request" {
			t.Fatalf("%s: code = %q, want invalid_request", body, code)
		}
	}

	// A valid body on a missing id reports the absence.
	status, decoded := transition(t, server.URL, "nope", `{"stage":"遏制","owner":"bob"}`)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	if code := errorCode(t, decoded); code != "incident_not_found" {
		t.Fatalf("code = %q, want incident_not_found", code)
	}
}

func TestTransitionConflictLeavesIncidentUntouched(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")
	if status, _ := transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"bob"}`); status != http.StatusOK {
		t.Fatalf("first transition failed")
	}

	cases := map[string]string{
		"current stage": "遏制",
		"backward":      "受理",
		"skip a stage":  "恢复",
		"jump to end":   "关闭",
	}
	for name, stage := range cases {
		t.Run(name, func(t *testing.T) {
			status, body := transition(t, server.URL, "INC-1", `{"stage":"`+stage+`","owner":"mallory"}`)
			if status != http.StatusConflict {
				t.Fatalf("status = %d, want 409", status)
			}
			if len(body) != 1 {
				t.Fatalf("error response must hold only the top-level error object: %v", body)
			}
			if code := errorCode(t, body); code != "invalid_transition" {
				t.Fatalf("code = %q, want invalid_transition", code)
			}
		})
	}

	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("fetch status = %d", status)
	}
	if fetched["stage"] != "遏制" || fetched["owner"] != "bob" || len(fetched["timeline"].([]any)) != 2 {
		t.Fatalf("conflicting transitions changed the incident: %v", fetched)
	}
}

func TestTransitionReflectsInQueries(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")
	registerIncident(t, server.URL, "INC-2", "high", "bob")

	if status, _ := transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"carol"}`); status != http.StatusOK {
		t.Fatalf("transition failed")
	}

	// Lookup by id reflects the new stage and owner.
	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK || fetched["stage"] != "遏制" || fetched["owner"] != "carol" {
		t.Fatalf("fetch = %v (status %d)", fetched, status)
	}

	// Stage filters move the incident between buckets.
	_, items := listIncidents(t, server.URL+"/incidents?stage="+url.QueryEscape("遏制"))
	if len(items) != 1 || items[0].(map[string]any)["id"] != "INC-1" {
		t.Fatalf("stage 遏制 filter = %v", items)
	}
	_, items = listIncidents(t, server.URL+"/incidents?stage="+url.QueryEscape("受理"))
	if len(items) != 1 || items[0].(map[string]any)["id"] != "INC-2" {
		t.Fatalf("stage 受理 filter = %v", items)
	}
}

func TestTransitionConcurrentSameStage(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")

	const racers = 2
	statuses := make([]int, racers)
	bodies := make([]map[string]any, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := fmt.Sprintf("owner-%d", i)
			statuses[i], bodies[i] = transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"`+owner+`"}`)
		}()
	}
	wg.Wait()

	winner := -1
	for i, status := range statuses {
		switch status {
		case http.StatusOK:
			if winner != -1 {
				t.Fatalf("both requests returned 200")
			}
			winner = i
		case http.StatusConflict:
			if code := errorCode(t, bodies[i]); code != "invalid_transition" {
				t.Fatalf("loser code = %q, want invalid_transition", code)
			}
		default:
			t.Fatalf("unexpected status %d (%v)", status, bodies[i])
		}
	}
	if winner == -1 {
		t.Fatalf("no request succeeded: %v", statuses)
	}

	// Exactly one transition landed: the winner's owner, one new entry.
	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("fetch status = %d", status)
	}
	wantOwner := fmt.Sprintf("owner-%d", winner)
	if fetched["owner"] != wantOwner || fetched["stage"] != "遏制" {
		t.Fatalf("incident = %v, want owner %q at 遏制", fetched, wantOwner)
	}
	timeline := fetched["timeline"].([]any)
	if len(timeline) != 2 {
		t.Fatalf("timeline length = %d, want 2", len(timeline))
	}
	last := timeline[1].(map[string]any)
	if last["stage"] != "遏制" || last["owner"] != wantOwner {
		t.Fatalf("last entry = %v, want 遏制/%q", last, wantOwner)
	}
}

func TestTransitionValidationPrecedesStorage(t *testing.T) {
	server, st := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")
	st.Close()

	// Invalid bodies are rejected even while the store is down.
	status, body := transition(t, server.URL, "INC-1", `{"stage":"unknown","owner":"bob"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if code := errorCode(t, body); code != "invalid_request" {
		t.Fatalf("code = %q, want invalid_request", code)
	}

	// A valid body still surfaces the storage failure.
	status, body = transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"bob"}`)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if code := errorCode(t, body); code != "storage_unavailable" {
		t.Fatalf("code = %q, want storage_unavailable", code)
	}
}

func TestTransitionPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first := httptest.NewServer(NewRouter(st))
	if status, _ := doRequest(t, http.MethodPost, first.URL+"/incidents", validBody); status != http.StatusCreated {
		t.Fatalf("create status = %d", status)
	}
	status, moved := transition(t, first.URL, "INC-1", `{"stage":"遏制","owner":"bob"}`)
	if status != http.StatusOK {
		t.Fatalf("transition status = %d", status)
	}
	first.Close()
	st.Close()

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	second := httptest.NewServer(NewRouter(reopened))
	defer second.Close()

	status, fetched := doRequest(t, http.MethodGet, second.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("fetch after restart: status %d", status)
	}
	movedTimeline := moved["timeline"].([]any)
	fetchedTimeline := fetched["timeline"].([]any)
	if fetched["stage"] != "遏制" || fetched["owner"] != "bob" || len(fetchedTimeline) != 2 {
		t.Fatalf("restart changed the record: %v", fetched)
	}
	for i := range movedTimeline {
		if fetchedTimeline[i].(map[string]any)["at"] != movedTimeline[i].(map[string]any)["at"] {
			t.Fatalf("history entry %d changed: %v vs %v", i, fetchedTimeline[i], movedTimeline[i])
		}
	}

	// The flow resumes from the stored stage after a restart.
	status, body := transition(t, second.URL, "INC-1", `{"stage":"清除","owner":"carol"}`)
	if status != http.StatusOK {
		t.Fatalf("transition after restart: status %d (%v)", status, body)
	}
	if len(body["timeline"].([]any)) != 3 {
		t.Fatalf("timeline after restart = %v", body["timeline"])
	}
}

// checkBodyConsistent fails the test unless a decoded incident body is
// internally consistent: stage and owner match the last timeline entry and
// the timeline walks the stage flow one entry at a time with the owners the
// flow assigned. A body assembled from two committed states violates this.
func checkBodyConsistent(t *testing.T, body map[string]any, stages, owners []string) {
	t.Helper()
	timeline, ok := body["timeline"].([]any)
	if !ok || len(timeline) == 0 {
		t.Fatalf("body has no timeline: %v", body)
	}
	idx := -1
	for i, stage := range stages {
		if body["stage"] == stage {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("stage = %v, not on the flow", body["stage"])
	}
	if len(timeline) != idx+1 {
		t.Fatalf("stage %v with %d timeline entries, want %d: %v",
			body["stage"], len(timeline), idx+1, body)
	}
	if body["owner"] != owners[idx] {
		t.Fatalf("stage %v with owner %v, want %q: %v", body["stage"], body["owner"], owners[idx], body)
	}
	for i, item := range timeline {
		entry := item.(map[string]any)
		if entry["stage"] != stages[i] || entry["owner"] != owners[i] {
			t.Fatalf("timeline entry %d = %v, want %q/%q: %v", i, entry, stages[i], owners[i], body)
		}
		if entry["at"] == "" {
			t.Fatalf("timeline entry %d lost its timestamp: %v", i, body)
		}
	}
	last := timeline[len(timeline)-1].(map[string]any)
	if last["stage"] != body["stage"] || last["owner"] != body["owner"] {
		t.Fatalf("body %v/%v disagrees with last entry %v", body["stage"], body["owner"], last)
	}
}

func TestQueryConsistentWhileTransitionsCommit(t *testing.T) {
	server, _ := newTestRouter(t)
	stages := []string{"受理", "遏制", "清除", "恢复", "关闭"}
	owners := []string{"alice", "bob", "carol", "dave", "erin"}

	registerIncident(t, server.URL, "INC-1", "high", owners[0])
	registerIncident(t, server.URL, "INC-2", "high", owners[0])
	registerIncident(t, server.URL, "INC-3", "low", owners[0])

	// Concurrent readers query by id, by stage, and by the severity/stage
	// combination while the writer walks INC-1 and INC-2 through the flow.
	// Every 200 response must reflect one committed state: for INC-1 and
	// INC-2 either the pre-transition body with its shorter history or the
	// post-transition one, never a mixture.
	byID := map[string]bool{
		"/incidents?id=INC-1": true,
		"/incidents?id=INC-2": true,
	}
	stageAccepted := "/incidents?stage=" + url.QueryEscape("受理")
	combo := "/incidents?severity=high&stage=" + url.QueryEscape("遏制")
	queries := []string{
		"/incidents?id=INC-1",
		"/incidents?id=INC-2",
		"/incidents",
		stageAccepted,
		combo,
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
				for _, path := range queries {
					response, err := http.Get(server.URL + path)
					if err != nil {
						t.Errorf("get %s: %v", path, err)
						return
					}
					if response.StatusCode != http.StatusOK {
						response.Body.Close()
						t.Errorf("get %s: status %d", path, response.StatusCode)
						return
					}
					if byID[path] {
						var body map[string]any
						if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
							t.Errorf("decode %s: %v", path, err)
							response.Body.Close()
							return
						}
						checkBodyConsistent(t, body, stages, owners)
					} else {
						var items []any
						if err := json.NewDecoder(response.Body).Decode(&items); err != nil {
							t.Errorf("decode %s: %v", path, err)
							response.Body.Close()
							return
						}
						for _, item := range items {
							body := item.(map[string]any)
							checkBodyConsistent(t, body, stages, owners)
							// Filter membership is decided in the same state
							// the body came from, and combined filters
							// intersect.
							if path == stageAccepted && body["stage"] != "受理" {
								t.Errorf("受理 filter returned %v", body)
							}
							if path == combo && (body["severity"] != "high" || body["stage"] != "遏制") {
								t.Errorf("combined filter returned %v", body)
							}
						}
					}
					response.Body.Close()
				}
			}
		}()
	}

	timestamps := map[string][]string{}
	for _, id := range []string{"INC-1", "INC-2"} {
		_, created := doRequest(t, http.MethodGet, server.URL+"/incidents?id="+id, "")
		timestamps[id] = []string{created["timeline"].([]any)[0].(map[string]any)["at"].(string)}
		for i := 1; i < len(stages); i++ {
			body := `{"stage":"` + stages[i] + `","owner":"` + owners[i] + `"}`
			status, moved := transition(t, server.URL, id, body)
			if status != http.StatusOK {
				t.Fatalf("transition %s to %s: status %d (%v)", id, stages[i], status, moved)
			}
			entry := moved["timeline"].([]any)[i].(map[string]any)
			timestamps[id] = append(timestamps[id], entry["at"].(string))
		}
	}
	close(stop)
	wg.Wait()

	// After every transition returned, queries show the final 关闭 state
	// with the complete history and the original timestamps untouched.
	for _, id := range []string{"INC-1", "INC-2"} {
		status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id="+id, "")
		if status != http.StatusOK {
			t.Fatalf("fetch %s: status %d", id, status)
		}
		checkBodyConsistent(t, fetched, stages, owners)
		timeline := fetched["timeline"].([]any)
		for i, item := range timeline {
			if at := item.(map[string]any)["at"]; at != timestamps[id][i] {
				t.Fatalf("%s entry %d at = %v, want the original %v", id, i, at, timestamps[id][i])
			}
		}
	}

	// The combined filter intersects on the final state: both high
	// incidents are closed, only INC-3 is still 受理.
	_, items := listIncidents(t, server.URL+"/incidents?severity=high&stage="+url.QueryEscape("关闭"))
	if len(items) != 2 || items[0].(map[string]any)["id"] != "INC-1" || items[1].(map[string]any)["id"] != "INC-2" {
		t.Fatalf("final high/关闭 list = %v", items)
	}
	_, items = listIncidents(t, server.URL+"/incidents?stage="+url.QueryEscape("受理"))
	if len(items) != 1 || items[0].(map[string]any)["id"] != "INC-3" {
		t.Fatalf("final 受理 list = %v", items)
	}
}
