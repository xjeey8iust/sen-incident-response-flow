package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
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

func TestTransitionWalksToClosed(t *testing.T) {
	server, _ := newTestRouter(t)
	status, created := doRequest(t, http.MethodPost, server.URL+"/incidents", validBody)
	if status != http.StatusCreated {
		t.Fatalf("register status = %d", status)
	}

	stages := []string{"遏制", "清除", "恢复", "关闭"}
	owners := []string{"bob", "carol", "dave", "erin"}
	var body map[string]any
	for i, stage := range stages {
		status, body = transition(t, server.URL, "INC-1", `{"stage":"`+stage+`","owner":"`+owners[i]+`"}`)
		if status != http.StatusOK {
			t.Fatalf("transition to %s: status = %d, want 200 (body %v)", stage, status, body)
		}
		if body["stage"] != stage || body["owner"] != owners[i] {
			t.Fatalf("stage/owner = %v/%v, want %s/%s", body["stage"], body["owner"], stage, owners[i])
		}
		if body["id"] != "INC-1" || body["severity"] != "high" {
			t.Fatalf("fixed fields changed: %v", body)
		}
		assets := body["assets"].([]any)
		if len(assets) != 2 || assets[0] != "db-1" || assets[1] != "web-2" {
			t.Fatalf("assets changed: %v", assets)
		}
		timeline := body["timeline"].([]any)
		if len(timeline) != i+2 {
			t.Fatalf("timeline length = %d, want %d", len(timeline), i+2)
		}
		entry := timeline[len(timeline)-1].(map[string]any)
		if entry["stage"] != stage || entry["owner"] != owners[i] {
			t.Fatalf("new timeline entry = %v", entry)
		}
		at, err := time.Parse(time.RFC3339, entry["at"].(string))
		if err != nil || at.Location() != time.UTC {
			t.Fatalf("at = %v, want UTC RFC3339 (%v)", entry["at"], err)
		}
		// The initial entry is untouched.
		first := created["timeline"].([]any)[0].(map[string]any)
		if timeline[0].(map[string]any)["at"] != first["at"] {
			t.Fatalf("history rewritten: %v vs %v", timeline[0], first)
		}
	}

	// Queries reflect the final stage.
	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK || fetched["stage"] != "关闭" || fetched["owner"] != "erin" {
		t.Fatalf("fetch after walk: status %d body %v", status, fetched)
	}
	_, items := listIncidents(t, server.URL+"/incidents?stage="+url.QueryEscape("关闭"))
	if len(items) != 1 {
		t.Fatalf("stage filter after walk = %v", items)
	}
	_, items = listIncidents(t, server.URL+"/incidents?stage="+url.QueryEscape("受理"))
	if len(items) != 0 {
		t.Fatalf("stale stage filter = %v", items)
	}
}

func TestTransitionKeepsOwnerVerbatim(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "low", "alice")
	// Surrounding whitespace is preserved; only all-blank owners are rejected.
	status, body := transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":" bob "}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %v)", status, body)
	}
	if body["owner"] != " bob " {
		t.Fatalf("owner = %q, want verbatim %q", body["owner"], " bob ")
	}
}

func TestTransitionRejectsInvalidBodies(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")
	cases := map[string]string{
		"empty body":          "",
		"not json":            `nope`,
		"json array":          `[]`,
		"json scalar":         `"遏制"`,
		"trailing object":     `{"stage":"遏制","owner":"bob"} {}`,
		"unknown field":       `{"stage":"遏制","owner":"bob","id":"INC-1"}`,
		"missing stage":       `{"owner":"bob"}`,
		"missing owner":       `{"stage":"遏制"}`,
		"null stage":          `{"stage":null,"owner":"bob"}`,
		"null owner":          `{"stage":"遏制","owner":null}`,
		"stage wrong type":    `{"stage":1,"owner":"bob"}`,
		"owner wrong type":    `{"stage":"遏制","owner":["bob"]}`,
		"blank owner":         `{"stage":"遏制","owner":"  "}`,
		"empty owner":         `{"stage":"遏制","owner":""}`,
		"unknown stage":       `{"stage":"修复","owner":"bob"}`,
		"stage case variant":  `{"Stage":"遏制","owner":"bob"}`,
		"owner case variant":  `{"stage":"遏制","Owner":"bob"}`,
		"duplicate stage":     `{"stage":"遏制","stage":"遏制","owner":"bob"}`,
		"duplicate owner":     `{"stage":"遏制","owner":"bob","owner":"carol"}`,
		"escaped dup stage":   `{"stage":"遏制","` + escapeName("stage") + `":"清除","owner":"bob"}`,
		"escaped dup owner":   `{"stage":"遏制","owner":"bob","` + escapeName("owner") + `":"carol"}`,
		"escaped unknown key": `{"stage":"遏制","owner":"bob","` + escapeName("extra") + `":1}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status, decoded := transition(t, server.URL, "INC-1", body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %v)", status, decoded)
			}
			if len(decoded) != 1 {
				t.Fatalf("error response must hold only the top-level error object: %v", decoded)
			}
			if code := errorCode(t, decoded); code != "invalid_request" {
				t.Fatalf("code = %q, want invalid_request", code)
			}
		})
	}

	// Nothing changed.
	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK || fetched["stage"] != "受理" || fetched["owner"] != "alice" ||
		len(fetched["timeline"].([]any)) != 1 {
		t.Fatalf("rejected bodies changed the incident: %v", fetched)
	}
}

func TestTransitionValidationPrecedesLookup(t *testing.T) {
	server, _ := newTestRouter(t)
	// No incident registered at all: invalid bodies still win over the lookup.
	for _, body := range []string{
		`{"Stage":"遏制","owner":"bob"}`,
		`{"stage":"遏制","stage":"遏制","owner":"bob"}`,
		`{"stage":"未知","owner":"bob"}`,
		`{"owner":" "}`,
	} {
		status, decoded := transition(t, server.URL, "GHOST", body)
		if status != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", body, status)
		}
		if code := errorCode(t, decoded); code != "invalid_request" {
			t.Fatalf("%s: code = %q, want invalid_request", body, code)
		}
	}
}

func TestTransitionMissingIncidentReturns404(t *testing.T) {
	server, _ := newTestRouter(t)
	status, body := transition(t, server.URL, "GHOST", `{"stage":"遏制","owner":"bob"}`)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	if code := errorCode(t, body); code != "incident_not_found" {
		t.Fatalf("code = %q, want incident_not_found", code)
	}
}

func TestTransitionRejectsIllegalMoves(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")

	// Current stage, backwards, and skipping all conflict.
	for _, stage := range []string{"受理", "清除", "恢复", "关闭"} {
		status, body := transition(t, server.URL, "INC-1", `{"stage":"`+stage+`","owner":"bob"}`)
		if status != http.StatusConflict {
			t.Fatalf("stage %s: status = %d, want 409", stage, status)
		}
		if code := errorCode(t, body); code != "invalid_transition" {
			t.Fatalf("stage %s: code = %q, want invalid_transition", stage, code)
		}
	}

	if status, _ := transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"bob"}`); status != http.StatusOK {
		t.Fatalf("legal transition rejected")
	}
	// Now 受理 and 遏制 are both illegal targets.
	for _, stage := range []string{"受理", "遏制", "恢复", "关闭"} {
		status, _ := transition(t, server.URL, "INC-1", `{"stage":"`+stage+`","owner":"bob"}`)
		if status != http.StatusConflict {
			t.Fatalf("stage %s: status = %d, want 409", stage, status)
		}
	}

	// Walk to 关闭; nothing may leave it.
	for _, stage := range []string{"清除", "恢复", "关闭"} {
		if status, _ := transition(t, server.URL, "INC-1", `{"stage":"`+stage+`","owner":"x"}`); status != http.StatusOK {
			t.Fatalf("transition to %s rejected", stage)
		}
	}
	for _, stage := range []string{"受理", "遏制", "清除", "恢复", "关闭"} {
		status, body := transition(t, server.URL, "INC-1", `{"stage":"`+stage+`","owner":"x"}`)
		if status != http.StatusConflict {
			t.Fatalf("from 关闭 to %s: status = %d, want 409", stage, status)
		}
		if code := errorCode(t, body); code != "invalid_transition" {
			t.Fatalf("from 关闭 to %s: code = %q", stage, code)
		}
	}

	// Only the four accepted moves are in the history.
	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK || fetched["stage"] != "关闭" || len(fetched["timeline"].([]any)) != 5 {
		t.Fatalf("rejected transitions changed the incident: %v", fetched)
	}
}

func TestTransitionConcurrentSameStageOneWinner(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")

	const racers = 2
	type outcome struct {
		status int
		body   map[string]any
	}
	results := make(chan outcome, racers)
	for i := 0; i < racers; i++ {
		go func(i int) {
			owner := string(rune('a' + i))
			status, body := transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"`+owner+`"}`)
			results <- outcome{status, body}
		}(i)
	}
	var winners, conflicts []outcome
	for i := 0; i < racers; i++ {
		result := <-results
		switch result.status {
		case http.StatusOK:
			winners = append(winners, result)
		case http.StatusConflict:
			conflicts = append(conflicts, result)
		default:
			t.Fatalf("status = %d, want 200 or 409 (body %v)", result.status, result.body)
		}
	}
	if len(winners) != 1 || len(conflicts) != 1 {
		t.Fatalf("winners = %d conflicts = %d, want 1 and 1", len(winners), len(conflicts))
	}
	if code := errorCode(t, conflicts[0].body); code != "invalid_transition" {
		t.Fatalf("loser code = %q, want invalid_transition", code)
	}

	// The stored owner belongs to the winning request and exactly one
	// history entry was added.
	winner := winners[0].body["owner"]
	status, fetched := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK || fetched["stage"] != "遏制" || fetched["owner"] != winner {
		t.Fatalf("stored incident = %v, want owner %q", fetched, winner)
	}
	timeline := fetched["timeline"].([]any)
	if len(timeline) != 2 {
		t.Fatalf("timeline length = %d, want 2", len(timeline))
	}
	if timeline[1].(map[string]any)["owner"] != winner {
		t.Fatalf("timeline owner = %v, want %q", timeline[1], winner)
	}
}

func TestTransitionSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	server := httptest.NewServer(NewRouter(st))
	registerIncident(t, server.URL, "INC-1", "high", "alice")
	status, moved := transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"bob"}`)
	if status != http.StatusOK {
		t.Fatalf("transition status = %d", status)
	}
	server.Close()
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
		t.Fatalf("fetch after reopen: status %d", status)
	}
	if fetched["stage"] != "遏制" || fetched["owner"] != "bob" {
		t.Fatalf("reopened incident = %v", fetched)
	}
	before := moved["timeline"].([]any)
	after := fetched["timeline"].([]any)
	if len(after) != len(before) {
		t.Fatalf("timeline length changed across reopen: %v vs %v", before, after)
	}
	for i := range before {
		if after[i].(map[string]any)["at"] != before[i].(map[string]any)["at"] ||
			after[i].(map[string]any)["stage"] != before[i].(map[string]any)["stage"] ||
			after[i].(map[string]any)["owner"] != before[i].(map[string]any)["owner"] {
			t.Fatalf("history entry %d changed across reopen: %v vs %v", i, before[i], after[i])
		}
	}
}

func TestTransitionValidationPrecedesStorage(t *testing.T) {
	server, st := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")
	st.Close()

	// Invalid bodies are rejected even while the store is down.
	status, body := transition(t, server.URL, "INC-1", `{"stage":"未知","owner":"bob"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if code := errorCode(t, body); code != "invalid_request" {
		t.Fatalf("code = %q, want invalid_request", code)
	}

	// A valid body surfaces the storage failure.
	status, body = transition(t, server.URL, "INC-1", `{"stage":"遏制","owner":"bob"}`)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if code := errorCode(t, body); code != "storage_unavailable" {
		t.Fatalf("code = %q, want storage_unavailable", code)
	}
}
