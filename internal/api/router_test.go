package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
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

// assertInvalidQueryShape locks the published 400 contract: exactly one
// top-level error object holding two strings, never the parser's own text.
func assertInvalidQueryShape(t *testing.T, rawQuery string, body map[string]any) {
	t.Helper()
	if len(body) != 1 {
		t.Fatalf("response has keys beyond error: %v", body)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no top-level error object: %v", body)
	}
	if len(errObj) != 2 {
		t.Fatalf("error object must hold only code and message: %v", errObj)
	}
	code, ok := errObj["code"].(string)
	if !ok || code != "invalid_query" {
		t.Fatalf("error.code = %v, want invalid_query", errObj["code"])
	}
	message, ok := errObj["message"].(string)
	if !ok || message != "query parameters are missing, repeated, unknown, or hold invalid values" {
		t.Fatalf("error.message = %v, want the published invalid_query text", errObj["message"])
	}
	// Parser diagnostics, SQL, stacks, and file paths must never leak, and the
	// offending fragment must not be echoed back verbatim.
	for _, leaked := range []string{"%ZZ", "%2G", "invalid URL escape", "semicolon separator", ".go", "sql:"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("message leaks %q: %q", leaked, message)
		}
	}
	if rawQuery != "" && strings.Contains(message, rawQuery) {
		t.Fatalf("message echoes the raw query %q: %q", rawQuery, message)
	}
}

// TestQueryMalformedFragmentsRejected is the core regression: a fragment that
// fails percent-decoding or carries a raw semicolon must reject the whole
// request. Previously url.Values dropped the parse error and only the
// parseable survivors were acted on, turning severity=%ZZ into an unfiltered
// list and id=INC-1&stage=%ZZ into a single-ticket lookup.
func TestQueryMalformedFragmentsRejected(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")

	cases := []string{
		"severity=%ZZ",               // non-hex value used to become an unfiltered list
		"sev%erity=high",             // non-hex escape in the parameter name
		"severity=%",                 // lone percent in value
		"severity=%2",                // truncated percent escape
		"severity=%2G",               // non-hex digit
		"%ZZ=high",                   // malformed name only
		"id=INC-1&stage=%ZZ",         // existing id keeps a malformed filter
		"stage=%ZZ&id=INC-1",         // malformed fragment first, existing id after
		"id=missing&stage=%ZZ",       // missing id must not yield 404
		"stage=%ZZ&id=missing",       // malformed first, missing id after
		"id=INC-1%ZZ",                // malformed id value must not resolve to INC-1
		"severity=high&%ZZ=1",        // malformed unknown fragment after a valid one
		"id=INC-1&%ZZ=1",             // malformed unknown fragment next to a hit
		"foo=%ZZ",                    // a malformed unknown parameter must not be dropped
		"severity=high&severity=%ZZ", // a malformed duplicate must not collapse away
		"severity=%ZZ&severity=high", // malformed duplicate first
		"id=INC-1;x=y",               // raw semicolon must not act as a separator
		"foo=a;b",                    // raw semicolon inside a value
		";severity=high",             // fragment beginning with a semicolon
	}
	for _, rawQuery := range cases {
		t.Run(rawQuery, func(t *testing.T) {
			status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?"+rawQuery, "")
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %v)", status, body)
			}
			assertInvalidQueryShape(t, rawQuery, body)

			// A malformed query must never surface as a partial success:
			// neither a list/single object nor a 404 for a surviving id.
			if _, isError := body["error"]; !isError {
				t.Fatalf("expected a bare error response, got %v", body)
			}
		})
	}

	// An encoded semicolon is a legal value character, so this is simply an id
	// lookup that misses — 404 incident_not_found, never the 400 reserved for a
	// raw semicolon.
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1%3BX", "")
	if status != http.StatusNotFound {
		t.Fatalf("encoded-semicolon id status = %d, want 404", status)
	}
	if code := errorCode(t, body); code != "incident_not_found" {
		t.Fatalf("code = %q, want incident_not_found", code)
	}
}

// TestQueryMalformedFragmentsRejectedWhenStorageDown proves validation runs
// before the store is consulted: an unparseable query is 400 even when storage
// is unavailable, while a legal query on the same dead store still reaches it.
func TestQueryMalformedFragmentsRejectedWhenStorageDown(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	server := httptest.NewServer(NewRouter(st))
	defer server.Close()

	// Control: the store really is unavailable for a legal query.
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("legal query on dead store: status = %d, want 503", status)
	}
	if code := errorCode(t, body); code != "storage_unavailable" {
		t.Fatalf("code = %q, want storage_unavailable", code)
	}

	for _, rawQuery := range []string{"severity=%ZZ", "id=INC-1&stage=%ZZ", "id=INC-1;x=y"} {
		t.Run(rawQuery, func(t *testing.T) {
			status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?"+rawQuery, "")
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (dead store must not turn this into 503)", status)
			}
			assertInvalidQueryShape(t, rawQuery, body)
		})
	}
}

// TestQueryMalformedFragmentsDoNotMutateRecords ensures rejected queries leave
// stored tickets and their timelines untouched.
func TestQueryMalformedFragmentsDoNotMutateRecords(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")

	status, before := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("snapshot status = %d", status)
	}
	status, listBefore := listIncidents(t, server.URL+"/incidents")
	if status != http.StatusOK || len(listBefore) != 1 {
		t.Fatalf("list before = %d (status %d)", len(listBefore), status)
	}

	malformed := []string{
		"severity=%ZZ",
		"id=INC-1&stage=%ZZ",
		"stage=%ZZ&id=INC-1",
		"id=INC-1%ZZ",
		"id=INC-1;x=y",
		"foo=%ZZ",
	}
	for _, rawQuery := range malformed {
		if status, _ := doRequest(t, http.MethodGet, server.URL+"/incidents?"+rawQuery, ""); status != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", rawQuery, status)
		}
	}

	status, after := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC-1", "")
	if status != http.StatusOK {
		t.Fatalf("post-rejection fetch status = %d", status)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("rejected query changed the incident:\nbefore=%v\nafter =%v", before, after)
	}
	status, listAfter := listIncidents(t, server.URL+"/incidents")
	if status != http.StatusOK || len(listAfter) != 1 {
		t.Fatalf("list after = %d (status %d), want the single original record", len(listAfter), status)
	}
}

// TestQueryDecodesNamesThenValidates ensures names and values are decoded
// exactly once and then recognized: an encoded known name works, an encoded
// duplicate name collides with its plain form, and an encoded unknown name is
// still unknown.
func TestQueryDecodesNamesThenValidates(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "high", "alice")
	registerIncident(t, server.URL, "INC-2", "low", "bob")

	// Encoded known parameter name (%73 == 's') filters normally.
	status, items := listIncidents(t, server.URL+"/incidents?%73everity=high")
	if status != http.StatusOK || len(items) != 1 {
		t.Fatalf("encoded severity name: status %d items %d", status, len(items))
	}

	// %73everity and severity decode to the same name: a duplicate.
	for _, rawQuery := range []string{
		"%73everity=high&severity=high",
		"severity=high&%73everity=low",
		"%69d=INC-1&id=INC-1", // %69 == 'i'
	} {
		t.Run(rawQuery, func(t *testing.T) {
			status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?"+rawQuery, "")
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
			assertInvalidQueryShape(t, rawQuery, body)
		})
	}

	// An encoded unknown name is unknown after decoding.
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?%66oo=bar", "")
	if status != http.StatusBadRequest {
		t.Fatalf("encoded unknown name status = %d, want 400", status)
	}
	if code := errorCode(t, body); code != "invalid_query" {
		t.Fatalf("code = %q, want invalid_query", code)
	}

	// Values decode once: %68igh -> high and matches; %2568igh -> %68igh,
	// which is not a severity rather than decoding a second time to high.
	status, items = listIncidents(t, server.URL+"/incidents?severity=%68igh")
	if status != http.StatusOK || len(items) != 1 {
		t.Fatalf("single-decoded severity: status %d items %d", status, len(items))
	}
	status, body = doRequest(t, http.MethodGet, server.URL+"/incidents?severity=%2568igh", "")
	if status != http.StatusBadRequest {
		t.Fatalf("double-decoded severity status = %d, want 400", status)
	}
	if code := errorCode(t, body); code != "invalid_query" {
		t.Fatalf("code = %q, want invalid_query", code)
	}
}

// TestQuerySpecialCharacterIDs covers the preserved decoding semantics:
// percent-encoded ; & + are literal id characters and never split the query,
// a plain '+' still means a space, and encoded Chinese keeps filtering.
func TestQuerySpecialCharacterIDs(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, `INC;A&B+C`, "high", "alice")
	registerIncident(t, server.URL, "INC X", "medium", "bob")
	registerIncident(t, server.URL, "INC+X", "low", "carol")

	// Encoded ; & + match the full id as stored and are not treated as query
	// delimiters (%3B ';', %26 '&', %2B '+').
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC%3BA%26B%2BC", "")
	if status != http.StatusOK {
		t.Fatalf("encoded special-char id: status = %d, want 200 (%v)", status, body)
	}
	if body["id"] != `INC;A&B+C` {
		t.Fatalf("id = %v, want INC;A&B+C", body["id"])
	}

	// A plain plus is a space: INC+X decodes to "INC X".
	status, body = doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC+X", "")
	if status != http.StatusOK || body["id"] != "INC X" {
		t.Fatalf("plain plus: status %d id %v, want INC X", status, body["id"])
	}
	// %2B is a literal plus: INC%2BX decodes to "INC+X".
	status, body = doRequest(t, http.MethodGet, server.URL+"/incidents?id=INC%2BX", "")
	if status != http.StatusOK || body["id"] != "INC+X" {
		t.Fatalf("encoded plus: status %d id %v, want INC+X", status, body["id"])
	}

	// Encoded Chinese stage keeps filtering; every registered ticket starts in
	// 受理 (percent-encoded UTF-8 below).
	status, items := listIncidents(t, server.URL+"/incidents?stage=%E5%8F%97%E7%90%86")
	if status != http.StatusOK || len(items) != 3 {
		t.Fatalf("encoded stage filter: status %d items %d, want 3", status, len(items))
	}
}

// TestQueryMalformedUTF8ValueIsInvalidValue confirms a parseable but invalid
// value is still an invalid_query 400 (a truncated UTF-8 sequence decodes to
// the replacement rune, which is not a published stage).
func TestQueryMalformedUTF8ValueIsInvalidValue(t *testing.T) {
	server, _ := newTestRouter(t)
	registerIncident(t, server.URL, "INC-1", "medium", "alice")
	rawQuery := "stage=%E5"
	status, body := doRequest(t, http.MethodGet, server.URL+"/incidents?"+rawQuery, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	assertInvalidQueryShape(t, rawQuery, body)
}
