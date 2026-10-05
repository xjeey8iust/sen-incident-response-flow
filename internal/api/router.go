package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-incident-response-flow/internal/store"
)

var validSeverities = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

var validStages = map[string]bool{
	"受理": true,
	"遏制": true,
	"清除": true,
	"恢复": true,
	"关闭": true,
}

// NewRouter wires the public HTTP surface. The service contract in README.md
// describes the error shape every entry must keep.
func NewRouter(st *store.Store) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		if err := st.Ping(); err != nil {
			writeError(c, http.StatusServiceUnavailable, "storage_unavailable", "database is not available")
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "database": "ok"})
	})

	router.POST("/incidents", createIncident(st))
	router.GET("/incidents", queryIncidents(st))
	router.POST("/incidents/:id/transition", transitionIncident(st))

	router.NoRoute(func(c *gin.Context) {
		writeError(c, http.StatusNotFound, "route_not_found", "no route matches this path")
	})
	return router
}

// registerRequest mirrors the accepted registration body. Pointer fields let
// the handler reject missing keys and explicit nulls alike.
type registerRequest struct {
	ID       *string   `json:"id"`
	Severity *string   `json:"severity"`
	Assets   *[]string `json:"assets"`
	Owner    *string   `json:"owner"`
}

// registerFields is the case-sensitive whitelist of accepted registration
// fields. Names are compared after JSON unescaping, so "id" is accepted
// while "ID" is an unknown field.
var registerFields = map[string]bool{
	"id":       true,
	"severity": true,
	"assets":   true,
	"owner":    true,
}

func createIncident(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		payload, ok := decodeRegisterRequest(c.Request.Body)
		if !ok || !payload.valid() {
			writeInvalidRequest(c)
			return
		}

		incident, err := st.Register(*payload.ID, *payload.Severity, *payload.Owner, *payload.Assets)
		if errors.Is(err, store.ErrIncidentConflict) {
			writeError(c, http.StatusConflict, "incident_conflict", "incident id is already registered with different attributes")
			return
		}
		if err != nil {
			writeError(c, http.StatusServiceUnavailable, "storage_unavailable", "database is not available")
			return
		}
		c.JSON(http.StatusCreated, incident)
	}
}

// decodeRegisterRequest parses the registration body token by token so the
// field whitelist stays case-sensitive and duplicate keys are rejected.
// encoding/json's struct decoding cannot do either: it matches tags
// case-insensitively and silently lets a later key overwrite an earlier one.
// Keys arrive already unescaped, so "id" collides with "id" while
// case variants like "ID" fall outside the whitelist.
func decodeRegisterRequest(body io.Reader) (registerRequest, bool) {
	var payload registerRequest
	ok := decodeStrictObject(body, registerFields, func(key string, decoder *json.Decoder) error {
		switch key {
		case "id":
			return decoder.Decode(&payload.ID)
		case "severity":
			return decoder.Decode(&payload.Severity)
		case "assets":
			return decoder.Decode(&payload.Assets)
		case "owner":
			return decoder.Decode(&payload.Owner)
		}
		return nil
	})
	return payload, ok
}

// decodeStrictObject parses body as a single JSON object whose keys all pass
// the case-sensitive allowed whitelist and never repeat, binding each value
// through bind. Anything else — trailing data, arrays, scalars, unknown or
// duplicate keys, malformed values — is rejected.
func decodeStrictObject(body io.Reader, allowed map[string]bool, bind func(key string, decoder *json.Decoder) error) bool {
	decoder := json.NewDecoder(body)
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || seen[key] {
			return false
		}
		seen[key] = true
		if err := bind(key, decoder); err != nil {
			return false
		}
	}
	if _, err := decoder.Token(); err != nil {
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return false
	}
	return true
}

// valid reports whether every required field is present and well formed.
func (r *registerRequest) valid() bool {
	if r.ID == nil || strings.TrimSpace(*r.ID) == "" {
		return false
	}
	if r.Severity == nil || !validSeverities[*r.Severity] {
		return false
	}
	if r.Owner == nil || strings.TrimSpace(*r.Owner) == "" {
		return false
	}
	if r.Assets == nil || len(*r.Assets) == 0 {
		return false
	}
	for _, asset := range *r.Assets {
		if strings.TrimSpace(asset) == "" {
			return false
		}
	}
	return true
}

func queryIncidents(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse the raw query ourselves: URL.Query() silently drops segments
		// with broken percent-escapes or unescaped semicolons, which would
		// turn a malformed filter into an unconditional listing. Any parse
		// error rejects the whole request before the store is touched.
		query, err := url.ParseQuery(c.Request.URL.RawQuery)
		if err != nil {
			writeInvalidQuery(c)
			return
		}
		for key, values := range query {
			if key != "severity" && key != "stage" && key != "id" {
				writeInvalidQuery(c)
				return
			}
			if len(values) != 1 || values[0] == "" {
				writeInvalidQuery(c)
				return
			}
		}

		if id := query.Get("id"); id != "" {
			if len(query) != 1 {
				writeInvalidQuery(c)
				return
			}
			incident, err := st.Get(id)
			if errors.Is(err, store.ErrIncidentNotFound) {
				writeError(c, http.StatusNotFound, "incident_not_found", "no incident is registered with this id")
				return
			}
			if err != nil {
				writeError(c, http.StatusServiceUnavailable, "storage_unavailable", "database is not available")
				return
			}
			c.JSON(http.StatusOK, incident)
			return
		}

		severity := query.Get("severity")
		if severity != "" && !validSeverities[severity] {
			writeInvalidQuery(c)
			return
		}
		stage := query.Get("stage")
		if stage != "" && !validStages[stage] {
			writeInvalidQuery(c)
			return
		}

		incidents, err := st.List(severity, stage)
		if err != nil {
			writeError(c, http.StatusServiceUnavailable, "storage_unavailable", "database is not available")
			return
		}
		c.JSON(http.StatusOK, incidents)
	}
}

// transitionRequest mirrors the accepted transition body. Pointer fields let
// the handler reject missing keys and explicit nulls alike.
type transitionRequest struct {
	Stage *string `json:"stage"`
	Owner *string `json:"owner"`
}

// transitionFields is the case-sensitive whitelist of accepted transition
// fields, compared after JSON unescaping just like the registration fields.
var transitionFields = map[string]bool{
	"stage": true,
	"owner": true,
}

func transitionIncident(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		payload, ok := decodeTransitionRequest(c.Request.Body)
		if !ok || !payload.valid() {
			writeInvalidTransitionRequest(c)
			return
		}

		incident, err := st.Transition(c.Param("id"), *payload.Stage, *payload.Owner)
		if errors.Is(err, store.ErrIncidentNotFound) {
			writeError(c, http.StatusNotFound, "incident_not_found", "no incident is registered with this id")
			return
		}
		if errors.Is(err, store.ErrInvalidTransition) {
			writeError(c, http.StatusConflict, "invalid_transition", "transition must advance exactly one stage")
			return
		}
		if err != nil {
			writeError(c, http.StatusServiceUnavailable, "storage_unavailable", "database is not available")
			return
		}
		c.JSON(http.StatusOK, incident)
	}
}

// decodeTransitionRequest parses the transition body with the same strict
// rules as the registration body: a single JSON object, case-sensitive
// whitelisted field names, no duplicates even after JSON unescaping.
func decodeTransitionRequest(body io.Reader) (transitionRequest, bool) {
	var payload transitionRequest
	ok := decodeStrictObject(body, transitionFields, func(key string, decoder *json.Decoder) error {
		switch key {
		case "stage":
			return decoder.Decode(&payload.Stage)
		case "owner":
			return decoder.Decode(&payload.Owner)
		}
		return nil
	})
	return payload, ok
}

// valid reports whether both required fields are present and well formed.
// The owner string is kept as-is; only its non-blankness is checked.
func (r *transitionRequest) valid() bool {
	if r.Stage == nil || !validStages[*r.Stage] {
		return false
	}
	if r.Owner == nil || strings.TrimSpace(*r.Owner) == "" {
		return false
	}
	return true
}

func writeInvalidRequest(c *gin.Context) {
	writeError(c, http.StatusBadRequest, "invalid_request", "request body must be a single JSON object with valid id, severity, assets, and owner")
}

func writeInvalidTransitionRequest(c *gin.Context) {
	writeError(c, http.StatusBadRequest, "invalid_request", "request body must be a single JSON object with valid stage and owner")
}

func writeInvalidQuery(c *gin.Context) {
	writeError(c, http.StatusBadRequest, "invalid_query", "query parameters are missing, repeated, unknown, or hold invalid values")
}

// writeError keeps the published error shape: a single top-level error object
// whose message never exposes SQL, stack traces, or file paths.
func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}
