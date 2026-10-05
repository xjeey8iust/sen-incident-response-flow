package api

import (
	"encoding/json"
	"errors"
	"fmt"
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

func createIncident(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		payload, err := decodeRegisterRequest(c.Request.Body)
		if err != nil || !payload.valid() {
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
// field whitelist is applied to the decoded names exactly as JSON defines
// them: case-sensitive, with escapes like \u0069 already resolved. Unknown
// fields and any repeated name — same value or not — reject the whole body
// before the store is touched, as do trailing values after the object.
func decodeRegisterRequest(reader io.Reader) (registerRequest, error) {
	var payload registerRequest
	decoder := json.NewDecoder(reader)
	token, err := decoder.Token()
	if err != nil {
		return payload, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return payload, errors.New("request body must be a JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return payload, err
		}
		name, ok := token.(string)
		if !ok {
			return payload, errors.New("request body must be a JSON object")
		}
		if seen[name] {
			return payload, fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return payload, err
		}
		if err := payload.setField(name, value); err != nil {
			return payload, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return payload, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return payload, errors.New("request body must hold a single JSON object")
	}
	return payload, nil
}

// setField stores one raw value under its decoded name, rejecting names
// outside the whitelist and values of the wrong JSON type.
func (r *registerRequest) setField(name string, value json.RawMessage) error {
	switch name {
	case "id":
		return json.Unmarshal(value, &r.ID)
	case "severity":
		return json.Unmarshal(value, &r.Severity)
	case "assets":
		return json.Unmarshal(value, &r.Assets)
	case "owner":
		return json.Unmarshal(value, &r.Owner)
	default:
		return fmt.Errorf("unknown field %q", name)
	}
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

func writeInvalidRequest(c *gin.Context) {
	writeError(c, http.StatusBadRequest, "invalid_request", "request body must be a single JSON object with valid id, severity, assets, and owner")
}

func writeInvalidQuery(c *gin.Context) {
	writeError(c, http.StatusBadRequest, "invalid_query", "query parameters are missing, repeated, unknown, or hold invalid values")
}

// writeError keeps the published error shape: a single top-level error object
// whose message never exposes SQL, stack traces, or file paths.
func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}
