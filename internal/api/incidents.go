package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

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

// createIncidentRequest uses pointers so missing and null fields are both
// distinguishable from present values.
type createIncidentRequest struct {
	ID       *string   `json:"id"`
	Severity *string   `json:"severity"`
	Assets   *[]string `json:"assets"`
	Owner    *string   `json:"owner"`
}

func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

func writeStorageUnavailable(c *gin.Context) {
	writeError(c, http.StatusServiceUnavailable, "storage_unavailable", "database is not available")
}

// createIncident handles POST /incidents.
func createIncident(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req createIncidentRequest
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil || decoder.More() {
			writeError(c, http.StatusBadRequest, "invalid_request",
				"body must be a single JSON object with id, severity, assets and owner")
			return
		}
		if !validCreateRequest(&req) {
			writeError(c, http.StatusBadRequest, "invalid_request",
				"id and owner must be non-blank strings, severity must be low, medium, high or critical, assets must be a non-empty array of non-blank strings")
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		incident := store.Incident{
			ID:       *req.ID,
			Severity: *req.Severity,
			Assets:   *req.Assets,
			Stage:    store.StageAccepted,
			Owner:    *req.Owner,
			Timeline: []store.TimelineEntry{{
				Stage: store.StageAccepted,
				Owner: *req.Owner,
				At:    now,
			}},
		}
		stored, _, err := st.RegisterIncident(incident)
		if err != nil {
			var conflict *store.IncidentConflictError
			if errors.As(err, &conflict) {
				writeError(c, http.StatusConflict, "incident_conflict",
					"an incident with this id is already registered with different details")
				return
			}
			writeStorageUnavailable(c)
			return
		}
		c.JSON(http.StatusCreated, stored)
	}
}

func validCreateRequest(req *createIncidentRequest) bool {
	if req.ID == nil || strings.TrimSpace(*req.ID) == "" {
		return false
	}
	if req.Severity == nil || !validSeverities[*req.Severity] {
		return false
	}
	if req.Owner == nil || strings.TrimSpace(*req.Owner) == "" {
		return false
	}
	if req.Assets == nil || len(*req.Assets) == 0 {
		return false
	}
	for _, asset := range *req.Assets {
		if strings.TrimSpace(asset) == "" {
			return false
		}
	}
	return true
}

// listIncidents handles GET /incidents with the id, severity and stage query parameters.
func listIncidents(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Request.URL.Query()
		for key, values := range query {
			switch key {
			case "id", "severity", "stage":
				if len(values) != 1 || values[0] == "" {
					writeError(c, http.StatusBadRequest, "invalid_query",
						"query parameters id, severity and stage each accept exactly one non-empty value")
					return
				}
			default:
				writeError(c, http.StatusBadRequest, "invalid_query",
					"only the id, severity and stage query parameters are supported")
				return
			}
		}
		_, hasID := query["id"]
		_, hasSeverity := query["severity"]
		_, hasStage := query["stage"]
		if hasID && (hasSeverity || hasStage) {
			writeError(c, http.StatusBadRequest, "invalid_query",
				"the id parameter cannot be combined with severity or stage")
			return
		}
		severity := query.Get("severity")
		stage := query.Get("stage")
		if hasSeverity && !validSeverities[severity] {
			writeError(c, http.StatusBadRequest, "invalid_query",
				"severity must be one of low, medium, high, critical")
			return
		}
		if hasStage && !validStages[stage] {
			writeError(c, http.StatusBadRequest, "invalid_query",
				"stage must be one of 受理, 遏制, 清除, 恢复, 关闭")
			return
		}

		if hasID {
			incident, err := st.GetIncident(query.Get("id"))
			if err != nil {
				writeStorageUnavailable(c)
				return
			}
			if incident == nil {
				writeError(c, http.StatusNotFound, "incident_not_found", "no incident is registered with this id")
				return
			}
			c.JSON(http.StatusOK, incident)
			return
		}

		incidents, err := st.ListIncidents(severity, stage)
		if err != nil {
			writeStorageUnavailable(c)
			return
		}
		c.JSON(http.StatusOK, incidents)
	}
}
