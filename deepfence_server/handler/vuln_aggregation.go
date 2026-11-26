package handler

import (
	"errors"
	"net/http"

	"github.com/deepfence/ThreatMapper/deepfence_server/reporters/vulnview"
	httpext "github.com/go-playground/pkg/v5/net/http"
)

// AggregateVulnerabilities handles POST /search/vulnerabilities/deduplicated.
//
// It returns the merged cross-cluster view: each CVE counted once, full
// cluster/workload/image/host attribution and (by default) the retained
// occurrences for drill-down. The request body is the same JSON family used by
// the existing search APIs and additionally accepts inline "findings" or
// legacy "vulnerabilities" rows for database-less aggregation.
func (h *Handler) AggregateVulnerabilities(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req vulnview.Request
	if err := httpext.DecodeJSON(r, httpext.NoQueryParams, MaxPostRequestSize, &req); err != nil {
		h.respondError(&BadDecoding{err}, w)
		return
	}

	resp, err := vulnview.Aggregate(r.Context(), req)
	if err != nil {
		h.respondAggregationError(err, w)
		return
	}

	if err := httpext.JSON(w, http.StatusOK, resp); err != nil {
		h.respondError(err, w)
	}
}

// AggregateVulnerabilitiesByWorkload handles
// POST /search/vulnerabilities/workload-aggregation.
func (h *Handler) AggregateVulnerabilitiesByWorkload(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req vulnview.Request
	if err := httpext.DecodeJSON(r, httpext.NoQueryParams, MaxPostRequestSize, &req); err != nil {
		h.respondError(&BadDecoding{err}, w)
		return
	}

	resp, err := vulnview.AggregateWorkloads(r.Context(), req)
	if err != nil {
		h.respondAggregationError(err, w)
		return
	}

	if err := httpext.JSON(w, http.StatusOK, resp); err != nil {
		h.respondError(err, w)
	}
}

// GetVulnerabilityDrillDown handles POST /search/vulnerabilities/drilldown.
// It returns one merged CVE with every occurrence and concrete image/host
// attribution.
func (h *Handler) GetVulnerabilityDrillDown(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req vulnview.Request
	if err := httpext.DecodeJSON(r, httpext.NoQueryParams, MaxPostRequestSize, &req); err != nil {
		h.respondError(&BadDecoding{err}, w)
		return
	}

	if req.CVEID == "" && req.DedupKey == "" {
		h.respondError(&BadDecoding{errors.New("cve_id or dedup_key is required")}, w)
		return
	}

	detail, err := vulnview.Detail(r.Context(), req)
	if err != nil {
		h.respondAggregationError(err, w)
		return
	}

	if err := httpext.JSON(w, http.StatusOK, detail); err != nil {
		h.respondError(err, w)
	}
}

func (h *Handler) respondAggregationError(err error, w http.ResponseWriter) {
	if errors.Is(err, vulnview.ErrVulnerabilityNotFound) {
		h.respondError(&NotFoundError{err: err}, w)
		return
	}
	h.respondError(err, w)
}
