// Package vulnview is the API-facing orchestration layer for the merged,
// cross-cluster vulnerability view. It feeds the dependency-free vulndedup
// engine from one of three sources:
//
//  1. inline "findings" supplied in the request body (useful for clients and
//     tests that already have flattened rows),
//  2. legacy /search/vulnerabilities JSON rows ("vulnerabilities"), proving
//     compatibility with the existing API,
//  3. the Neo4j graph (production default when no inline data is present).
package vulnview

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/deepfence/ThreatMapper/deepfence_server/model"
	"github.com/deepfence/ThreatMapper/deepfence_server/reporters/vulndedup"
)

// Request is the body shared by the deduplicated view, workload aggregation
// and drill-down endpoints. Every field is optional except the data source:
// when neither inline findings nor legacy rows are supplied the handler reads
// from Neo4j.
type Request struct {
	// Findings are pre-flattened occurrence rows.
	Findings []vulndedup.Finding `json:"findings,omitempty"`
	// Vulnerabilities accepts the existing /search/vulnerabilities JSON rows.
	Vulnerabilities []vulndedup.LegacyVulnerability `json:"vulnerabilities,omitempty"`
	// LegacyPayload accepts a bare legacy JSON array or an object wrapping
	// vulnerabilities/items/data.
	LegacyPayload json.RawMessage `json:"legacy_payload,omitempty"`

	// Granularity is "cve" (default) or "cve_package".
	Granularity string `json:"granularity,omitempty"`
	// WorkloadScope is "per_cluster" (default) or "logical".
	WorkloadScope string `json:"workload_scope,omitempty"`

	ClusterIDs  []string `json:"cluster_ids,omitempty"`
	WorkloadIDs []string `json:"workload_ids,omitempty"`
	CVEIDs      []string `json:"cve_ids,omitempty"`
	Severities  []string `json:"severities,omitempty"`

	// IncludeOccurrences defaults to true.
	IncludeOccurrences *bool `json:"include_occurrences,omitempty"`

	// CVEID / DedupKey select one entry for the drill-down endpoint.
	CVEID    string `json:"cve_id,omitempty"`
	DedupKey string `json:"dedup_key,omitempty"`

	// Window paginates the top-level vulnerabilities list. size == 0 returns
	// every entry (matching model.FetchWindow semantics).
	Window model.FetchWindow `json:"window,omitempty"`
}

// Response is the merged vulnerability view with pagination metadata.
type Response struct {
	*vulndedup.Report
	Offset    int `json:"offset"`
	Limit     int `json:"limit"`
	PageItems int `json:"page_items"`
}

// WorkloadResponse is the workload-only aggregation view.
type WorkloadResponse struct {
	Summary          vulndedup.Summary           `json:"summary"`
	Workloads        []vulndedup.WorkloadSummary `json:"workloads"`
	LogicalWorkloads []vulndedup.WorkloadSummary `json:"logical_workloads"`
}

func (r Request) options() vulndedup.Options {
	include := true
	if r.IncludeOccurrences != nil {
		include = *r.IncludeOccurrences
	}
	return vulndedup.Options{
		Granularity:        vulndedup.ParseGranularity(r.Granularity),
		WorkloadScope:      parseWorkloadScope(r.WorkloadScope),
		ClusterIDs:         r.ClusterIDs,
		WorkloadIDs:        r.WorkloadIDs,
		CVEIDs:             r.CVEIDs,
		Severities:         r.Severities,
		IncludeOccurrences: include,
	}
}

func parseWorkloadScope(scope string) vulndedup.WorkloadScope {
	if scope == string(vulndedup.WorkloadScopeLogical) {
		return vulndedup.WorkloadScopeLogical
	}
	return vulndedup.WorkloadScopePerCluster
}

// CollectFindings resolves the raw findings from inline data or the graph.
func CollectFindings(ctx context.Context, req Request) ([]vulndedup.Finding, error) {
	if len(req.Findings) > 0 {
		return req.Findings, nil
	}
	if len(req.Vulnerabilities) > 0 {
		return vulndedup.FindingsFromLegacyVulnerabilities(req.Vulnerabilities), nil
	}
	if len(req.LegacyPayload) > 0 {
		return vulndedup.FindingsFromLegacyJSON(req.LegacyPayload)
	}
	return findingsFromGraph(ctx, req)
}

// Aggregate builds the full merged report and applies window pagination to the
// top-level vulnerabilities list. Summary totals are computed before
// pagination and therefore always reflect the whole filtered set.
func Aggregate(ctx context.Context, req Request) (*Response, error) {
	findings, err := CollectFindings(ctx, req)
	if err != nil {
		return nil, err
	}

	report := vulndedup.DeduplicateWithOptions(findings, req.options())

	offset, limit := req.Window.Offset, req.Window.Size
	paged := paginate(report.Vulnerabilities, offset, limit)
	pageItems := len(paged)
	report.Vulnerabilities = paged

	return &Response{
		Report:    report,
		Offset:    offset,
		Limit:     limit,
		PageItems: pageItems,
	}, nil
}

// AggregateWorkloads returns both per-cluster and logical workload rollups.
func AggregateWorkloads(ctx context.Context, req Request) (*WorkloadResponse, error) {
	findings, err := CollectFindings(ctx, req)
	if err != nil {
		return nil, err
	}

	options := req.options()
	perCluster := vulndedup.AggregateByWorkload(findings, options)

	logicalOptions := options
	logicalOptions.WorkloadScope = vulndedup.WorkloadScopeLogical
	logical := vulndedup.AggregateByWorkload(findings, logicalOptions)

	// Summary is produced by the CVE dedup pass so totals reconcile.
	report := vulndedup.DeduplicateWithOptions(findings, options)

	return &WorkloadResponse{
		Summary:          report.Summary,
		Workloads:        perCluster,
		LogicalWorkloads: logical,
	}, nil
}

// Detail returns one fully attributed, occurrence-bearing merged vulnerability
// selected by cve_id or dedup_key. It powers the image/host drill-down.
func Detail(ctx context.Context, req Request) (*vulndedup.DeduplicatedVulnerability, error) {
	findings, err := CollectFindings(ctx, req)
	if err != nil {
		return nil, err
	}

	options := req.options()
	options.IncludeOccurrences = true
	report := vulndedup.DeduplicateWithOptions(findings, options)

	for i := range report.Vulnerabilities {
		v := &report.Vulnerabilities[i]
		if req.DedupKey != "" && v.DedupKey == req.DedupKey {
			return v, nil
		}
		if req.CVEID != "" && strings.EqualFold(v.CVEID, req.CVEID) {
			return v, nil
		}
	}
	return nil, ErrVulnerabilityNotFound
}

func paginate[T any](items []T, offset, limit int) []T {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return []T{}
	}
	items = items[offset:]
	if limit > 0 && limit < len(items) {
		items = items[:limit]
	}
	return items
}
