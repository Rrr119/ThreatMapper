package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deepfence/ThreatMapper/deepfence_server/reporters/vulndedup"
	"github.com/deepfence/ThreatMapper/deepfence_server/reporters/vulnview"
)

func threeClusterFindings() []vulndedup.Finding {
	clusters := []struct{ id, name, host string }{
		{"cluster-a", "east", "host-a"},
		{"cluster-b", "west", "host-b"},
		{"cluster-c", "eu", "host-c"},
	}
	out := make([]vulndedup.Finding, 0, 3)
	for _, c := range clusters {
		out = append(out, vulndedup.Finding{
			CVEID:        "CVE-2024-3094",
			Severity:     "critical",
			ClusterID:    c.id,
			ClusterName:  c.name,
			Namespace:    "payments",
			WorkloadID:   "wl-checkout-" + c.id,
			WorkloadName: "checkout",
			WorkloadKind: "Deployment",
			ImageID:      "img-checkout-" + c.id,
			ImageName:    "acme/checkout:v2",
			HostID:       c.host,
			HostName:     c.host + "-name",
		})
	}
	return out
}

func postAggregation(t *testing.T, h *Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	switch path {
	case "/search/vulnerabilities/deduplicated":
		h.AggregateVulnerabilities(rec, req)
	case "/search/vulnerabilities/workload-aggregation":
		h.AggregateVulnerabilitiesByWorkload(rec, req)
	case "/search/vulnerabilities/drilldown":
		h.GetVulnerabilityDrillDown(rec, req)
	default:
		t.Fatalf("unknown path %s", path)
	}
	return rec
}

func TestHTTP_DeduplicatedView_ThreeClusters(t *testing.T) {
	h := &Handler{}
	rec := postAggregation(t, h, "/search/vulnerabilities/deduplicated", map[string]any{
		"findings": threeClusterFindings(),
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	resp := vulnview.Response{Report: &vulndedup.Report{}}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, rec.Body.String())
	}

	if resp.Summary.TotalVulnerabilities != 1 {
		t.Fatalf("same CVE across 3 clusters must count once, got %d",
			resp.Summary.TotalVulnerabilities)
	}
	if !resp.Summary.Reconciliation.Match {
		t.Errorf("totals must reconcile: %+v", resp.Summary.Reconciliation)
	}
	if len(resp.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 merged vulnerability, got %d", len(resp.Vulnerabilities))
	}
	v := resp.Vulnerabilities[0]
	if v.ClusterCount != 3 || v.HostCount != 3 || v.ImageCount != 3 {
		t.Errorf("attribution counts wrong: clusters=%d hosts=%d images=%d",
			v.ClusterCount, v.HostCount, v.ImageCount)
	}
	if len(v.Occurrences) != 3 {
		t.Errorf("expected 3 drill-down occurrences, got %d", len(v.Occurrences))
	}
}

func TestHTTP_LegacyAPIFormatIsCompatible(t *testing.T) {
	h := &Handler{}
	// Exactly the JSON shape returned by POST /search/vulnerabilities.
	legacy := []map[string]any{{
		"node_id":      "path-openssl-CVE-2024-3094",
		"cve_id":       "CVE-2024-3094",
		"cve_severity": "critical",
		"namespace":    "payments",
		"resources": []map[string]any{
			{"node_id": "cluster-a", "name": "east", "node_type": "kubernetes_cluster"},
			{"node_id": "img-1", "name": "checkout:v2", "node_type": "container_image"},
			{"node_id": "host-1", "name": "host-1", "node_type": "host", "host_name": "host-1"},
		},
	}}

	rec := postAggregation(t, h, "/search/vulnerabilities/deduplicated", map[string]any{
		"vulnerabilities": legacy,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var report vulndedup.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalVulnerabilities != 1 {
		t.Fatalf("legacy rows should dedup to 1, got %d", report.Summary.TotalVulnerabilities)
	}
	v := report.Vulnerabilities[0]
	if v.ImageCount != 1 || v.HostCount != 1 || v.ClusterCount != 1 {
		t.Errorf("legacy resource attribution wrong: %+v", v)
	}
}

func TestHTTP_WorkloadAggregationEndpoint(t *testing.T) {
	h := &Handler{}
	rec := postAggregation(t, h, "/search/vulnerabilities/workload-aggregation", map[string]any{
		"findings": threeClusterFindings(),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp vulnview.WorkloadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// Same workload id differs per cluster => 3 per-cluster rows.
	if len(resp.Workloads) != 3 {
		t.Errorf("expected 3 per-cluster workloads, got %d", len(resp.Workloads))
	}
	if len(resp.LogicalWorkloads) != 1 {
		t.Errorf("expected 1 logical workload, got %d", len(resp.LogicalWorkloads))
	}
}

func TestHTTP_DrillDownAndErrors(t *testing.T) {
	h := &Handler{}

	ok := postAggregation(t, h, "/search/vulnerabilities/drilldown", map[string]any{
		"findings": threeClusterFindings(),
		"cve_id":   "cve-2024-3094", // case-insensitive
	})
	if ok.Code != http.StatusOK {
		t.Fatalf("drilldown status=%d body=%s", ok.Code, ok.Body.String())
	}
	var detail vulndedup.DeduplicatedVulnerability
	if err := json.Unmarshal(ok.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.HostCount != 3 || len(detail.Hosts) != 3 || len(detail.Images) != 3 {
		t.Errorf("drilldown missing images/hosts: %+v", detail)
	}

	missing := postAggregation(t, h, "/search/vulnerabilities/drilldown", map[string]any{
		"findings": threeClusterFindings(),
		"cve_id":   "CVE-NOPE",
	})
	if missing.Code != http.StatusNotFound {
		t.Errorf("missing cve expected 404, got %d", missing.Code)
	}

	badRequest := postAggregation(t, h, "/search/vulnerabilities/drilldown", map[string]any{
		"findings": threeClusterFindings(),
	})
	if badRequest.Code != http.StatusBadRequest {
		t.Errorf("missing selector expected 400, got %d", badRequest.Code)
	}

	malformed := httptest.NewRequest(http.MethodPost, "/search/vulnerabilities/deduplicated",
		bytes.NewReader([]byte("{not-json")))
	malformed.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.AggregateVulnerabilities(rec, malformed)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed json expected 400, got %d", rec.Code)
	}
}
