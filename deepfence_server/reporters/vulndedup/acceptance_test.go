package vulndedup

import (
	"fmt"
	"sort"
	"testing"
)

type fixtureCluster struct {
	id, name, hostID, hostName string
}

// threeClusterFixture builds a deterministic estate with three clusters.
//
// CVE-2024-3094 (the headline CVE) runs in every cluster through the
// "checkout" workload on a concrete image and host. Two extra CVEs have
// narrower reach so totals are non trivial:
//
//	CVE-2024-3094 -> cluster-a, cluster-b, cluster-c (3 occurrences)
//	CVE-2024-1111 -> cluster-a, cluster-b            (2 occurrences)
//	CVE-2024-2222 -> cluster-a                       (1 occurrence)
//
// Raw rows: 6. Distinct CVEs (manual count): 3.
func threeClusterFixture() []Finding {
	clusters := []fixtureCluster{
		{"cluster-a", "prod-east", "host-a-1", "node-east-1"},
		{"cluster-b", "prod-west", "host-b-1", "node-west-1"},
		{"cluster-c", "prod-eu", "host-c-1", "node-eu-1"},
	}

	var findings []Finding
	add := func(c fixtureCluster, cve, sev, wl, imageID, imageName string) {
		findings = append(findings, Finding{
			CVEID:        cve,
			Severity:     sev,
			CVSSScore:    9.8,
			ClusterID:    c.id,
			ClusterName:  c.name,
			Namespace:    "payments",
			WorkloadID:   "wl-" + wl + "-" + c.id,
			WorkloadName: wl,
			WorkloadKind: "Deployment",
			ImageID:      imageID,
			ImageName:    imageName,
			HostID:       c.hostID,
			HostName:     c.hostName,
			ScanID:       "scan-" + c.id,
		})
	}

	for i, c := range clusters {
		// Headline CVE everywhere, same image content but a per-cluster
		// runtime image node id to prove drill-down handles both.
		add(c, "CVE-2024-3094", "critical", "checkout",
			fmt.Sprintf("img-checkout-%s", c.id), "acme/checkout:v2.4.0")

		if i < 2 {
			add(c, "CVE-2024-1111", "high", "ledger",
				fmt.Sprintf("img-ledger-%s", c.id), "acme/ledger:v1.9.1")
		}
		if i == 0 {
			add(c, "CVE-2024-2222", "medium", "checkout",
				fmt.Sprintf("img-checkout-%s", c.id), "acme/checkout:v2.4.0")
		}
	}

	return findings
}

// manualDistinctCVEs is the "human checked" total: count distinct CVE ids with
// an explicit map, independent of the aggregation code.
func manualDistinctCVEs(findings []Finding) int {
	seen := map[string]struct{}{}
	for _, f := range findings {
		if cve := normalizeCVE(f.CVEID); cve != "" {
			seen[cve] = struct{}{}
		}
	}
	return len(seen)
}

func findVuln(report *Report, cve string) *DeduplicatedVulnerability {
	for i := range report.Vulnerabilities {
		if report.Vulnerabilities[i].CVEID == cve {
			return &report.Vulnerabilities[i]
		}
	}
	return nil
}

// Acceptance: the same CVE across 3 clusters is counted exactly once.
func TestAcceptance_ThreeClustersSameCVE_CountedOnce(t *testing.T) {
	findings := threeClusterFixture()
	report := Deduplicate(findings)

	// Exactly one merged entry for the headline CVE.
	headline := findVuln(report, "CVE-2024-3094")
	if headline == nil {
		t.Fatalf("expected merged CVE-2024-3094 in report")
	}
	if report.Summary.TotalVulnerabilities != 3 {
		t.Fatalf("expected 3 deduplicated vulnerabilities, got %d",
			report.Summary.TotalVulnerabilities)
	}

	// The headline CVE is one entry but retains all three occurrences.
	if headline.OccurrenceCount != 3 {
		t.Errorf("expected 3 occurrences, got %d", headline.OccurrenceCount)
	}
	if headline.ClusterCount != 3 {
		t.Errorf("expected attribution to 3 clusters, got %d", headline.ClusterCount)
	}
	if len(headline.Clusters) != 3 {
		t.Errorf("expected 3 cluster attributions, got %d", len(headline.Clusters))
	}

	clusterNames := map[string]bool{}
	for _, c := range headline.Clusters {
		clusterNames[c.ClusterName] = true
		if c.OccurrenceCount != 1 {
			t.Errorf("cluster %s: expected 1 occurrence, got %d",
				c.ClusterName, c.OccurrenceCount)
		}
	}
	for _, want := range []string{"prod-east", "prod-west", "prod-eu"} {
		if !clusterNames[want] {
			t.Errorf("expected cluster attribution %q", want)
		}
	}
}

// Acceptance: the merged CVE can be drilled down to concrete images and hosts.
func TestAcceptance_DrillDownToImagesAndHosts(t *testing.T) {
	report := Deduplicate(threeClusterFixture())
	headline := findVuln(report, "CVE-2024-3094")
	if headline == nil {
		t.Fatal("headline CVE missing")
	}

	if headline.HostCount != 3 || len(headline.Hosts) != 3 {
		t.Fatalf("expected 3 distinct hosts, count=%d list=%d",
			headline.HostCount, len(headline.Hosts))
	}
	if headline.ImageCount != 3 || len(headline.Images) != 3 {
		t.Fatalf("expected 3 distinct image nodes, count=%d list=%d",
			headline.ImageCount, len(headline.Images))
	}

	wantHosts := map[string]bool{"host-a-1": false, "host-b-1": false, "host-c-1": false}
	for _, h := range headline.Hosts {
		if _, ok := wantHosts[h.NodeID]; !ok {
			t.Errorf("unexpected host %q", h.NodeID)
		}
		wantHosts[h.NodeID] = true
		if h.NodeType != "host" {
			t.Errorf("host node type = %q, want host", h.NodeType)
		}
		if len(h.Clusters) == 0 {
			t.Errorf("host %s missing cluster attribution", h.NodeID)
		}
	}
	for id, seen := range wantHosts {
		if !seen {
			t.Errorf("expected drill-down host %s", id)
		}
	}

	// Every retained occurrence must carry concrete image and host coordinates.
	if len(headline.Occurrences) != 3 {
		t.Fatalf("expected 3 drill-down occurrences, got %d", len(headline.Occurrences))
	}
	for _, occ := range headline.Occurrences {
		if occ.ImageID == "" || occ.ImageName == "" {
			t.Errorf("occurrence missing image: %+v", occ)
		}
		if occ.HostID == "" || occ.HostName == "" {
			t.Errorf("occurrence missing host: %+v", occ)
		}
		if occ.ClusterID == "" || occ.WorkloadName == "" {
			t.Errorf("occurrence missing cluster/workload attribution: %+v", occ)
		}
	}
}

// Acceptance: the de-duplicated total agrees with an independent manual count.
func TestAcceptance_DeduplicatedTotalMatchesManualCheck(t *testing.T) {
	findings := threeClusterFixture()
	manual := manualDistinctCVEs(findings)

	report := Deduplicate(findings)

	if manual != 3 {
		t.Fatalf("fixture sanity: manual count should be 3, got %d", manual)
	}
	if report.Summary.TotalFindings != len(findings) {
		t.Errorf("raw findings = %d, want %d", report.Summary.TotalFindings, len(findings))
	}
	if report.Summary.TotalVulnerabilities != manual {
		t.Errorf("dedup total %d != manual count %d",
			report.Summary.TotalVulnerabilities, manual)
	}
	if report.Summary.DistinctCVE != manual {
		t.Errorf("distinct cve %d != manual count %d", report.Summary.DistinctCVE, manual)
	}
	if !report.Summary.Reconciliation.Match {
		t.Errorf("reconciliation failed: %+v", report.Summary.Reconciliation)
	}
	if report.Summary.Reconciliation.Difference != 0 {
		t.Errorf("expected zero difference, got %d",
			report.Summary.Reconciliation.Difference)
	}

	// The standalone reconciler must agree as well.
	rec := ReconcileTotal(findings, report.Summary.TotalVulnerabilities)
	if !rec.Match || rec.ManualDistinctCVE != manual {
		t.Errorf("standalone reconciliation mismatch: %+v", rec)
	}
}

// Workload aggregation reports unique CVEs per workload and supports a
// cross-cluster logical rollup.
func TestWorkloadAggregation(t *testing.T) {
	findings := threeClusterFixture()

	perCluster := AggregateWorkloads(findings)

	// checkout runs in 3 clusters and ledger in 2 => 5 per-cluster workloads.
	if len(perCluster) != 5 {
		t.Fatalf("expected 5 per-cluster workloads, got %d", len(perCluster))
	}

	var checkout *WorkloadSummary
	for i := range perCluster {
		if perCluster[i].WorkloadName == "checkout" &&
			perCluster[i].ClusterID == "cluster-a" {
			checkout = &perCluster[i]
		}
	}
	if checkout == nil {
		t.Fatal("missing checkout workload in cluster-a")
	}
	// cluster-a checkout has CVE-3094 and CVE-2222 => 2 unique CVEs.
	if checkout.UniqueCVE != 2 {
		t.Errorf("checkout unique cves = %d, want 2", checkout.UniqueCVE)
	}
	if checkout.OccurrenceCount != 2 {
		t.Errorf("checkout occurrences = %d, want 2", checkout.OccurrenceCount)
	}
	if checkout.SeverityCounts.Critical != 1 || checkout.SeverityCounts.Medium != 1 {
		t.Errorf("unexpected severity counts: %+v", checkout.SeverityCounts)
	}

	logical := AggregateWorkloads(findings, WithLogicalWorkloadAggregation())
	names := map[string]*WorkloadSummary{}
	for i := range logical {
		names[logical[i].WorkloadName] = &logical[i]
	}
	if len(logical) != 2 {
		t.Fatalf("expected 2 logical workloads (checkout, ledger), got %d: %v",
			len(logical), workloadNames(logical))
	}
	co := names["checkout"]
	if co == nil {
		t.Fatal("missing logical checkout workload")
	}
	if co.ClusterCount != 3 {
		t.Errorf("logical checkout cluster count = %d, want 3", co.ClusterCount)
	}
	// Across all clusters checkout carries CVE-3094 and CVE-2222.
	if co.UniqueCVE != 2 {
		t.Errorf("logical checkout unique cves = %d, want 2", co.UniqueCVE)
	}
}

func workloadNames(ws []WorkloadSummary) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.WorkloadName)
	}
	sort.Strings(out)
	return out
}

// CVE+package granularity keeps same CVE on different packages distinct while
// default CVE granularity merges them.
func TestGranularity_CVEAndPackage(t *testing.T) {
	findings := []Finding{
		{CVEID: "CVE-2024-9", PackageName: "openssl", ClusterID: "c1", HostID: "h1"},
		{CVEID: "CVE-2024-9", PackageName: "libssl", ClusterID: "c2", HostID: "h2"},
		{CVEID: "cve-2024-9", PackageName: "openssl", ClusterID: "c3", HostID: "h3"},
	}

	cveView := Deduplicate(findings)
	if cveView.Summary.TotalVulnerabilities != 1 {
		t.Fatalf("CVE granularity should merge to 1, got %d",
			cveView.Summary.TotalVulnerabilities)
	}
	if cveView.Summary.ClusterCount != 3 {
		t.Errorf("expected 3 clusters, got %d", cveView.Summary.ClusterCount)
	}

	pkgView := Deduplicate(findings, WithGranularity(DedupByCVEAndPackage))
	// openssl (two rows, one key after CVE normalization) and libssl => 2.
	if pkgView.Summary.TotalVulnerabilities != 2 {
		t.Fatalf("package granularity expected 2 entries, got %d",
			pkgView.Summary.TotalVulnerabilities)
	}
}

// Filtering must not break reconciliation semantics.
func TestFilters(t *testing.T) {
	findings := threeClusterFixture()

	onlyA := Deduplicate(findings, WithClusterFilter("cluster-a"))
	if onlyA.Summary.ClusterCount != 1 {
		t.Fatalf("expected 1 cluster, got %d", onlyA.Summary.ClusterCount)
	}
	// cluster-a contains all three CVEs.
	if onlyA.Summary.TotalVulnerabilities != 3 {
		t.Errorf("cluster-a total = %d, want 3", onlyA.Summary.TotalVulnerabilities)
	}

	critical := Deduplicate(findings, WithSeverityFilter("critical"))
	if critical.Summary.TotalVulnerabilities != 1 {
		t.Errorf("critical total = %d, want 1", critical.Summary.TotalVulnerabilities)
	}
}

func TestEmptyInput(t *testing.T) {
	report := Deduplicate(nil)
	if report.Summary.TotalVulnerabilities != 0 ||
		len(report.Vulnerabilities) != 0 || len(report.Workloads) != 0 {
		t.Fatalf("empty input should produce an empty report: %+v", report.Summary)
	}
	if !report.Summary.Reconciliation.Match {
		t.Error("empty report should reconcile")
	}
}
