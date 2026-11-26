package vulndedup

// EntityRef is a minimal reference to a graph entity involved in an
// attribution.
type EntityRef struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
}

// ClusterAttribution describes where a deduplicated vulnerability was found
// inside one cluster.
type ClusterAttribution struct {
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name"`

	// OccurrenceCount is the number of raw findings in this cluster.
	OccurrenceCount int `json:"occurrence_count"`
	// ImageCount / HostCount / WorkloadCount are distinct resources.
	ImageCount    int `json:"image_count"`
	HostCount     int `json:"host_count"`
	WorkloadCount int `json:"workload_count"`
}

// WorkloadAttribution describes a workload affected by a deduplicated
// vulnerability.
type WorkloadAttribution struct {
	WorkloadID   string `json:"workload_id"`
	WorkloadName string `json:"workload_name"`
	WorkloadKind string `json:"workload_kind"`
	Namespace    string `json:"namespace"`
	ClusterID    string `json:"cluster_id"`
	ClusterName  string `json:"cluster_name"`

	OccurrenceCount int `json:"occurrence_count"`
	ImageCount      int `json:"image_count"`
	HostCount       int `json:"host_count"`
}

// ResourceAttribution is a distinct image or host carrying a vulnerability,
// together with the places it was observed. It is the drill-down target.
type ResourceAttribution struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	NodeType string `json:"node_type"`
	Digest   string `json:"digest,omitempty"`

	OccurrenceCount int `json:"occurrence_count"`

	// Clusters / Workloads are where this resource was observed carrying the
	// vulnerability. Hosts is populated for images, Images for hosts.
	Clusters  []EntityRef `json:"clusters"`
	Workloads []EntityRef `json:"workloads,omitempty"`
	Hosts     []EntityRef `json:"hosts,omitempty"`
	Images    []EntityRef `json:"images,omitempty"`
}

// DeduplicatedVulnerability is one logical vulnerability (one CVE by default)
// merged from every cluster/scan occurrence.
type DeduplicatedVulnerability struct {
	// Identity of the merged entry.
	DedupKey string `json:"dedup_key"`
	CVEID    string `json:"cve_id"`
	RuleID   string `json:"rule_id,omitempty"`

	// Representative metadata (taken from the most severe occurrence).
	Severity    string  `json:"cve_severity"`
	CVSSScore   float64 `json:"cve_cvss_score"`
	FixedIn     string  `json:"cve_fixed_in,omitempty"`
	Link        string  `json:"cve_link,omitempty"`
	Description string  `json:"cve_description,omitempty"`

	// Distinct package coordinates affected by this CVE.
	PackageNames []string `json:"package_names,omitempty"`

	// Multiplicity / reach.
	OccurrenceCount int `json:"occurrence_count"`
	ClusterCount    int `json:"cluster_count"`
	WorkloadCount   int `json:"workload_count"`
	ImageCount      int `json:"image_count"`
	HostCount       int `json:"host_count"`

	// Attribution / drill-down.
	Clusters  []ClusterAttribution  `json:"clusters"`
	Workloads []WorkloadAttribution `json:"workloads"`
	Images    []ResourceAttribution `json:"images"`
	Hosts     []ResourceAttribution `json:"hosts"`

	// Occurrences retains every raw finding so callers can drill all the way
	// down to the concrete image/host/scan.
	Occurrences []Finding `json:"occurrences,omitempty"`
}

// SeverityCounts holds per-severity totals.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
}

// Map returns the severity counts as the legacy map shape used by ThreatMapper
// category counts.
func (s SeverityCounts) Map() map[string]int32 {
	return map[string]int32{
		"critical": int32(s.Critical),
		"high":     int32(s.High),
		"medium":   int32(s.Medium),
		"low":      int32(s.Low),
		"info":     int32(s.Info),
		"unknown":  int32(s.Unknown),
	}
}

// Reconciliation compares the reported de-duplicated total against an
// independently computed manual expectation (the number of distinct CVE ids).
type Reconciliation struct {
	// RawFindingCount is the number of input occurrence rows.
	RawFindingCount int `json:"raw_finding_count"`
	// ManualDistinctCVE is the "human checked" expectation: distinct CVE ids.
	ManualDistinctCVE int `json:"manual_distinct_cve"`
	// ReportedDeduplicatedTotal is what the aggregation produced.
	ReportedDeduplicatedTotal int `json:"reported_deduplicated_total"`
	// Difference is Reported - Manual. Zero means the totals agree.
	Difference int `json:"difference"`
	// Match is true when Difference == 0.
	Match bool `json:"match"`
}

// Summary contains the headline, de-duplicated counts.
type Summary struct {
	Granularity DedupGranularity `json:"granularity"`

	// TotalFindings is the raw occurrence count (what the legacy API would
	// count), kept for comparison.
	TotalFindings int `json:"total_findings"`

	// TotalVulnerabilities is the de-duplicated total. Under DedupByCVE this
	// equals the number of distinct CVEs and is the acceptance number.
	TotalVulnerabilities int `json:"total_vulnerabilities"`

	// DistinctCVE is the number of distinct CVE ids irrespective of
	// granularity; it is the manual reconciliation reference.
	DistinctCVE int `json:"distinct_cve"`

	ClusterCount  int `json:"cluster_count"`
	WorkloadCount int `json:"workload_count"`
	ImageCount    int `json:"image_count"`
	HostCount     int `json:"host_count"`

	// SeverityCounts counts each de-duplicated vulnerability once.
	SeverityCounts SeverityCounts `json:"severity_counts"`

	Reconciliation Reconciliation `json:"reconciliation"`
}

// WorkloadSummary aggregates de-duplicated vulnerability counts for one
// workload.
type WorkloadSummary struct {
	WorkloadID   string `json:"workload_id"`
	WorkloadName string `json:"workload_name"`
	WorkloadKind string `json:"workload_kind"`
	Namespace    string `json:"namespace"`
	ClusterID    string `json:"cluster_id"`
	ClusterName  string `json:"cluster_name"`

	// ClusterCount is > 1 when the same logical workload is rolled up across
	// clusters (only with WorkloadScopeLogical). Clusters lists them.
	ClusterCount int         `json:"cluster_count"`
	Clusters     []EntityRef `json:"clusters,omitempty"`

	// OccurrenceCount counts raw findings belonging to the workload.
	OccurrenceCount int `json:"occurrence_count"`
	// UniqueCVE is the number of distinct CVEs in the workload.
	UniqueCVE int `json:"unique_cves"`
	// ImageCount / HostCount are distinct resources for the workload.
	ImageCount int `json:"image_count"`
	HostCount  int `json:"host_count"`

	SeverityCounts SeverityCounts `json:"severity_counts"`

	// CVEs lists the distinct CVE ids (sorted) for drill-down.
	CVEs []string `json:"cves,omitempty"`
}

// Report is the complete cross-cluster, de-duplicated vulnerability view.
type Report struct {
	Summary         Summary                     `json:"summary"`
	Vulnerabilities []DeduplicatedVulnerability `json:"vulnerabilities"`
	Workloads       []WorkloadSummary           `json:"workloads"`

	// LogicalWorkloads optionally rolls same namespace/kind/name workloads
	// together across clusters. Populated by AggregateLogicalWorkloads.
	LogicalWorkloads []WorkloadSummary `json:"logical_workloads,omitempty"`
}
