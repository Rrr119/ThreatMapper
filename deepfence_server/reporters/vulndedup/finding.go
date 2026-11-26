// Package vulndedup implements cross-cluster vulnerability deduplication,
// attribution and workload aggregation.
//
// The package is intentionally dependency free (standard library only) so the
// aggregation logic can be unit tested and reused by every delivery channel
// (HTTP reporters, background jobs or offline reports).
//
// The central input is a flat list of Finding values. A Finding represents a
// single detection of a vulnerability on a concrete resource (container image
// or host) that belongs to a workload inside a Kubernetes cluster. Repeated
// Findings with the same CVE produced by different clusters/scans are merged
// into one DeduplicatedVulnerability while every occurrence is retained for
// drill-down.
package vulndedup

import "strings"

// DedupGranularity controls when two Findings are considered the same
// vulnerability for the merged view.
type DedupGranularity string

const (
	// DedupByCVE collapses every occurrence of the same CVE into a single
	// entry regardless of the affected package. This is the cross-cluster
	// "one CVE counted once" view required by the acceptance criteria.
	DedupByCVE DedupGranularity = "cve"

	// DedupByCVEAndPackage keeps the same CVE affecting different packages
	// (or package paths) as distinct entries, matching ThreatMapper's native
	// Vulnerability node identity (package path + package + CVE).
	DedupByCVEAndPackage DedupGranularity = "cve_package"
)

// ParseGranularity normalizes a user supplied granularity. Unknown or empty
// values fall back to DedupByCVE.
func ParseGranularity(value string) DedupGranularity {
	switch DedupGranularity(strings.ToLower(strings.TrimSpace(value))) {
	case DedupByCVEAndPackage:
		return DedupByCVEAndPackage
	case DedupByCVE:
		return DedupByCVE
	default:
		return DedupByCVE
	}
}

// Finding is one occurrence of a vulnerability. It is the flattened row that
// the graph/reporting layer is expected to produce.
type Finding struct {
	// Vulnerability identity / metadata.
	NodeID      string  `json:"node_id,omitempty"`
	CVEID       string  `json:"cve_id"`
	RuleID      string  `json:"rule_id,omitempty"`
	Severity    string  `json:"cve_severity,omitempty"`
	CVSSScore   float64 `json:"cve_cvss_score,omitempty"`
	FixedIn     string  `json:"cve_fixed_in,omitempty"`
	PackageName string  `json:"cve_caused_by_package,omitempty"`
	PackagePath string  `json:"cve_caused_by_package_path,omitempty"`
	Link        string  `json:"cve_link,omitempty"`
	Description string  `json:"cve_description,omitempty"`

	// Attribution: where the occurrence was observed.
	ClusterID   string `json:"cluster_id,omitempty"`
	ClusterName string `json:"cluster_name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`

	WorkloadID   string `json:"workload_id,omitempty"`
	WorkloadName string `json:"workload_name,omitempty"`
	WorkloadKind string `json:"workload_kind,omitempty"`

	PodID       string `json:"pod_id,omitempty"`
	PodName     string `json:"pod_name,omitempty"`
	ContainerID string `json:"container_id,omitempty"`

	ImageID     string `json:"image_id,omitempty"`
	ImageName   string `json:"image_name,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`

	HostID   string `json:"host_id,omitempty"`
	HostName string `json:"host_name,omitempty"`

	ScanID    string `json:"scan_id,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// normalizeCVE returns the canonical CVE identifier. CVE ids are
// conventionally upper case; normalizing avoids counting "cve-2024-1" and
// "CVE-2024-1" twice.
func normalizeCVE(cve string) string {
	return strings.ToUpper(strings.TrimSpace(cve))
}

func normalizeValue(value string) string {
	return strings.TrimSpace(value)
}

// Identity returns the de-duplication key of the finding for the requested
// granularity. Findings sharing an identity are merged into one entry.
//
// When the finding has no CVE id, the native node/rule id is used so that
// non-CVE findings are never collapsed into a single empty bucket.
func (f Finding) Identity(granularity DedupGranularity) string {
	cve := normalizeCVE(f.CVEID)
	if cve == "" {
		if id := normalizeValue(f.NodeID); id != "" {
			return "node:" + id
		}
		if id := normalizeValue(f.RuleID); id != "" {
			return "rule:" + id
		}
		return "unknown"
	}

	if granularity == DedupByCVEAndPackage {
		return strings.Join([]string{
			cve,
			normalizeValue(f.PackageName),
			normalizeValue(f.PackagePath),
		}, "/")
	}
	return cve
}

// DisplayCVE returns the normalized CVE id or a stable placeholder.
func (f Finding) DisplayCVE() string {
	if cve := normalizeCVE(f.CVEID); cve != "" {
		return cve
	}
	if f.RuleID != "" {
		return f.RuleID
	}
	return f.NodeID
}

// NormalizeSeverity canonicalizes a severity string to one of the ThreatMapper
// severity buckets.
func NormalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "negligible":
		return "info"
	default:
		return "unknown"
	}
}

// severityRank orders severities by urgency. Higher is more severe.
func severityRank(severity string) int {
	switch NormalizeSeverity(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
