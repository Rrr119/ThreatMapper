package vulndedup

import (
	"sort"
	"strings"
)

// Options controls deduplication and attribution behavior.
type Options struct {
	// Granularity selects the dedup identity. Defaults to DedupByCVE.
	Granularity DedupGranularity

	// ClusterIDs, when non-empty, restrict processing to the given cluster
	// ids or names.
	ClusterIDs []string
	// WorkloadIDs restricts processing to the given workload ids or names.
	WorkloadIDs []string
	// CVEIDs restricts processing to the given CVE ids.
	CVEIDs []string
	// Severities restricts processing to the given severity buckets.
	Severities []string

	// WorkloadScope selects whether workload aggregation is cluster scoped
	// (default) or rolls same namespace/kind/name across clusters.
	WorkloadScope WorkloadScope

	// IncludeOccurrences keeps every raw occurrence in the result. Defaults
	// to true when using Deduplicate; the HTTP layer may disable it for list
	// calls and page occurrences separately.
	IncludeOccurrences bool
}

// WorkloadScope controls workload identity across clusters.
type WorkloadScope string

const (
	// WorkloadScopePerCluster treats a workload in each cluster as a distinct
	// workload (cluster + namespace + kind + name/id). This is the correct
	// identity for Kubernetes workloads.
	WorkloadScopePerCluster WorkloadScope = "per_cluster"
	// WorkloadScopeLogical merges same namespace/kind/name workloads across
	// clusters into one logical workload row.
	WorkloadScopeLogical WorkloadScope = "logical"
)

// Option configures Deduplicate.
type Option func(*Options)

// WithGranularity sets the deduplication granularity.
func WithGranularity(granularity DedupGranularity) Option {
	return func(o *Options) { o.Granularity = granularity }
}

// WithClusterFilter restricts the result to the provided cluster ids/names.
func WithClusterFilter(clusters ...string) Option {
	return func(o *Options) { o.ClusterIDs = append(o.ClusterIDs, clusters...) }
}

// WithWorkloadFilter restricts the result to the provided workload ids/names.
func WithWorkloadFilter(workloads ...string) Option {
	return func(o *Options) { o.WorkloadIDs = append(o.WorkloadIDs, workloads...) }
}

// WithCVEFilter restricts the result to the provided CVE ids.
func WithCVEFilter(cves ...string) Option {
	return func(o *Options) { o.CVEIDs = append(o.CVEIDs, cves...) }
}

// WithSeverityFilter restricts the result to the provided severities.
func WithSeverityFilter(severities ...string) Option {
	return func(o *Options) { o.Severities = append(o.Severities, severities...) }
}

// WithOccurrences toggles retention of raw occurrences in the output.
func WithOccurrences(include bool) Option {
	return func(o *Options) { o.IncludeOccurrences = include }
}

// WithWorkloadScope sets the workload aggregation scope.
func WithWorkloadScope(scope WorkloadScope) Option {
	return func(o *Options) { o.WorkloadScope = scope }
}

// WithLogicalWorkloadAggregation rolls identically named workloads across
// clusters into a single row.
func WithLogicalWorkloadAggregation() Option {
	return func(o *Options) { o.WorkloadScope = WorkloadScopeLogical }
}

// DefaultOptions returns the default aggregation options: CVE level dedup with
// occurrences retained.
func DefaultOptions() Options {
	return Options{
		Granularity:        DedupByCVE,
		IncludeOccurrences: true,
		WorkloadScope:      WorkloadScopePerCluster,
	}
}

// Deduplicate merges findings that share one identity (the same CVE by
// default) across clusters and builds full attribution / drill-down data.
//
// It never mutates the input and is safe to call with an empty slice.
func Deduplicate(findings []Finding, opts ...Option) *Report {
	options := DefaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return DeduplicateWithOptions(findings, options)
}

// DeduplicateFindings is an alias for Deduplicate using default options.
func DeduplicateFindings(findings []Finding) *Report {
	return DeduplicateWithOptions(findings, DefaultOptions())
}

// DeduplicateWithOptions performs the aggregation with an explicit Options
// value.
func DeduplicateWithOptions(findings []Finding, options Options) *Report {
	if options.Granularity == "" {
		options.Granularity = DedupByCVE
	}
	if options.WorkloadScope == "" {
		options.WorkloadScope = WorkloadScopePerCluster
	}

	clusterFilter := lowerSet(options.ClusterIDs)
	workloadFilter := lowerSet(options.WorkloadIDs)
	cveFilter := upperSet(options.CVEIDs)
	severityFilter := normalizedSeveritySet(options.Severities)

	accs := make(map[string]*vulnAcc)
	globalClusters := make(stringSet)
	globalWorkloads := make(stringSet)
	globalImages := make(stringSet)
	globalHosts := make(stringSet)
	distinctCVE := make(stringSet)

	rawCount := 0

	for _, f := range findings {
		if !matchFilters(f, clusterFilter, workloadFilter, cveFilter, severityFilter) {
			continue
		}
		rawCount++

		if cve := normalizeCVE(f.CVEID); cve != "" {
			distinctCVE.add(cve)
		}

		key := f.Identity(options.Granularity)
		acc, ok := accs[key]
		if !ok {
			acc = &vulnAcc{
				key:       key,
				cve:       normalizeCVE(f.CVEID),
				ruleID:    f.RuleID,
				rep:       f,
				packages:  make(stringSet),
				clusters:  make(map[string]*clusterAcc),
				workloads: make(map[string]*workloadAcc),
				images:    make(map[string]*resourceAcc),
				hosts:     make(map[string]*resourceAcc),
			}
			accs[key] = acc
		}
		acc.add(f, options.IncludeOccurrences)

		if ck := clusterKey(f); ck != "" {
			globalClusters.add(ck)
		}
		if wk := workloadKey(f); wk != "" {
			globalWorkloads.add(wk)
		}
		if ik := imageKey(f); ik != "" {
			globalImages.add(ik)
		}
		if hk := hostKey(f); hk != "" {
			globalHosts.add(hk)
		}
	}

	vulns := make([]DeduplicatedVulnerability, 0, len(accs))
	sevCounts := SeverityCounts{}

	for _, acc := range accs {
		v := acc.build(options.IncludeOccurrences)
		bumpSeverity(&sevCounts, v.Severity)
		vulns = append(vulns, v)
	}

	sort.Slice(vulns, func(i, j int) bool {
		ri, rj := severityRank(vulns[i].Severity), severityRank(vulns[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if vulns[i].CVSSScore != vulns[j].CVSSScore {
			return vulns[i].CVSSScore > vulns[j].CVSSScore
		}
		return vulns[i].CVEID < vulns[j].CVEID
	})

	workloads := AggregateByWorkload(findings, options)
	logicalOptions := options
	logicalOptions.WorkloadScope = WorkloadScopeLogical
	logicalWorkloads := AggregateByWorkload(findings, logicalOptions)

	total := len(vulns)
	manual := len(distinctCVE.sorted())
	reconciliation := Reconciliation{
		RawFindingCount:           rawCount,
		ManualDistinctCVE:         manual,
		ReportedDeduplicatedTotal: total,
		Difference:                total - manual,
	}
	reconciliation.Match = reconciliation.Difference == 0

	report := &Report{
		Summary: Summary{
			Granularity:          options.Granularity,
			TotalFindings:        rawCount,
			TotalVulnerabilities: total,
			DistinctCVE:          manual,
			ClusterCount:         len(globalClusters),
			WorkloadCount:        len(globalWorkloads),
			ImageCount:           len(globalImages),
			HostCount:            len(globalHosts),
			SeverityCounts:       sevCounts,
			Reconciliation:       reconciliation,
		},
		Vulnerabilities:  vulns,
		Workloads:        workloads,
		LogicalWorkloads: logicalWorkloads,
	}

	return report
}

// ReconcileTotal independently computes the manual de-duplicated total
// (distinct CVE ids) for the supplied findings and compares it against
// reportedTotal. It is provided for callers that already have a report and
// want an explicit reconciliation check.
func ReconcileTotal(findings []Finding, reportedTotal int) Reconciliation {
	distinct := make(stringSet)
	raw := 0
	for _, f := range findings {
		raw++
		if cve := normalizeCVE(f.CVEID); cve != "" {
			distinct.add(cve)
		}
	}
	manual := len(distinct.sorted())
	diff := reportedTotal - manual
	return Reconciliation{
		RawFindingCount:           raw,
		ManualDistinctCVE:         manual,
		ReportedDeduplicatedTotal: reportedTotal,
		Difference:                diff,
		Match:                     diff == 0,
	}
}

// ---------------------------------------------------------------------------
// filters
// ---------------------------------------------------------------------------

func matchFilters(f Finding, clusters, workloads, cves, severities map[string]struct{}) bool {
	if len(clusters) > 0 {
		if _, ok := clusters[strings.ToLower(f.ClusterID)]; !ok {
			if _, ok := clusters[strings.ToLower(f.ClusterName)]; !ok {
				return false
			}
		}
	}
	if len(workloads) > 0 {
		if _, ok := workloads[strings.ToLower(f.WorkloadID)]; !ok {
			if _, ok := workloads[strings.ToLower(f.WorkloadName)]; !ok {
				return false
			}
		}
	}
	if len(cves) > 0 {
		if _, ok := cves[normalizeCVE(f.CVEID)]; !ok {
			return false
		}
	}
	if len(severities) > 0 {
		if _, ok := severities[NormalizeSeverity(f.Severity)]; !ok {
			return false
		}
	}
	return true
}

func lowerSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			set[v] = struct{}{}
		}
	}
	return set
}

func upperSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = normalizeCVE(v)
		if v != "" {
			set[v] = struct{}{}
		}
	}
	return set
}

func normalizedSeveritySet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if s := NormalizeSeverity(v); s != "unknown" || strings.TrimSpace(v) != "" {
			set[s] = struct{}{}
		}
	}
	return set
}

func bumpSeverity(counts *SeverityCounts, severity string) {
	switch NormalizeSeverity(severity) {
	case "critical":
		counts.Critical++
	case "high":
		counts.High++
	case "medium":
		counts.Medium++
	case "low":
		counts.Low++
	case "info":
		counts.Info++
	default:
		counts.Unknown++
	}
}

// ---------------------------------------------------------------------------
// entity keys
// ---------------------------------------------------------------------------

func clusterKey(f Finding) string {
	return firstNonEmpty(f.ClusterID, f.ClusterName)
}

func workloadKey(f Finding) string {
	return joinKey(clusterKey(f), f.Namespace, f.WorkloadKind,
		firstNonEmpty(f.WorkloadID, f.WorkloadName, f.PodName))
}

// logicalWorkloadKey identifies a workload by namespace/kind/name without the
// cluster, so the same logical service in multiple clusters rolls together.
func logicalWorkloadKey(f Finding) string {
	return joinKey(f.Namespace, f.WorkloadKind,
		firstNonEmpty(f.WorkloadName, f.WorkloadID, f.PodName))
}

// scopedWorkloadKey selects the key for the requested scope.
func scopedWorkloadKey(f Finding, scope WorkloadScope) string {
	if scope == WorkloadScopeLogical {
		return logicalWorkloadKey(f)
	}
	return workloadKey(f)
}

func joinKey(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			clean = append(clean, p)
		}
	}
	return strings.Join(clean, "/")
}

func imageKey(f Finding) string {
	return firstNonEmpty(f.ImageID, f.ImageDigest, f.ImageName)
}

func hostKey(f Finding) string {
	return firstNonEmpty(f.HostID, f.HostName)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
