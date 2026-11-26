package vulndedup

import "sort"

// AggregateWorkloads aggregates findings by workload using functional options.
func AggregateWorkloads(findings []Finding, opts ...Option) []WorkloadSummary {
	options := DefaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return AggregateByWorkload(findings, options)
}

// AggregateByWorkload groups findings by their owning workload and reports
// occurrence counts, distinct CVE totals and severity distribution of the
// distinct CVEs.
func AggregateByWorkload(findings []Finding, options Options) []WorkloadSummary {
	if options.WorkloadScope == "" {
		options.WorkloadScope = WorkloadScopePerCluster
	}
	clusterFilter := lowerSet(options.ClusterIDs)
	workloadFilter := lowerSet(options.WorkloadIDs)
	cveFilter := upperSet(options.CVEIDs)
	severityFilter := normalizedSeveritySet(options.Severities)

	type wlAcc struct {
		summary  WorkloadSummary
		images   stringSet
		hosts    stringSet
		cveSev   map[string]string
		cveRank  map[string]int
		clusters refSet
	}

	accs := make(map[string]*wlAcc)

	for _, f := range findings {
		if !matchFilters(f, clusterFilter, workloadFilter, cveFilter, severityFilter) {
			continue
		}
		wk := scopedWorkloadKey(f, options.WorkloadScope)
		if wk == "" {
			// Findings that cannot be attributed to any workload are grouped
			// under a stable unattributed bucket rather than dropped.
			wk = "unattributed"
		}

		acc, ok := accs[wk]
		if !ok {
			acc = &wlAcc{
				summary: WorkloadSummary{
					WorkloadID:   f.WorkloadID,
					WorkloadName: firstNonEmpty(f.WorkloadName, f.PodName, "unattributed"),
					WorkloadKind: f.WorkloadKind,
					Namespace:    f.Namespace,
					ClusterID:    f.ClusterID,
					ClusterName:  f.ClusterName,
				},
				images:   make(stringSet),
				hosts:    make(stringSet),
				cveSev:   make(map[string]string),
				cveRank:  make(map[string]int),
				clusters: make(refSet),
			}
			accs[wk] = acc
		}

		acc.summary.OccurrenceCount++
		acc.images.add(imageKey(f))
		acc.hosts.add(hostKey(f))
		acc.clusters.add(f.ClusterID, f.ClusterName)

		cve := normalizeCVE(f.CVEID)
		if cve == "" {
			continue
		}
		rank := severityRank(f.Severity)
		if existing, seen := acc.cveRank[cve]; !seen || rank > existing {
			acc.cveRank[cve] = rank
			acc.cveSev[cve] = NormalizeSeverity(f.Severity)
		}
	}

	out := make([]WorkloadSummary, 0, len(accs))
	for _, acc := range accs {
		s := acc.summary
		s.ImageCount = len(acc.images)
		s.HostCount = len(acc.hosts)
		s.UniqueCVE = len(acc.cveSev)
		s.Clusters = acc.clusters.sorted()
		s.ClusterCount = len(s.Clusters)
		if s.ClusterCount == 0 {
			s.ClusterCount = 1
		}
		if s.ClusterID == "" && len(s.Clusters) > 0 {
			s.ClusterID = s.Clusters[0].NodeID
			s.ClusterName = s.Clusters[0].Name
		}

		cves := make([]string, 0, len(acc.cveSev))
		for cve, sev := range acc.cveSev {
			cves = append(cves, cve)
			bumpSeverity(&s.SeverityCounts, sev)
		}
		sort.Strings(cves)
		s.CVEs = cves

		out = append(out, s)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].UniqueCVE != out[j].UniqueCVE {
			return out[i].UniqueCVE > out[j].UniqueCVE
		}
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		if out[i].ClusterName != out[j].ClusterName {
			return out[i].ClusterName < out[j].ClusterName
		}
		return out[i].WorkloadName < out[j].WorkloadName
	})

	return out
}
