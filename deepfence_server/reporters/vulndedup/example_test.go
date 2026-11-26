package vulndedup

import "fmt"

// ExampleDeduplicate prints the acceptance scenario: one CVE observed by three
// clusters is counted once while remaining drill-down rich. The Output block is
// executed and checked by "go test".
func ExampleDeduplicate() {
	report := Deduplicate(threeClusterFixture())

	fmt.Printf("raw=%d deduped=%d manual=%d reconcile=%v\n",
		report.Summary.TotalFindings,
		report.Summary.TotalVulnerabilities,
		report.Summary.Reconciliation.ManualDistinctCVE,
		report.Summary.Reconciliation.Match)

	headline := findVuln(report, "CVE-2024-3094")
	fmt.Printf("%s occurrences=%d clusters=%d images=%d hosts=%d\n",
		headline.CVEID,
		headline.OccurrenceCount,
		headline.ClusterCount,
		headline.ImageCount,
		headline.HostCount)

	logical := AggregateWorkloads(threeClusterFixture(), WithLogicalWorkloadAggregation())
	for _, w := range logical {
		fmt.Printf("workload=%s clusters=%d unique_cves=%d\n",
			w.WorkloadName, w.ClusterCount, w.UniqueCVE)
	}

	// Unordered output:
	// raw=6 deduped=3 manual=3 reconcile=true
	// CVE-2024-3094 occurrences=3 clusters=3 images=3 hosts=3
	// workload=checkout clusters=3 unique_cves=2
	// workload=ledger clusters=2 unique_cves=1
}
