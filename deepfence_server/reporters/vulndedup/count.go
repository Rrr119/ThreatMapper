package vulndedup

// CountDistinctCVEs returns the manual-check total: the number of distinct,
// normalized CVE ids in the supplied findings. Findings without a CVE id are
// ignored. This is the number a human would produce by listing unique CVEs
// across clusters and is the reconciliation reference for the deduped total.
func CountDistinctCVEs(findings []Finding) int {
	seen := make(stringSet)
	for _, f := range findings {
		seen.add(normalizeCVE(f.CVEID))
	}
	return len(seen)
}

// DeduplicatedCount is a convenience wrapper that runs CVE-level deduplication
// and returns only the merged total.
func DeduplicatedCount(findings []Finding) int {
	return Deduplicate(findings).Summary.TotalVulnerabilities
}
