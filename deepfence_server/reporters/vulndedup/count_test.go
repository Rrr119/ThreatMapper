package vulndedup

import "testing"

func TestCountDistinctCVEsAndDeduplicatedCount(t *testing.T) {
	findings := threeClusterFixture()

	if got := CountDistinctCVEs(findings); got != 3 {
		t.Errorf("CountDistinctCVEs = %d, want 3", got)
	}
	if got := DeduplicatedCount(findings); got != CountDistinctCVEs(findings) {
		t.Errorf("DeduplicatedCount = %d, want %d", got, CountDistinctCVEs(findings))
	}

	// Case and whitespace normalization must not inflate the manual count.
	normalized := []Finding{
		{CVEID: "cve-2024-1"},
		{CVEID: " CVE-2024-1 "},
		{CVEID: "CVE-2024-2"},
	}
	if got := CountDistinctCVEs(normalized); got != 2 {
		t.Errorf("normalized distinct count = %d, want 2", got)
	}
}
