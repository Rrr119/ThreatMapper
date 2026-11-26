package vulnview

import "errors"

// ErrVulnerabilityNotFound is returned by Detail when no merged entry matches
// the requested cve_id/dedup_key within the filtered set.
var ErrVulnerabilityNotFound = errors.New("deduplicated vulnerability not found")
