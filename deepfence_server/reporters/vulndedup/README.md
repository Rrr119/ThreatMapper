# Cross-cluster vulnerability de-duplication & workload aggregation

This package implements the merged multi-cluster vulnerability view. The same
CVE detected by scans in several Kubernetes clusters is counted **once**, while
every occurrence is retained for attribution and drill-down to the concrete
cluster, workload, container image and host.

It is dependency-free (standard library only) so the aggregation rules are
unit-testable without Neo4j. The Neo4j-backed feeder and HTTP wiring live in
`deepfence_server/reporters/vulnview` and
`deepfence_server/handler/vuln_aggregation.go`.

## Acceptance mapping

Given the same CVE in three clusters (`acceptance_test.go`):

- `TestAcceptance_ThreeClustersSameCVE_CountedOnce` — one merged entry,
  `summary.total_vulnerabilities == distinct CVE count`.
- `TestAcceptance_DrillDownToImagesAndHosts` — the entry exposes three clusters,
  distinct images and hosts, and `occurrences[]` carry the concrete
  image/host/scan coordinates.
- `TestAcceptance_DeduplicatedTotalMatchesManualCheck` — the reported total
  equals an independent distinct-CVE ("manual") count and
  `summary.reconciliation.match == true`.

Run everything with the repository script:

```bash
./verify_vuln_dedup.sh
```

or directly:

```bash
cd deepfence_server
go test -v ./reporters/vulndedup/
go run ./cmd/vulndedup            # human table + "verify_ok"
go run ./cmd/vulndedup -json      # full JSON report
```

## Core API

```go
report := vulndedup.Deduplicate(findings)                 // CVE identity, occurrences kept
report := vulndedup.Deduplicate(findings,
    vulndedup.WithGranularity(vulndedup.DedupByCVEAndPackage),
    vulndedup.WithClusterFilter("cluster-a"),
    vulndedup.WithSeverityFilter("critical", "high"),
)
workloads := vulndedup.AggregateWorkloads(findings,
    vulndedup.WithLogicalWorkloadAggregation())
rec := vulndedup.ReconcileTotal(findings, report.Summary.TotalVulnerabilities)
```

`Finding` is the flattened occurrence row (CVE metadata + cluster/workload/pod/
image/host coordinates). `DeduplicatedVulnerability` carries counts plus
`clusters`, `workloads`, `images`, `hosts` and the raw `occurrences`.

Two granularities are supported:

- `cve` (default): one CVE = one entry — the cross-cluster "count once" view.
- `cve_package`: same CVE on different packages/package paths stays distinct,
  matching ThreatMapper's native `packagePath-package-CVE` node identity.

## Compatibility with the existing API

The existing `POST /deepfence/search/vulnerabilities` endpoint and its response
shape are **unchanged**. Existing JSON rows can be fed straight into the
de-duplicator:

```go
findings, _ := vulndedup.FindingsFromLegacyJSON(existingSearchResponseBody)
report := vulndedup.Deduplicate(findings)
```

`FindingsFromLegacyVulnerabilities` maps the existing `cve_id`,
`cve_severity`, ... and `resources[].node_type` (`kubernetes_cluster`,
`container_image`, `host`, `pod`, `container`) into attributed findings.

## New HTTP endpoints (additive)

All are mounted under the authenticated `/deepfence/search` group and accept
the same filter/window JSON family. When the body contains no inline data they
read from Neo4j; supplying `findings` or legacy `vulnerabilities` performs
database-less aggregation.

- `POST /search/vulnerabilities/deduplicated` — merged report
  (`summary`, paginated `vulnerabilities`, per-cluster and logical
  `workloads`).
- `POST /search/vulnerabilities/workload-aggregation` — workload rollups.
- `POST /search/vulnerabilities/drilldown` — one merged CVE with all
  occurrences/images/hosts (`{"cve_id":"CVE-..."}`).

Example:

```bash
curl -s "$CONSOLE/deepfence/search/vulnerabilities/deduplicated" \
  -H "Authorization: Bearer $TOKEN" -d '{
    "granularity": "cve",
    "window": {"offset": 0, "size": 50},
    "findings": [ { "cve_id": "CVE-2024-3094",
      "cluster_id": "c1", "cluster_name": "east",
      "workload_name": "checkout", "workload_kind": "Deployment",
      "namespace": "payments",
      "image_id": "img-1", "image_name": "checkout:v2",
      "host_id": "h1", "host_name": "node-1" } ]
  }'
```
