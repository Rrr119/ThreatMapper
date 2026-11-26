// Command vulndedup is a dependency-free runner for the cross-cluster
// vulnerability de-duplication / attribution engine.
//
// With no arguments it executes the three-cluster acceptance scenario: the
// same CVE observed in three clusters is counted once and can be drilled down
// to concrete images and hosts. It exits non-zero if the de-duplicated total
// does not reconcile with the manual distinct-CVE count.
//
// It can also aggregate a JSON file:
//
//	go run ./cmd/vulndedup -f findings.json
//	go run ./cmd/vulndedup -f legacy-search-response.json -json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/deepfence/ThreatMapper/deepfence_server/reporters/vulndedup"
)

func main() {
	file := flag.String("f", "", "JSON file with {\"findings\":[...]} or a legacy /search/vulnerabilities payload")
	asJSON := flag.Bool("json", false, "print the full report as JSON")
	logical := flag.Bool("logical-workloads", false, "roll same-named workloads across clusters together")
	flag.Parse()

	var findings []vulndedup.Finding
	var err error
	if *file != "" {
		findings, err = loadFindings(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		findings = demoFindings()
	}

	opts := []vulndedup.Option{vulndedup.WithOccurrences(true)}
	if *logical {
		opts = append(opts, vulndedup.WithLogicalWorkloadAggregation())
	}
	report := vulndedup.Deduplicate(findings, opts...)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "encode failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		printReport(report)
	}

	if !report.Summary.Reconciliation.Match {
		fmt.Printf("RECONCILE_FAILED reported=%d manual=%d\n",
			report.Summary.Reconciliation.ReportedDeduplicatedTotal,
			report.Summary.Reconciliation.ManualDistinctCVE)
		os.Exit(2)
	}

	if *file == "" {
		fmt.Println("verify_ok: 3 clusters, same CVE counted once, drill-down and totals reconcile")
	}
}

func loadFindings(path string) ([]vulndedup.Finding, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		Findings []vulndedup.Finding `json:"findings"`
	}
	if err := json.Unmarshal(payload, &wrapper); err == nil && len(wrapper.Findings) > 0 {
		return wrapper.Findings, nil
	}

	return vulndedup.FindingsFromLegacyJSON(payload)
}

func printReport(report *vulndedup.Report) {
	s := report.Summary
	fmt.Printf("Cross-cluster vulnerability view (granularity=%s)\n", s.Granularity)
	fmt.Printf("raw_occurrences=%d  deduplicated_total=%d  distinct_cve_manual=%d  reconcile=%v\n\n",
		s.TotalFindings, s.TotalVulnerabilities, s.Reconciliation.ManualDistinctCVE,
		s.Reconciliation.Match)
	fmt.Printf("clusters=%d workloads=%d images=%d hosts=%d\n\n",
		s.ClusterCount, s.WorkloadCount, s.ImageCount, s.HostCount)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "CVE\tSEVERITY\tOCC\tCLUSTERS\tWORKLOADS\tIMAGES\tHOSTS")
	for _, v := range report.Vulnerabilities {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
			v.CVEID, v.Severity, v.OccurrenceCount, v.ClusterCount,
			v.WorkloadCount, v.ImageCount, v.HostCount)
	}
	w.Flush()

	for _, v := range report.Vulnerabilities {
		if v.CVEID != "CVE-2024-3094" {
			continue
		}
		fmt.Printf("\nDrill-down for %s:\n", v.CVEID)
		for _, img := range v.Images {
			fmt.Printf("  image: %s (%s) occurrences=%d\n", img.Name, img.NodeID, img.OccurrenceCount)
		}
		for _, host := range v.Hosts {
			fmt.Printf("  host:  %s (%s) clusters=%v\n", host.Name, host.NodeID, refNames(host.Clusters))
		}
	}

	fmt.Println("\nWorkload aggregation (per cluster):")
	ww := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(ww, "CLUSTER\tNAMESPACE\tWORKLOAD\tKIND\tUNIQUE_CVE\tOCC")
	for _, wl := range report.Workloads {
		fmt.Fprintf(ww, "%s\t%s\t%s\t%s\t%d\t%d\n",
			wl.ClusterName, wl.Namespace, wl.WorkloadName, wl.WorkloadKind,
			wl.UniqueCVE, wl.OccurrenceCount)
	}
	ww.Flush()
}

func refNames(refs []vulndedup.EntityRef) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Name != "" {
			names = append(names, r.Name)
		} else {
			names = append(names, r.NodeID)
		}
	}
	return names
}

func demoFindings() []vulndedup.Finding {
	type cluster struct{ id, name, host string }
	clusters := []cluster{
		{"cluster-a", "prod-east", "host-a-1"},
		{"cluster-b", "prod-west", "host-b-1"},
		{"cluster-c", "prod-eu", "host-c-1"},
	}

	var findings []vulndedup.Finding
	add := func(c cluster, cve, sev, workload, image string) {
		findings = append(findings, vulndedup.Finding{
			CVEID:        cve,
			Severity:     sev,
			CVSSScore:    9.8,
			ClusterID:    c.id,
			ClusterName:  c.name,
			Namespace:    "payments",
			WorkloadID:   "wl-" + workload + "-" + c.id,
			WorkloadName: workload,
			WorkloadKind: "Deployment",
			ImageID:      "img-" + workload + "-" + c.id,
			ImageName:    image,
			HostID:       c.host,
			HostName:     c.host + ".internal",
			ScanID:       "scan-" + c.id,
		})
	}

	for i, c := range clusters {
		add(c, "CVE-2024-3094", "critical", "checkout", "acme/checkout:v2.4.0")
		if i < 2 {
			add(c, "CVE-2024-1111", "high", "ledger", "acme/ledger:v1.9.1")
		}
		if i == 0 {
			add(c, "CVE-2024-2222", "medium", "checkout", "acme/checkout:v2.4.0")
		}
	}
	return findings
}
