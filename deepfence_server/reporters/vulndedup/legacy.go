package vulndedup

import (
	"encoding/json"
	"strings"
)

// LegacyResource is the subset of model.BasicNode returned inside the
// "resources" field of the existing /search/vulnerabilities API.
type LegacyResource struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	NodeType string `json:"node_type"`
	HostName string `json:"host_name"`
	Active   bool   `json:"active"`
}

// LegacyVulnerability is the subset of the existing ThreatMapper vulnerability
// JSON representation (deepfence_server/model.Vulnerability) required for
// de-duplication. Unknown fields are ignored by encoding/json.
type LegacyVulnerability struct {
	NodeID                 string           `json:"node_id"`
	CveID                  string           `json:"cve_id"`
	RuleID                 string           `json:"rule_id"`
	CveSeverity            string           `json:"cve_severity"`
	CveCvssScore           float64          `json:"cve_cvss_score"`
	CveFixedIn             string           `json:"cve_fixed_in"`
	CveCausedByPackage     string           `json:"cve_caused_by_package"`
	CveCausedByPackagePath string           `json:"cve_caused_by_package_path"`
	CveLink                string           `json:"cve_link"`
	CveDescription         string           `json:"cve_description"`
	Namespace              string           `json:"namespace"`
	Resources              []LegacyResource `json:"resources"`
}

// FindingsFromLegacyVulnerabilities converts rows returned by the existing
// POST /search/vulnerabilities API into Findings that can be de-duplicated.
//
// Each resource attached to a vulnerability yields one attributed Finding;
// vulnerabilities without resources yield a single unattributed Finding so the
// CVE is still counted exactly once.
func FindingsFromLegacyVulnerabilities(rows []LegacyVulnerability) []Finding {
	findings := make([]Finding, 0, len(rows))
	for _, row := range rows {
		base := Finding{
			NodeID:      row.NodeID,
			CVEID:       row.CveID,
			RuleID:      row.RuleID,
			Severity:    row.CveSeverity,
			CVSSScore:   row.CveCvssScore,
			FixedIn:     row.CveFixedIn,
			PackageName: row.CveCausedByPackage,
			PackagePath: row.CveCausedByPackagePath,
			Link:        row.CveLink,
			Description: row.CveDescription,
			Namespace:   row.Namespace,
		}

		if len(row.Resources) == 0 {
			findings = append(findings, base)
			continue
		}

		for _, res := range row.Resources {
			f := base
			applyLegacyResource(&f, res)
			findings = append(findings, f)
		}
	}
	return findings
}

// FindingsFromLegacyJSON parses a JSON payload that is either a bare array of
// vulnerability objects (the existing search response) or an object of the
// form {"vulnerabilities":[...]} / {"items":[...]}.
func FindingsFromLegacyJSON(payload []byte) ([]Finding, error) {
	trimmed := strings.TrimSpace(string(payload))
	if strings.HasPrefix(trimmed, "[") {
		var rows []LegacyVulnerability
		if err := json.Unmarshal(payload, &rows); err != nil {
			return nil, err
		}
		return FindingsFromLegacyVulnerabilities(rows), nil
	}

	var wrapper struct {
		Vulnerabilities []LegacyVulnerability `json:"vulnerabilities"`
		Items           []LegacyVulnerability `json:"items"`
		Data            []LegacyVulnerability `json:"data"`
	}
	if err := json.Unmarshal(payload, &wrapper); err != nil {
		return nil, err
	}
	rows := wrapper.Vulnerabilities
	if len(rows) == 0 {
		rows = wrapper.Items
	}
	if len(rows) == 0 {
		rows = wrapper.Data
	}
	return FindingsFromLegacyVulnerabilities(rows), nil
}

func applyLegacyResource(f *Finding, res LegacyResource) {
	name := firstNonEmpty(res.Name, res.NodeID)
	switch classifyNodeType(res.NodeType) {
	case "cluster":
		f.ClusterID = res.NodeID
		f.ClusterName = name
	case "image":
		f.ImageID = res.NodeID
		f.ImageName = name
	case "host":
		f.HostID = res.NodeID
		f.HostName = firstNonEmpty(res.HostName, res.Name, res.NodeID)
	case "pod":
		f.PodID = res.NodeID
		f.PodName = firstNonEmpty(res.Name, res.NodeID)
	case "container":
		f.ContainerID = res.NodeID
		if f.HostID == "" && res.HostName != "" {
			f.HostName = res.HostName
		}
	default:
		// Unknown resource type: preserve it as a host-ish attribution only
		// when a host_name is provided.
		if res.HostName != "" {
			f.HostName = res.HostName
		}
	}
}

// classifyNodeType maps the various node_type spellings used across
// ThreatMapper agents/API into a small canonical set.
func classifyNodeType(nodeType string) string {
	t := strings.ToLower(strings.TrimSpace(nodeType))
	t = strings.ReplaceAll(t, "-", "_")
	t = strings.ReplaceAll(t, " ", "_")

	switch {
	case strings.Contains(t, "kubernetes_cluster") || t == "cluster" || strings.Contains(t, "k8s_cluster"):
		return "cluster"
	case strings.Contains(t, "container_image") || strings.Contains(t, "image"):
		return "image"
	case t == "pod" || strings.Contains(t, "pod"):
		return "pod"
	case strings.Contains(t, "container"):
		return "container"
	case strings.Contains(t, "host") || t == "node" || t == "linux" || strings.Contains(t, "node"):
		return "host"
	default:
		return "unknown"
	}
}
