package vulnview

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_server/reporters/vulndedup"
	"github.com/deepfence/ThreatMapper/deepfence_utils/directory"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// findingsQuery flattens vulnerability detections together with the scanned
// resource, host, cluster and kubernetes metadata.
//
// Relationship conventions (see reporters/scan and reporters/lookup):
//
//	(VulnerabilityScan)-[:DETECTED]->(Vulnerability)
//	(VulnerabilityScan)-[:SCANNED]->(scanned node)
//	(Node/host)-[:HOSTS]->(ContainerImage|Container)
//	(KubernetesCluster)-[:INSTANCIATE]->(Node/host)
//
// Every topology join is OPTIONAL so incomplete graph data never drops a CVE.
const findingsQuery = `
	MATCH (s:VulnerabilityScan)-[rd:DETECTED]->(v:Vulnerability)
	WHERE COALESCE(rd.masked, false) = false
	  AND COALESCE(v.masked, false) = false
	OPTIONAL MATCH (v)-[:IS]->(rule:VulnerabilityStub)
	OPTIONAL MATCH (s)-[:SCANNED]->(scanned)
	OPTIONAL MATCH (host:Node)-[:HOSTS]->(scanned)
	OPTIONAL MATCH (cluster:KubernetesCluster)-[:INSTANCIATE]->(host)
	OPTIONAL MATCH (container:Container)
		WHERE scanned IS NOT NULL
		  AND (container.node_id = scanned.node_id
		       OR container.docker_image_id = scanned.node_id)
	WITH s, v, rule, scanned, host, cluster, container
	LIMIT 100000
	RETURN
		v.node_id                                   AS node_id,
		v.cve_id                                    AS cve_id,
		COALESCE(v.cve_severity, '')                AS severity,
		COALESCE(v.cve_cvss_score, rule.cve_cvss_score, 0) AS cvss_score,
		COALESCE(v.cve_fixed_in, rule.cve_fixed_in, '')     AS fixed_in,
		COALESCE(v.cve_link, rule.cve_link, '')             AS link,
		COALESCE(v.cve_description, rule.cve_description, '') AS description,
		COALESCE(v.cve_caused_by_package, '')       AS package_name,
		COALESCE(v.cve_caused_by_package_path, '')  AS package_path,
		s.node_id                                   AS scan_id,
		scanned.node_id                             AS scanned_id,
		labels(scanned)                             AS scanned_labels,
		COALESCE(scanned.node_type, '')             AS scanned_type,
		COALESCE(scanned.node_name, scanned.host_name,
		         scanned.docker_image_name_with_tag,
		         scanned.docker_image_name, '')     AS scanned_name,
		COALESCE(scanned.docker_image_id, '')       AS docker_image_id,
		COALESCE(scanned.docker_image_name_with_tag,
		         scanned.docker_image_name, '')     AS docker_image_name,
		COALESCE(host.node_id, '')                  AS host_id,
		COALESCE(host.host_name, host.node_name, '') AS host_name,
		COALESCE(cluster.node_id,
		         scanned.kubernetes_cluster_id,
		         container.kubernetes_cluster_id, '') AS cluster_id,
		COALESCE(cluster.node_name, cluster.name,
		         scanned.kubernetes_cluster_name,
		         container.kubernetes_cluster_name, '') AS cluster_name,
		COALESCE(scanned.kubernetes_namespace,
		         container.kubernetes_namespace, '') AS namespace,
		COALESCE(container.node_id, '')             AS container_id,
		COALESCE(container.pod_name, scanned.pod_name, '') AS pod_name,
		COALESCE(container.docker_labels, '')        AS docker_labels,
		COALESCE(v.updated_at, 0)                   AS updated_at
`

func findingsFromGraph(ctx context.Context, req Request) ([]vulndedup.Finding, error) {
	driver, err := directory.Neo4jClient(ctx)
	if err != nil {
		return nil, err
	}

	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	tx, err := session.BeginTransaction(ctx, neo4j.WithTxTimeout(30*time.Second))
	if err != nil {
		return nil, err
	}
	defer tx.Close(ctx)

	result, err := tx.Run(ctx, findingsQuery, map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	records, err := result.Collect(ctx)
	if err != nil {
		return nil, err
	}

	findings := make([]vulndedup.Finding, 0, len(records))
	for _, rec := range records {
		findings = append(findings, recordToFinding(rec))
	}
	return findings, nil
}

func recordToFinding(rec *neo4j.Record) vulndedup.Finding {
	get := func(key string) any {
		val, _ := rec.Get(key)
		return val
	}

	f := vulndedup.Finding{
		NodeID:      asString(get("node_id")),
		CVEID:       asString(get("cve_id")),
		Severity:    asString(get("severity")),
		CVSSScore:   asFloat(get("cvss_score")),
		FixedIn:     asString(get("fixed_in")),
		Link:        asString(get("link")),
		Description: asString(get("description")),
		PackageName: asString(get("package_name")),
		PackagePath: asString(get("package_path")),
		ScanID:      asString(get("scan_id")),
		HostID:      asString(get("host_id")),
		HostName:    asString(get("host_name")),
		ClusterID:   asString(get("cluster_id")),
		ClusterName: asString(get("cluster_name")),
		Namespace:   asString(get("namespace")),
		ContainerID: asString(get("container_id")),
		PodName:     asString(get("pod_name")),
		UpdatedAt:   asInt64(get("updated_at")),
	}

	scannedID := asString(get("scanned_id"))
	scannedName := asString(get("scanned_name"))
	scannedType := asString(get("scanned_type"))
	labels := asStringSlice(get("scanned_labels"))
	dockerImageID := asString(get("docker_image_id"))
	dockerImageName := asString(get("docker_image_name"))

	isImage := containsFold(scannedType, "image") || containsLabel(labels, "ContainerImage")
	isHost := containsFold(scannedType, "host") || containsFold(scannedType, "node") ||
		containsLabel(labels, "Node")

	switch {
	case isImage:
		f.ImageID = scannedID
		f.ImageName = firstNonEmpty(dockerImageName, scannedName, scannedID)
	case isHost:
		if f.HostID == "" {
			f.HostID = scannedID
		}
		if f.HostName == "" {
			f.HostName = scannedName
		}
	default:
		// Container/Pod/other scanned node: image coordinates live in the
		// denormalized docker_image_* properties.
		if dockerImageID != "" {
			f.ImageID = dockerImageID
			f.ImageName = firstNonEmpty(dockerImageName, dockerImageID)
		}
		if strings.EqualFold(scannedType, "container") || containsLabel(labels, "Container") {
			if f.ContainerID == "" {
				f.ContainerID = scannedID
			}
		}
		if f.HostName == "" {
			f.HostName = scannedName
		}
	}

	// Workload attribution: prefer an explicit pod name, then kubernetes labels.
	if f.PodName == "" {
		f.PodName = podFromLabels(asString(get("docker_labels")))
	}
	if f.PodName != "" {
		if name, kind := vulndedup.DeriveWorkloadFromPodName(f.PodName); name != "" {
			f.WorkloadName = name
			f.WorkloadKind = kind
		}
	}

	return f
}

func podFromLabels(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || (!strings.HasPrefix(raw, "{") && !strings.HasPrefix(raw, "map[")) {
		return ""
	}
	var labels map[string]interface{}
	if strings.HasPrefix(raw, "{") {
		if err := json.Unmarshal([]byte(raw), &labels); err != nil {
			return ""
		}
	} else {
		return ""
	}
	for _, key := range []string{
		"io.kubernetes.pod.name",
		"pod_name",
		"pod",
	} {
		if v, ok := labels[key]; ok {
			return asString(v)
		}
	}
	return ""
}

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if strings.EqualFold(l, want) {
			return true
		}
	}
	return false
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func asString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func asFloat(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	default:
		return 0
	}
}

func asInt64(v any) int64 {
	switch x := v.(type) {
	case nil:
		return 0
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	default:
		return 0
	}
}

func asStringSlice(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []string:
		return x
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, asString(item))
		}
		return out
	default:
		return nil
	}
}
