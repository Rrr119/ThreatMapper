package vulndedup

import "strings"

// DeriveWorkloadFromPodName makes a best-effort attempt to recover the owning
// Kubernetes workload name/kind from a generated pod name.
//
// Examples:
//
//	checkout-7d4b8c9f6-x2k9p -> ("checkout", "Deployment")
//	agent-abcde              -> ("agent", "DaemonSet")
//	postgres-2               -> ("postgres", "StatefulSet")
//
// It is a heuristic: callers that have an explicit owner/workload identifier
// should prefer that. When nothing meaningful can be derived the pod name is
// returned with an empty kind.
func DeriveWorkloadFromPodName(podName string) (name, kind string) {
	podName = strings.TrimSpace(podName)
	if podName == "" {
		return "", ""
	}
	parts := strings.Split(podName, "-")
	if len(parts) == 0 {
		return podName, ""
	}

	// StatefulSet: <name>-<ordinal>.
	if last := parts[len(parts)-1]; isAllDigits(last) && len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-1], "-"), "StatefulSet"
	}

	// Deployment pod: <name>-<replicaset-hash>-<pod-hash>.
	if len(parts) >= 3 && isHashToken(parts[len(parts)-1]) && isHashToken(parts[len(parts)-2]) {
		return strings.Join(parts[:len(parts)-2], "-"), "Deployment"
	}

	// DaemonSet / bare replicas: <name>-<hash>.
	if len(parts) >= 2 && isHashToken(parts[len(parts)-1]) {
		return strings.Join(parts[:len(parts)-1], "-"), "DaemonSet"
	}

	return podName, ""
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isHashToken reports whether a pod-name segment looks like a generated
// ReplicaSet/pod hash (alphanumeric, containing a digit or run of lower-case
// chars, with a bounded length).
func isHashToken(s string) bool {
	if len(s) < 2 || len(s) > 10 {
		return false
	}
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
			hasLetter = true
		default:
			return false
		}
	}
	return hasLetter
}
