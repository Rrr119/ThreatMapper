package vulndedup

import "sort"

type stringSet map[string]struct{}

func (s stringSet) add(value string) {
	if value == "" {
		return
	}
	s[value] = struct{}{}
}

func (s stringSet) has(value string) bool {
	_, ok := s[value]
	return ok
}

func (s stringSet) sorted() []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// refSet indexes EntityRef values by a stable key.
type refSet map[string]EntityRef

func (s refSet) add(id, name string) {
	key := firstNonEmpty(id, name)
	if key == "" {
		return
	}
	if existing, ok := s[key]; ok {
		if existing.Name == "" && name != "" {
			existing.Name = name
			s[key] = existing
		}
		return
	}
	s[key] = EntityRef{NodeID: id, Name: name}
}

func (s refSet) sorted() []EntityRef {
	out := make([]EntityRef, 0, len(s))
	for _, ref := range s {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

type clusterAcc struct {
	ref   EntityRef
	count int

	images    stringSet
	hosts     stringSet
	workloads stringSet
}

type workloadAcc struct {
	clusterID   string
	clusterName string
	namespace   string
	kind        string
	ref         EntityRef
	count       int

	images stringSet
	hosts  stringSet
	cves   stringSet
}

type resourceAcc struct {
	ref    EntityRef
	digest string
	count  int

	clusters  refSet
	workloads refSet
	hosts     refSet
	images    refSet
}

type vulnAcc struct {
	key    string
	cve    string
	ruleID string
	rep    Finding

	count       int
	packages    stringSet
	occurrences []Finding
	clusters    map[string]*clusterAcc
	workloads   map[string]*workloadAcc
	images      map[string]*resourceAcc
	hosts       map[string]*resourceAcc
}

func (a *vulnAcc) add(f Finding, keepOccurrence bool) {
	a.count++
	a.packages.add(f.PackageName)

	if keepOccurrence {
		a.occurrences = append(a.occurrences, f)
	}

	// Representative metadata: prefer the most severe / highest scoring row.
	if severityRank(f.Severity) > severityRank(a.rep.Severity) ||
		(NormalizeSeverity(f.Severity) == NormalizeSeverity(a.rep.Severity) && f.CVSSScore > a.rep.CVSSScore) {
		a.rep = f
	}

	if ck := clusterKey(f); ck != "" {
		c, ok := a.clusters[ck]
		if !ok {
			c = &clusterAcc{
				ref:       EntityRef{NodeID: f.ClusterID, Name: f.ClusterName},
				images:    make(stringSet),
				hosts:     make(stringSet),
				workloads: make(stringSet),
			}
			a.clusters[ck] = c
		}
		c.count++
		c.images.add(imageKey(f))
		c.hosts.add(hostKey(f))
		c.workloads.add(workloadKey(f))
	}

	if wk := workloadKey(f); wk != "" {
		w, ok := a.workloads[wk]
		if !ok {
			w = &workloadAcc{
				ref:         EntityRef{NodeID: f.WorkloadID, Name: f.WorkloadName},
				clusterID:   f.ClusterID,
				clusterName: f.ClusterName,
				namespace:   f.Namespace,
				kind:        f.WorkloadKind,
				images:      make(stringSet),
				hosts:       make(stringSet),
				cves:        make(stringSet),
			}
			a.workloads[wk] = w
		}
		w.count++
		w.images.add(imageKey(f))
		w.hosts.add(hostKey(f))
		w.cves.add(normalizeCVE(f.CVEID))
	}

	if ik := imageKey(f); ik != "" {
		img, ok := a.images[ik]
		if !ok {
			img = &resourceAcc{
				ref:       EntityRef{NodeID: f.ImageID, Name: f.ImageName},
				digest:    f.ImageDigest,
				clusters:  make(refSet),
				workloads: make(refSet),
				hosts:     make(refSet),
				images:    make(refSet),
			}
			a.images[ik] = img
		}
		img.count++
		img.clusters.add(f.ClusterID, f.ClusterName)
		img.workloads.add(f.WorkloadID, f.WorkloadName)
		img.hosts.add(f.HostID, f.HostName)
	}

	if hk := hostKey(f); hk != "" {
		h, ok := a.hosts[hk]
		if !ok {
			h = &resourceAcc{
				ref:       EntityRef{NodeID: f.HostID, Name: f.HostName},
				clusters:  make(refSet),
				workloads: make(refSet),
				hosts:     make(refSet),
				images:    make(refSet),
			}
			a.hosts[hk] = h
		}
		h.count++
		h.clusters.add(f.ClusterID, f.ClusterName)
		h.workloads.add(f.WorkloadID, f.WorkloadName)
		h.images.add(f.ImageID, f.ImageName)
	}
}

func (a *vulnAcc) build(includeOccurrences bool) DeduplicatedVulnerability {
	out := DeduplicatedVulnerability{
		DedupKey:        a.key,
		CVEID:           firstNonEmpty(a.cve, a.rep.CVEID),
		RuleID:          firstNonEmpty(a.ruleID, a.rep.RuleID),
		Severity:        NormalizeSeverity(a.rep.Severity),
		CVSSScore:       a.rep.CVSSScore,
		FixedIn:         a.rep.FixedIn,
		Link:            a.rep.Link,
		Description:     a.rep.Description,
		PackageNames:    a.packages.sorted(),
		OccurrenceCount: a.count,
		ClusterCount:    len(a.clusters),
		WorkloadCount:   len(a.workloads),
		ImageCount:      len(a.images),
		HostCount:       len(a.hosts),
	}

	out.Clusters = buildClusterAttributions(a.clusters)
	out.Workloads = buildWorkloadAttributions(a.workloads)
	out.Images = buildResourceAttributions(a.images, "container_image")
	out.Hosts = buildResourceAttributions(a.hosts, "host")

	if includeOccurrences {
		// Stable order: cluster, workload, image, host, scan.
		occ := append([]Finding(nil), a.occurrences...)
		sort.SliceStable(occ, func(i, j int) bool {
			return occurrenceLess(occ[i], occ[j])
		})
		out.Occurrences = occ
	}

	return out
}

func occurrenceLess(x, y Finding) bool {
	keys := []func(Finding) string{
		func(f Finding) string { return f.ClusterName + f.ClusterID },
		func(f Finding) string { return f.WorkloadName + f.WorkloadID },
		func(f Finding) string { return f.ImageName + imageKey(f) },
		func(f Finding) string { return f.HostName + f.HostID },
		func(f Finding) string { return f.ScanID },
	}
	for _, k := range keys {
		if kx, ky := k(x), k(y); kx != ky {
			return kx < ky
		}
	}
	return false
}

func buildClusterAttributions(in map[string]*clusterAcc) []ClusterAttribution {
	out := make([]ClusterAttribution, 0, len(in))
	for _, c := range in {
		out = append(out, ClusterAttribution{
			ClusterID:       c.ref.NodeID,
			ClusterName:     c.ref.Name,
			OccurrenceCount: c.count,
			ImageCount:      len(c.images),
			HostCount:       len(c.hosts),
			WorkloadCount:   len(c.workloads),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		return out[i].ClusterName < out[j].ClusterName
	})
	return out
}

func buildWorkloadAttributions(in map[string]*workloadAcc) []WorkloadAttribution {
	out := make([]WorkloadAttribution, 0, len(in))
	for _, w := range in {
		out = append(out, WorkloadAttribution{
			WorkloadID:      w.ref.NodeID,
			WorkloadName:    w.ref.Name,
			WorkloadKind:    w.kind,
			Namespace:       w.namespace,
			ClusterID:       w.clusterID,
			ClusterName:     w.clusterName,
			OccurrenceCount: w.count,
			ImageCount:      len(w.images),
			HostCount:       len(w.hosts),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		return out[i].WorkloadName < out[j].WorkloadName
	})
	return out
}

func buildResourceAttributions(in map[string]*resourceAcc, nodeType string) []ResourceAttribution {
	out := make([]ResourceAttribution, 0, len(in))
	for _, r := range in {
		out = append(out, ResourceAttribution{
			NodeID:          r.ref.NodeID,
			Name:            r.ref.Name,
			NodeType:        nodeType,
			Digest:          r.digest,
			OccurrenceCount: r.count,
			Clusters:        r.clusters.sorted(),
			Workloads:       r.workloads.sorted(),
			Hosts:           r.hosts.sorted(),
			Images:          r.images.sorted(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		return out[i].Name < out[j].Name
	})
	return out
}
