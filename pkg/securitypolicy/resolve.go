// Copyright 2019-2026 The Liqo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package securitypolicy

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	psaapi "k8s.io/pod-security-admission/api"
	"sigs.k8s.io/controller-runtime/pkg/client"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	fcutils "github.com/liqotech/liqo/pkg/utils/foreigncluster"
)

// Resolve returns the spec of the effective policy enforced on the pods offloaded by the given consumer cluster,
// merging the OffloadingSecurityPolicies selecting the cluster (see [Merge]). As with NetworkPolicies, a cluster
// selected by no policy is unrestricted: the privileged level is returned, consistently with Kubernetes, which enforces
// no Pod Security Standard unless configured to. Once a policy selects it, only what the policies grant is admitted.
func Resolve(ctx context.Context, cl client.Client,
	clusterID liqov1beta1.ClusterID,
) (offloadingv1beta1.OffloadingSecurityPolicySpec, error) {
	policies, err := Select(ctx, cl, clusterID)
	if err != nil {
		return offloadingv1beta1.OffloadingSecurityPolicySpec{}, err
	}
	if len(policies) == 0 {
		return offloadingv1beta1.OffloadingSecurityPolicySpec{Level: offloadingv1beta1.PodSecurityLevelPrivileged}, nil
	}
	return Merge(policies...), nil
}

// Select returns the [offloadingv1beta1.OffloadingSecurityPolicy] objects selecting the given consumer cluster, matching
// their cluster selector against the labels of its ForeignCluster. When the ForeignCluster does not exist, the
// selectors are matched against the remote cluster ID label only, so that the policies selecting the cluster by its ID
// still apply.
func Select(ctx context.Context, cl client.Client,
	clusterID liqov1beta1.ClusterID,
) ([]offloadingv1beta1.OffloadingSecurityPolicy, error) {
	clusterLabels := labels.Set{consts.RemoteClusterID: string(clusterID)}
	fc, err := fcutils.GetForeignClusterByID(ctx, cl, clusterID)
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return nil, fmt.Errorf("failed to get the ForeignCluster of cluster %q: %w", clusterID, err)
	default:
		clusterLabels = labels.Merge(fc.Labels, clusterLabels)
	}

	var policies offloadingv1beta1.OffloadingSecurityPolicyList
	if err := cl.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("failed to list the OffloadingSecurityPolicies: %w", err)
	}

	var selected []offloadingv1beta1.OffloadingSecurityPolicy
	for i := range policies.Items {
		selector, err := metav1.LabelSelectorAsSelector(&policies.Items[i].Spec.ClusterSelector)
		if err != nil {
			// The policy might be meant to restrict the cluster: failing avoids silently ignoring it.
			return nil, fmt.Errorf("invalid cluster selector of OffloadingSecurityPolicy %q: %w", policies.Items[i].Name, err)
		}
		if selector.Matches(clusterLabels) {
			selected = append(selected, policies.Items[i])
		}
	}
	return selected, nil
}

// getEffectiveLevel evaluates the provided [offloadingv1beta1.OffloadingSecurityPolicy] objects and returns the
// effective [offloadingv1beta1.PodSecurityLevel] that is enforced when they are all applied together, i.e. the
// most permissive one among those set. The policies with no level only grant allowances, and do not contribute
// to the level: when no policy sets it, it returns the restricted level, so that the selected cluster is granted only
// the allowances of the policies.
func getEffectiveLevel(policies ...offloadingv1beta1.OffloadingSecurityPolicy) offloadingv1beta1.PodSecurityLevel {
	var effective *psaapi.Level
	for i := range policies {
		if policies[i].Spec.Level == "" {
			continue
		}
		if level := parseLevel(policies[i].Spec.Level); effective == nil || psaapi.CompareLevels(level, *effective) < 0 {
			effective = &level
		}
	}

	if effective == nil {
		return offloadingv1beta1.PodSecurityLevelRestricted
	}
	return offloadingv1beta1.PodSecurityLevel(*effective)
}

// getEffectiveAllowances evaluates the provided [offloadingv1beta1.OffloadingSecurityPolicy] objects and returns the
// effective [offloadingv1beta1.OffloadingSecurityPolicyAllowances] granted when they are all applied together, i.e.
// the union of what each of them allows. When no policy is provided, it returns no allowances.
// The result shares no memory with the provided policies, and its lists are sorted and free of duplicates.
func getEffectiveAllowances(
	policies ...offloadingv1beta1.OffloadingSecurityPolicy,
) offloadingv1beta1.OffloadingSecurityPolicyAllowances {
	var effective offloadingv1beta1.OffloadingSecurityPolicyAllowances
	for i := range policies {
		effective = mergePermissiveAllowances(&effective, &policies[i].Spec.Allow)
	}

	return effective
}

// mergePermissiveAllowances returns the union of the two allowances, without modifying them.
func mergePermissiveAllowances(a, b *offloadingv1beta1.OffloadingSecurityPolicyAllowances) offloadingv1beta1.OffloadingSecurityPolicyAllowances {
	return offloadingv1beta1.OffloadingSecurityPolicyAllowances{
		HostNamespaces:     sets.List(sets.New(a.HostNamespaces...).Insert(b.HostNamespaces...)),
		Privileged:         a.Privileged || b.Privileged,
		Capabilities:       sets.List(sets.New(a.Capabilities...).Insert(b.Capabilities...)),
		HostPaths:          sets.List(sets.New(a.HostPaths...).Insert(b.HostPaths...)),
		HostPorts:          unionPortRanges(a.HostPorts, b.HostPorts),
		Sysctls:            sets.List(sets.New(a.Sysctls...).Insert(b.Sysctls...)),
		SELinuxTypes:       sets.List(sets.New(a.SELinuxTypes...).Insert(b.SELinuxTypes...)),
		UnconfinedSeccomp:  a.UnconfinedSeccomp || b.UnconfinedSeccomp,
		UnconfinedAppArmor: a.UnconfinedAppArmor || b.UnconfinedAppArmor,
		UnmaskedProcMount:  a.UnmaskedProcMount || b.UnmaskedProcMount,
		HostProcess:        a.HostProcess || b.HostProcess,
	}
}

// unionPortRanges returns the union of the two lists of port ranges, sorted and with overlapping or adjacent ranges
// merged into one, or nil when both are empty.
func unionPortRanges(a, b []offloadingv1beta1.HostPortRange) []offloadingv1beta1.HostPortRange {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}

	ranges := slices.Concat(a, b)
	slices.SortFunc(ranges, func(x, y offloadingv1beta1.HostPortRange) int {
		return cmp.Or(cmp.Compare(x.Min, y.Min), cmp.Compare(x.Max, y.Max))
	})

	merged := ranges[:1]
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if r.Min <= last.Max+1 {
			last.Max = max(last.Max, r.Max)
			continue
		}
		merged = append(merged, r)
	}

	return merged
}

// parseLevel converts the level to the pod-security-admission one. Unset and unknown levels are mapped to the most
// restrictive one, so that an invalid policy can never loosen the effective level.
func parseLevel(level offloadingv1beta1.PodSecurityLevel) psaapi.Level {
	// ParseLevel returns the restricted level along with the error for unset and unknown levels.
	parsed, _ := psaapi.ParseLevel(string(level))
	return parsed
}
