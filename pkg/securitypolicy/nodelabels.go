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
	"math"
	"slices"

	psaapi "k8s.io/pod-security-admission/api"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
)

// The labels advertising the effective policy enforced by a provider cluster on a consumer cluster, set on the
// corresponding virtual node, so that the consumer cluster can schedule there only the pods the provider admits.
const (
	// NodeLabelPrefix is the prefix of the labels advertising the effective policy.
	NodeLabelPrefix = consts.SecurityPolicyNodeLabelPrefix
	// LevelNodeLabel is the label advertising the effective level.
	LevelNodeLabel = NodeLabelPrefix + "level"

	// FeatureAllowed is the value of a feature label when the feature is allowed without restrictions.
	FeatureAllowed = "allowed"
	// FeaturePartial is the value of a feature label when only some values of the feature are allowed
	// (e.g., some capabilities only): the provider cluster still checks the pod upon its offloading.
	FeaturePartial = "partial"
)

// Feature is a control of the baseline level, which the policy can relax. Its label is set only when relaxed.
type Feature string

// The features of the baseline level, one for each field of [offloadingv1beta1.OffloadingSecurityPolicyAllowances].
const (
	FeatureHostNetwork        Feature = "host-network"
	FeatureHostPID            Feature = "host-pid"
	FeatureHostIPC            Feature = "host-ipc"
	FeaturePrivileged         Feature = "privileged"
	FeatureCapabilities       Feature = "capabilities"
	FeatureHostPaths          Feature = "host-paths"
	FeatureHostPorts          Feature = "host-ports"
	FeatureSysctls            Feature = "sysctls"
	FeatureSELinuxTypes       Feature = "selinux-types"
	FeatureUnconfinedSeccomp  Feature = "unconfined-seccomp"
	FeatureUnconfinedAppArmor Feature = "unconfined-apparmor"
	FeatureUnmaskedProcMount  Feature = "unmasked-proc-mount"
	FeatureHostProcess        Feature = "host-process"
)

// Features lists all the features, i.e. all the controls of the baseline level the policy can relax.
var Features = []Feature{
	FeatureHostNetwork, FeatureHostPID, FeatureHostIPC, FeaturePrivileged, FeatureCapabilities, FeatureHostPaths,
	FeatureHostPorts, FeatureSysctls, FeatureSELinuxTypes, FeatureUnconfinedSeccomp, FeatureUnconfinedAppArmor,
	FeatureUnmaskedProcMount, FeatureHostProcess,
}

// NodeLabel returns the label advertising whether the feature is allowed.
func (f Feature) NodeLabel() string {
	return NodeLabelPrefix + string(f)
}

// NodeLabels returns the labels advertising the given effective policy (as returned by [Resolve]): its level, and the
// features it relaxes, either fully ([FeatureAllowed]) or partially ([FeaturePartial]). All the features are allowed
// at the privileged level, while the label of the features that are not relaxed is not set.
func NodeLabels(policy *offloadingv1beta1.OffloadingSecurityPolicySpec) map[string]string {
	level := parseLevel(policy.Level)
	labels := map[string]string{LevelNodeLabel: string(level)}
	for feature, value := range featureValues(level == psaapi.LevelPrivileged, &policy.Allow) {
		if value != "" {
			labels[feature.NodeLabel()] = value
		}
	}
	return labels
}

// featureValues returns the label value of each feature, or the empty string if not relaxed.
func featureValues(privileged bool, allow *allowances) map[Feature]string {
	if privileged {
		values := make(map[Feature]string, len(Features))
		for _, feature := range Features {
			values[feature] = FeatureAllowed
		}
		return values
	}

	allowed := func(relaxed bool) string {
		if relaxed {
			return FeatureAllowed
		}
		return ""
	}
	partially := func(relaxed, all bool) string {
		switch {
		case all:
			return FeatureAllowed
		case relaxed:
			return FeaturePartial
		default:
			return ""
		}
	}

	return map[Feature]string{
		FeatureHostNetwork:        allowed(slices.Contains(allow.HostNamespaces, offloadingv1beta1.HostNamespaceNetwork)),
		FeatureHostPID:            allowed(slices.Contains(allow.HostNamespaces, offloadingv1beta1.HostNamespacePID)),
		FeatureHostIPC:            allowed(slices.Contains(allow.HostNamespaces, offloadingv1beta1.HostNamespaceIPC)),
		FeaturePrivileged:         allowed(allow.Privileged),
		FeatureCapabilities:       partially(len(allow.Capabilities) > 0, false),
		FeatureHostPaths:          partially(len(allow.HostPaths) > 0, slices.Contains(allow.HostPaths, "/")),
		FeatureHostPorts:          partially(len(allow.HostPorts) > 0, hostPortAllowedAll(allow.HostPorts)),
		FeatureSysctls:            partially(len(allow.Sysctls) > 0, slices.Contains(allow.Sysctls, "*")),
		FeatureSELinuxTypes:       partially(len(allow.SELinuxTypes) > 0, false),
		FeatureUnconfinedSeccomp:  allowed(allow.UnconfinedSeccomp),
		FeatureUnconfinedAppArmor: allowed(allow.UnconfinedAppArmor),
		FeatureUnmaskedProcMount:  allowed(allow.UnmaskedProcMount),
		FeatureHostProcess:        allowed(allow.HostProcess),
	}
}

// hostPortAllowedAll returns whether a single range of the given ones (as merged by [Merge]) covers all the ports.
func hostPortAllowedAll(ranges []offloadingv1beta1.HostPortRange) bool {
	for _, r := range ranges {
		if r.Min <= 1 && r.Max >= math.MaxUint16 {
			return true
		}
	}
	return false
}
