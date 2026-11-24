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
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

// Requirement is one of the alternative conditions under which a provider cluster admits a pod: the effective policy
// enforced on its consumer cluster has one of the given levels, and relaxes all the given features.
type Requirement struct {
	// Levels are the levels the effective policy may have.
	Levels []offloadingv1beta1.PodSecurityLevel
	// Features are the features the effective policy must relax, sorted as [Features].
	Features []Feature
}

// Requirements returns the alternative conditions under which a provider cluster admits the pod, described by its
// metadata and spec, as evaluated by [Evaluate]: at most one for the restricted level, and one for the baseline (or
// privileged) level, or only for the privileged level, when the pod cannot be admitted otherwise. It returns nil when
// the pod complies with the restricted level without any allowance, hence any provider cluster admits it.
//
// The requirements are derived evaluating the pod as the provider cluster does, so that the two never diverge: a
// level is feasible if the pod complies with it when everything the pod uses is allowed, and a feature is required at
// that level if the pod no longer complies when only that feature is not allowed.
func Requirements(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) []Requirement {
	complies := func(level offloadingv1beta1.PodSecurityLevel, allow *allowances) bool {
		return len(Evaluate(podMetadata, podSpec, &offloadingv1beta1.OffloadingSecurityPolicySpec{Level: level, Allow: *allow})) == 0
	}
	required := func(level offloadingv1beta1.PodSecurityLevel, all *allowances) []Feature {
		var features []Feature
		for _, feature := range Features {
			if allow := withoutFeature(all, feature); !complies(level, &allow) {
				features = append(features, feature)
			}
		}
		return features
	}

	if complies(offloadingv1beta1.PodSecurityLevelRestricted, &allowances{}) {
		return nil
	}

	// The levels are monotonic: whatever is admitted at a level is admitted at the more permissive ones as well.
	all := allowEverything(podSpec)
	var requirements []Requirement
	if complies(offloadingv1beta1.PodSecurityLevelRestricted, &all) {
		requirements = append(requirements, Requirement{
			Levels:   []offloadingv1beta1.PodSecurityLevel{offloadingv1beta1.PodSecurityLevelRestricted},
			Features: required(offloadingv1beta1.PodSecurityLevelRestricted, &all),
		})
	}
	if complies(offloadingv1beta1.PodSecurityLevelBaseline, &all) {
		// Every feature is allowed at the privileged level, hence the features required at the baseline level hold too.
		return append(requirements, Requirement{
			Levels:   []offloadingv1beta1.PodSecurityLevel{offloadingv1beta1.PodSecurityLevelBaseline, offloadingv1beta1.PodSecurityLevelPrivileged},
			Features: required(offloadingv1beta1.PodSecurityLevelBaseline, &all),
		})
	}
	return []Requirement{{Levels: []offloadingv1beta1.PodSecurityLevel{offloadingv1beta1.PodSecurityLevelPrivileged}}}
}

// NodeSelectorTerms returns the node selector terms matching the virtual nodes whose advertised policy satisfies
// any of the given requirements (see [NodeLabels]). The features only partially relaxed are accepted, as the provider
// cluster checks the actual values upon offloading.
func NodeSelectorTerms(requirements []Requirement) []corev1.NodeSelectorTerm {
	terms := make([]corev1.NodeSelectorTerm, 0, len(requirements))
	for i := range requirements {
		levels := make([]string, len(requirements[i].Levels))
		for j, level := range requirements[i].Levels {
			levels[j] = string(level)
		}

		term := corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{
			Key: LevelNodeLabel, Operator: corev1.NodeSelectorOpIn, Values: levels,
		}}}
		for _, feature := range requirements[i].Features {
			term.MatchExpressions = append(term.MatchExpressions, corev1.NodeSelectorRequirement{
				Key: feature.NodeLabel(), Operator: corev1.NodeSelectorOpIn, Values: []string{FeatureAllowed, FeaturePartial},
			})
		}
		terms = append(terms, term)
	}
	return terms
}

// allowEverything returns the allowances relaxing every feature, as far as the given pod is concerned.
func allowEverything(podSpec *corev1.PodSpec) allowances {
	capabilities, seLinuxTypes := sets.New[corev1.Capability](), sets.New[string]()
	collectSELinuxType := func(sc *corev1.SELinuxOptions) {
		if sc != nil {
			seLinuxTypes.Insert(sc.Type)
		}
	}
	if podSpec.SecurityContext != nil {
		collectSELinuxType(podSpec.SecurityContext.SELinuxOptions)
	}
	allContainers(podSpec, func(container *corev1.Container) bool {
		if sc := container.SecurityContext; sc != nil {
			if sc.Capabilities != nil {
				capabilities.Insert(sc.Capabilities.Add...)
			}
			collectSELinuxType(sc.SELinuxOptions)
		}
		return true
	})

	return allowances{
		HostNamespaces: []offloadingv1beta1.HostNamespace{
			offloadingv1beta1.HostNamespaceNetwork, offloadingv1beta1.HostNamespacePID, offloadingv1beta1.HostNamespaceIPC,
		},
		Privileged:         true,
		Capabilities:       sets.List(capabilities),
		HostPaths:          []string{"/"},
		HostPorts:          []offloadingv1beta1.HostPortRange{{Min: 1, Max: 65535}},
		Sysctls:            []string{"*"},
		SELinuxTypes:       sets.List(seLinuxTypes),
		UnconfinedSeccomp:  true,
		UnconfinedAppArmor: true,
		UnmaskedProcMount:  true,
		HostProcess:        true,
	}
}

// withoutFeature returns a copy of the allowances not relaxing the given feature.
func withoutFeature(allow *allowances, feature Feature) allowances {
	without := *allow
	removeNamespace := func(ns offloadingv1beta1.HostNamespace) {
		without.HostNamespaces = slices.DeleteFunc(slices.Clone(allow.HostNamespaces),
			func(n offloadingv1beta1.HostNamespace) bool { return n == ns })
	}

	switch feature {
	case FeatureHostNetwork:
		removeNamespace(offloadingv1beta1.HostNamespaceNetwork)
	case FeatureHostPID:
		removeNamespace(offloadingv1beta1.HostNamespacePID)
	case FeatureHostIPC:
		removeNamespace(offloadingv1beta1.HostNamespaceIPC)
	case FeaturePrivileged:
		without.Privileged = false
	case FeatureCapabilities:
		without.Capabilities = nil
	case FeatureHostPaths:
		without.HostPaths = nil
	case FeatureHostPorts:
		without.HostPorts = nil
	case FeatureSysctls:
		without.Sysctls = nil
	case FeatureSELinuxTypes:
		without.SELinuxTypes = nil
	case FeatureUnconfinedSeccomp:
		without.UnconfinedSeccomp = false
	case FeatureUnconfinedAppArmor:
		without.UnconfinedAppArmor = false
	case FeatureUnmaskedProcMount:
		without.UnmaskedProcMount = false
	case FeatureHostProcess:
		without.HostProcess = false
	}
	return without
}
