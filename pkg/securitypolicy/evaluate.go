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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	psaapi "k8s.io/pod-security-admission/api"
	psapolicy "k8s.io/pod-security-admission/policy"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

// allowances shortens the name of the allowances type.
type allowances = offloadingv1beta1.OffloadingSecurityPolicyAllowances

// waiver returns whether the allowances cover every reason why the upstream check forbids the pod.
type waiver func(podSpec *corev1.PodSpec, allow *allowances) bool

// control is a Pod Security Standards control that the allowances can relax.
//
// The pod is always evaluated by the upstream check of the level, which is the only one deciding whether the pod is
// forbidden and why. When the check forbids the pod and the allowances relax the control, the failure is waived if
// the allowances cover every reason of it: the allowances can only waive failures, never introduce new ones.
type control struct {
	// baselineCheck is the ID of the upstream check enforcing the control at the baseline level.
	baselineCheck psapolicy.CheckID
	// restrictedCheck is the ID of the upstream check replacing baselineCheck at the restricted level, if any.
	restrictedCheck psapolicy.CheckID
	// relaxedBy returns whether the allowances relax the control.
	relaxedBy func(allow *allowances) bool
	// baseline is the waiver of baselineCheck. A nil waiver means that the allowance permits everything the upstream
	// check forbids, hence any failure of the check is waived.
	baseline waiver
	// restricted is the waiver of restrictedCheck, with the same meaning as baseline.
	restricted waiver
}

// controls are the controls the allowances can relax. Any other control is evaluated by the upstream evaluator, and
// its failures are never waived.
//
// The level selects the hardening profile, while the allowances relax the isolation of the provider hosts, one
// control at a time. Hence, a control is listed here only if it is a baseline control protecting the host (its
// namespaces, kernel, filesystem, ports or privileges) that legitimate workloads may need to relax, e.g. network
// agents requiring NET_ADMIN and the host network, or log collectors mounting /var/log. When a restricted check
// replaces the baseline check of a listed control, it is listed as its restrictedCheck, so that the same allowance
// applies at both levels, while the stricter restricted requirements (e.g. dropping all capabilities) still hold.
//
// Other controls are deliberately not relaxable:
//   - the restricted-only controls (allowPrivilegeEscalation, runAsNonRoot, runAsUser) are relaxed by selecting the
//     baseline level instead;
//   - hostProbesAndHostLifecycle would let consumers make the kubelet of the provider nodes connect to arbitrary
//     hosts, e.g. to probe the provider network, with no legitimate need for offloaded workloads;
//   - checks added upstream in the future are enforced as they are, until an allowance is deliberately added for
//     them, together with a CRD field, an entry here and the corresponding coverage in the alignment tests.
var controls = []control{{
	baselineCheck: "hostNamespaces",
	relaxedBy:     func(allow *allowances) bool { return len(allow.HostNamespaces) > 0 },
	baseline:      hostNamespacesAllowed,
}, {
	baselineCheck: "privileged",
	relaxedBy:     func(allow *allowances) bool { return allow.Privileged },
}, {
	baselineCheck:   "capabilities_baseline",
	restrictedCheck: "capabilities_restricted",
	relaxedBy:       func(allow *allowances) bool { return len(allow.Capabilities) > 0 },
	baseline:        capabilitiesBaselineAllowed,
	restricted:      capabilitiesRestrictedAllowed,
}, {
	baselineCheck:   "hostPathVolumes",
	restrictedCheck: "restrictedVolumes",
	relaxedBy:       func(allow *allowances) bool { return len(allow.HostPaths) > 0 },
	baseline:        hostPathVolumesAllowed,
	restricted:      restrictedVolumesAllowed,
}, {
	baselineCheck: "hostPorts",
	relaxedBy:     func(allow *allowances) bool { return len(allow.HostPorts) > 0 || hostNetworkAllowed(allow) },
	baseline:      hostPortsAllowed,
}, {
	baselineCheck: "sysctls",
	relaxedBy:     func(allow *allowances) bool { return len(allow.Sysctls) > 0 },
	baseline:      sysctlsAllowed,
}, {
	baselineCheck: "seLinuxOptions",
	relaxedBy:     func(allow *allowances) bool { return len(allow.SELinuxTypes) > 0 },
	baseline:      seLinuxOptionsAllowed,
}, {
	baselineCheck:   "seccompProfile_baseline",
	restrictedCheck: "seccompProfile_restricted",
	relaxedBy:       func(allow *allowances) bool { return allow.UnconfinedSeccomp },
	restricted:      seccompProfileRestrictedAllowed,
}, {
	baselineCheck: "appArmorProfile",
	relaxedBy:     func(allow *allowances) bool { return allow.UnconfinedAppArmor },
}, {
	baselineCheck:   "procMount",
	restrictedCheck: "procMount_restricted",
	relaxedBy:       func(allow *allowances) bool { return allow.UnmaskedProcMount },
}, {
	baselineCheck: "windowsHostProcess",
	relaxedBy:     func(allow *allowances) bool { return allow.HostProcess },
}}

// upstreamChecks are the latest versions of the upstream checks enforcing the controls, while evaluator evaluates
// the pods against the upstream checks of any other control.
var upstreamChecks, evaluator = mustLoadUpstreamChecks()

// mustLoadUpstreamChecks splits the default upstream checks between the controls and the evaluator of any other
// control. The checks are static, hence any error is a programming error, e.g. a control naming an unknown check.
func mustLoadUpstreamChecks() (map[psapolicy.CheckID]psapolicy.CheckPodFn, psapolicy.Evaluator) {
	controlled := sets.New[psapolicy.CheckID]()
	for i := range controls {
		controlled.Insert(controls[i].baselineCheck)
		if controls[i].restrictedCheck != "" {
			controlled.Insert(controls[i].restrictedCheck)
		}
	}

	checks := map[psapolicy.CheckID]psapolicy.CheckPodFn{}
	var others []psapolicy.Check
	for _, check := range psapolicy.DefaultChecks() {
		if controlled.Has(check.ID) {
			checks[check.ID] = check.Versions[len(check.Versions)-1].CheckPod
			continue
		}
		others = append(others, check)
	}

	if missing := controlled.Difference(sets.KeySet(checks)); missing.Len() > 0 {
		panic(fmt.Sprintf("unknown pod security checks %v", sets.List(missing)))
	}

	e, err := psapolicy.NewEvaluator(others, nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create the pod security evaluator: %v", err))
	}
	return checks, e
}

// evaluate evaluates the pod against the upstream check of the control at the given level, waiving its failure when
// the allowances cover every reason of it.
func (c *control) evaluate(level psaapi.Level, podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec,
	allow *allowances,
) psapolicy.CheckResult {
	id, waived := c.baselineCheck, c.baseline
	if level == psaapi.LevelRestricted && c.restrictedCheck != "" {
		id, waived = c.restrictedCheck, c.restricted
	}

	result := upstreamChecks[id](podMetadata, podSpec)
	if result.Allowed || !c.relaxedBy(allow) || (waived != nil && !waived(podSpec, allow)) {
		return result
	}
	return psapolicy.CheckResult{Allowed: true}
}

// Evaluate evaluates the pod, described by its metadata and spec, against the policy, and returns the violations,
// each made of a forbidden reason and, when available, its detail (e.g. "host namespaces (hostNetwork=true)").
// It returns no violations when the pod complies with the policy. The provided objects are not modified.
func Evaluate(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec,
	policy *offloadingv1beta1.OffloadingSecurityPolicySpec,
) []string {
	level := parseLevel(policy.Level)
	if level == psaapi.LevelPrivileged {
		return nil
	}
	if podMetadata == nil {
		podMetadata = &metav1.ObjectMeta{}
	}

	levelVersion := psaapi.LevelVersion{Level: level, Version: psaapi.LatestVersion()}
	results := evaluator.EvaluatePod(levelVersion, podMetadata, podSpec)
	for i := range controls {
		results = append(results, controls[i].evaluate(level, podMetadata, podSpec, &policy.Allow))
	}

	aggregate := psapolicy.AggregateCheckResults(results)
	if aggregate.Allowed {
		return nil
	}

	violations := make([]string, len(aggregate.ForbiddenReasons))
	for i, reason := range aggregate.ForbiddenReasons {
		violations[i] = reason
		if detail := aggregate.ForbiddenDetails[i]; detail != "" {
			violations[i] = fmt.Sprintf("%s (%s)", reason, detail)
		}
	}
	return violations
}
