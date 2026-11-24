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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

func policyWithLevel(level offloadingv1beta1.PodSecurityLevel) offloadingv1beta1.OffloadingSecurityPolicy {
	return offloadingv1beta1.OffloadingSecurityPolicy{
		Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{Level: level},
	}
}

var _ = Describe("getEffectiveLevel", func() {
	const (
		privileged = offloadingv1beta1.PodSecurityLevelPrivileged
		baseline   = offloadingv1beta1.PodSecurityLevelBaseline
		restricted = offloadingv1beta1.PodSecurityLevelRestricted
	)

	DescribeTable("returns the most permissive level",
		func(levels []offloadingv1beta1.PodSecurityLevel, expected offloadingv1beta1.PodSecurityLevel) {
			policies := make([]offloadingv1beta1.OffloadingSecurityPolicy, len(levels))
			for i := range levels {
				policies[i] = policyWithLevel(levels[i])
			}
			Expect(getEffectiveLevel(policies...)).To(Equal(expected))
		},
		Entry("no policies: restricted", nil, restricted),
		Entry("single unset: restricted", []offloadingv1beta1.PodSecurityLevel{""}, restricted),
		Entry("unset and restricted: unset ignored", []offloadingv1beta1.PodSecurityLevel{"", restricted}, restricted),
		Entry("restricted and unset: unset ignored", []offloadingv1beta1.PodSecurityLevel{restricted, ""}, restricted),
		Entry("unset and privileged", []offloadingv1beta1.PodSecurityLevel{"", privileged}, privileged),
		Entry("single restricted", []offloadingv1beta1.PodSecurityLevel{restricted}, restricted),
		Entry("single baseline", []offloadingv1beta1.PodSecurityLevel{baseline}, baseline),
		Entry("single privileged", []offloadingv1beta1.PodSecurityLevel{privileged}, privileged),
		Entry("restricted and baseline", []offloadingv1beta1.PodSecurityLevel{restricted, baseline}, baseline),
		Entry("baseline and restricted", []offloadingv1beta1.PodSecurityLevel{baseline, restricted}, baseline),
		Entry("all levels", []offloadingv1beta1.PodSecurityLevel{restricted, privileged, baseline}, privileged),
		Entry("unknown level never loosens", []offloadingv1beta1.PodSecurityLevel{"unknown"}, restricted),
		Entry("unknown level with baseline", []offloadingv1beta1.PodSecurityLevel{"unknown", baseline}, baseline),
	)
})

var _ = Describe("getEffectiveAllowances", func() {
	policyWithAllow := func(allow offloadingv1beta1.OffloadingSecurityPolicyAllowances) offloadingv1beta1.OffloadingSecurityPolicy {
		return offloadingv1beta1.OffloadingSecurityPolicy{Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{Allow: allow}}
	}
	portRange := func(minPort, maxPort int32) offloadingv1beta1.HostPortRange {
		return offloadingv1beta1.HostPortRange{Min: minPort, Max: maxPort}
	}

	It("returns no allowances when no policy is provided", func() {
		Expect(getEffectiveAllowances()).To(BeZero())
	})

	It("returns no allowances when policies allow nothing", func() {
		effective := getEffectiveAllowances(policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{}),
			policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{}))
		// Semantic equality treats empty and nil lists as equal.
		Expect(equality.Semantic.DeepEqual(effective, offloadingv1beta1.OffloadingSecurityPolicyAllowances{})).To(BeTrue())
	})

	It("returns the union of the allowances", func() {
		a := policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{
			HostNamespaces:    []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespacePID},
			Capabilities:      []corev1.Capability{"NET_ADMIN", "SYS_TIME"},
			HostPaths:         []string{"/var/log"},
			Sysctls:           []string{"net.ipv4.*"},
			UnconfinedSeccomp: true,
		})
		b := policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{
			HostNamespaces:    []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
			Capabilities:      []corev1.Capability{"NET_ADMIN", "NET_RAW"},
			SELinuxTypes:      []string{"spc_t"},
			UnmaskedProcMount: true,
			HostProcess:       true,
		})
		c := policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{
			Privileged:         true,
			UnconfinedAppArmor: true,
		})

		Expect(getEffectiveAllowances(a, b, c)).To(Equal(offloadingv1beta1.OffloadingSecurityPolicyAllowances{
			HostNamespaces: []offloadingv1beta1.HostNamespace{
				offloadingv1beta1.HostNamespaceNetwork, offloadingv1beta1.HostNamespacePID,
			},
			Privileged:         true,
			Capabilities:       []corev1.Capability{"NET_ADMIN", "NET_RAW", "SYS_TIME"},
			HostPaths:          []string{"/var/log"},
			Sysctls:            []string{"net.ipv4.*"},
			SELinuxTypes:       []string{"spc_t"},
			UnconfinedSeccomp:  true,
			UnconfinedAppArmor: true,
			UnmaskedProcMount:  true,
			HostProcess:        true,
		}))
	})

	It("does not modify the provided policies", func() {
		a := policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{
			Capabilities: []corev1.Capability{"SYS_TIME", "NET_ADMIN"},
			HostPorts:    []offloadingv1beta1.HostPortRange{portRange(100, 200)},
		})
		b := policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{
			HostPorts: []offloadingv1beta1.HostPortRange{portRange(150, 300)},
		})
		aCopy, bCopy := a.DeepCopy(), b.DeepCopy()

		effective := getEffectiveAllowances(a, b)
		effective.Capabilities[0] = "CHANGED"
		effective.HostPorts[0].Max = 1

		Expect(a).To(Equal(*aCopy))
		Expect(b).To(Equal(*bCopy))
	})

	DescribeTable("merges the host port ranges",
		func(a, b, expected []offloadingv1beta1.HostPortRange) {
			Expect(getEffectiveAllowances(
				policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{HostPorts: a}),
				policyWithAllow(offloadingv1beta1.OffloadingSecurityPolicyAllowances{HostPorts: b}),
			).HostPorts).To(Equal(expected))
		},
		Entry("both empty", nil, nil, nil),
		Entry("one side only",
			[]offloadingv1beta1.HostPortRange{portRange(80, 80)}, nil,
			[]offloadingv1beta1.HostPortRange{portRange(80, 80)}),
		Entry("disjoint ranges are sorted",
			[]offloadingv1beta1.HostPortRange{portRange(9000, 9100)}, []offloadingv1beta1.HostPortRange{portRange(80, 80)},
			[]offloadingv1beta1.HostPortRange{portRange(80, 80), portRange(9000, 9100)}),
		Entry("overlapping ranges are merged",
			[]offloadingv1beta1.HostPortRange{portRange(100, 200)}, []offloadingv1beta1.HostPortRange{portRange(150, 300)},
			[]offloadingv1beta1.HostPortRange{portRange(100, 300)}),
		Entry("adjacent ranges are merged",
			[]offloadingv1beta1.HostPortRange{portRange(100, 200)}, []offloadingv1beta1.HostPortRange{portRange(201, 300)},
			[]offloadingv1beta1.HostPortRange{portRange(100, 300)}),
		Entry("contained range is absorbed",
			[]offloadingv1beta1.HostPortRange{portRange(100, 300), portRange(400, 400)},
			[]offloadingv1beta1.HostPortRange{portRange(150, 160)},
			[]offloadingv1beta1.HostPortRange{portRange(100, 300), portRange(400, 400)}),
		Entry("duplicates are removed",
			[]offloadingv1beta1.HostPortRange{portRange(80, 80)}, []offloadingv1beta1.HostPortRange{portRange(80, 80)},
			[]offloadingv1beta1.HostPortRange{portRange(80, 80)}),
	)
})
