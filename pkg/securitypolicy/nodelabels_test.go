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

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

var _ = Describe("NodeLabels", func() {
	label := func(f Feature) string { return f.NodeLabel() }

	It("advertises only the level when nothing is relaxed", func() {
		Expect(NodeLabels(&offloadingv1beta1.OffloadingSecurityPolicySpec{Level: offloadingv1beta1.PodSecurityLevelBaseline})).
			To(Equal(map[string]string{LevelNodeLabel: "baseline"}))
	})

	It("advertises the most restrictive level when unset", func() {
		Expect(NodeLabels(&offloadingv1beta1.OffloadingSecurityPolicySpec{})).To(HaveKeyWithValue(LevelNodeLabel, "restricted"))
	})

	It("advertises every feature as allowed at the privileged level", func() {
		labels := NodeLabels(&offloadingv1beta1.OffloadingSecurityPolicySpec{Level: offloadingv1beta1.PodSecurityLevelPrivileged})
		Expect(labels).To(HaveLen(len(Features) + 1))
		Expect(labels).To(HaveKeyWithValue(LevelNodeLabel, "privileged"))
		for _, feature := range Features {
			Expect(labels).To(HaveKeyWithValue(feature.NodeLabel(), FeatureAllowed))
		}
	})

	It("advertises the relaxed features, also on top of the restricted level", func() {
		labels := NodeLabels(&offloadingv1beta1.OffloadingSecurityPolicySpec{
			Level: offloadingv1beta1.PodSecurityLevelRestricted,
			Allow: offloadingv1beta1.OffloadingSecurityPolicyAllowances{
				HostNamespaces:    []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork, offloadingv1beta1.HostNamespaceIPC},
				Privileged:        true,
				Capabilities:      []corev1.Capability{"NET_ADMIN"},
				HostPaths:         []string{"/var/log"},
				HostPorts:         []offloadingv1beta1.HostPortRange{{Min: 8080, Max: 8090}},
				Sysctls:           []string{"net.ipv4.*"},
				SELinuxTypes:      []string{"container_t"},
				UnconfinedSeccomp: true,
			},
		})
		Expect(labels).To(Equal(map[string]string{
			LevelNodeLabel:                  "restricted",
			label(FeatureHostNetwork):       FeatureAllowed,
			label(FeatureHostIPC):           FeatureAllowed,
			label(FeaturePrivileged):        FeatureAllowed,
			label(FeatureCapabilities):      FeaturePartial,
			label(FeatureHostPaths):         FeaturePartial,
			label(FeatureHostPorts):         FeaturePartial,
			label(FeatureSysctls):           FeaturePartial,
			label(FeatureSELinuxTypes):      FeaturePartial,
			label(FeatureUnconfinedSeccomp): FeatureAllowed,
		}))
	})

	It("advertises the list features as allowed when fully covered", func() {
		labels := NodeLabels(&offloadingv1beta1.OffloadingSecurityPolicySpec{
			Level: offloadingv1beta1.PodSecurityLevelBaseline,
			Allow: offloadingv1beta1.OffloadingSecurityPolicyAllowances{
				HostPaths: []string{"/var/log", "/"},
				HostPorts: []offloadingv1beta1.HostPortRange{{Min: 1, Max: 65535}},
				Sysctls:   []string{"*"},
			},
		})
		Expect(labels).To(HaveKeyWithValue(label(FeatureHostPaths), FeatureAllowed))
		Expect(labels).To(HaveKeyWithValue(label(FeatureHostPorts), FeatureAllowed))
		Expect(labels).To(HaveKeyWithValue(label(FeatureSysctls), FeatureAllowed))
	})

	It("generates valid label keys", func() {
		for _, feature := range Features {
			Expect(feature.NodeLabel()).To(MatchRegexp(`^policy\.liqo\.io/[a-z0-9]([-a-z0-9]*[a-z0-9])?$`))
			Expect(len(string(feature))).To(BeNumerically("<=", 63))
		}
	})
})
