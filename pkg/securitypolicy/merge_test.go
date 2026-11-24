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

var _ = Describe("Merge", func() {
	policy := func(level offloadingv1beta1.PodSecurityLevel,
		allow offloadingv1beta1.OffloadingSecurityPolicyAllowances,
	) offloadingv1beta1.OffloadingSecurityPolicy {
		return offloadingv1beta1.OffloadingSecurityPolicy{
			Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{Level: level, Allow: allow},
		}
	}

	It("enforces the restricted level, with no allowances, when no policy is provided", func() {
		effective := Merge()
		expected := offloadingv1beta1.OffloadingSecurityPolicySpec{Level: offloadingv1beta1.PodSecurityLevelRestricted}
		Expect(equality.Semantic.DeepEqual(effective, expected)).To(BeTrue(), "got %+v", effective)
	})

	It("grants the allowances on top of the restricted level when no policy sets the level", func() {
		effective := Merge(policy("", offloadingv1beta1.OffloadingSecurityPolicyAllowances{
			HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
		}))
		Expect(effective.Level).To(Equal(offloadingv1beta1.PodSecurityLevelRestricted))
		Expect(effective.Allow.HostNamespaces).To(ConsistOf(offloadingv1beta1.HostNamespaceNetwork))
	})

	It("never restricts what another policy grants", func() {
		effective := Merge(
			policy(offloadingv1beta1.PodSecurityLevelBaseline, offloadingv1beta1.OffloadingSecurityPolicyAllowances{Sysctls: []string{"net.core.somaxconn"}}),
			policy(offloadingv1beta1.PodSecurityLevelRestricted, offloadingv1beta1.OffloadingSecurityPolicyAllowances{}),
		)
		Expect(effective.Level).To(Equal(offloadingv1beta1.PodSecurityLevelBaseline))
		Expect(effective.Allow.Sysctls).To(ConsistOf("net.core.somaxconn"))
	})

	It("does not modify the provided policies", func() {
		first := policy(offloadingv1beta1.PodSecurityLevelBaseline, offloadingv1beta1.OffloadingSecurityPolicyAllowances{Sysctls: []string{"net.core.somaxconn"}})
		_ = Merge(first, policy("", offloadingv1beta1.OffloadingSecurityPolicyAllowances{Sysctls: []string{"kernel.shm_rmid_forced"}}))
		Expect(first.Spec.Allow.Sysctls).To(Equal([]string{"net.core.somaxconn"}))
	})

	It("merges level and allowances", func() {
		effective := Merge(
			policy(offloadingv1beta1.PodSecurityLevelRestricted, offloadingv1beta1.OffloadingSecurityPolicyAllowances{
				Capabilities: []corev1.Capability{"NET_ADMIN"},
			}),
			policy(offloadingv1beta1.PodSecurityLevelBaseline, offloadingv1beta1.OffloadingSecurityPolicyAllowances{
				HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
			}),
		)
		expected := offloadingv1beta1.OffloadingSecurityPolicySpec{
			Level: offloadingv1beta1.PodSecurityLevelBaseline,
			Allow: offloadingv1beta1.OffloadingSecurityPolicyAllowances{
				HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
				Capabilities:   []corev1.Capability{"NET_ADMIN"},
			},
		}
		// Semantic equality treats empty and nil lists as equal.
		Expect(equality.Semantic.DeepEqual(effective, expected)).To(BeTrue(), "got %+v", effective)
	})
})
