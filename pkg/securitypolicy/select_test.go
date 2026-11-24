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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
)

var _ = Describe("Select", func() {
	const clusterID liqov1beta1.ClusterID = "consumer"

	var (
		ctx     context.Context
		objects []client.Object
	)

	policy := func(name string, selector metav1.LabelSelector) *offloadingv1beta1.OffloadingSecurityPolicy {
		return &offloadingv1beta1.OffloadingSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       offloadingv1beta1.OffloadingSecurityPolicySpec{ClusterSelector: selector},
		}
	}
	foreignCluster := func(id liqov1beta1.ClusterID, extraLabels map[string]string) *liqov1beta1.ForeignCluster {
		fc := &liqov1beta1.ForeignCluster{
			ObjectMeta: metav1.ObjectMeta{Name: string(id), Labels: map[string]string{consts.RemoteClusterID: string(id)}},
			Spec:       liqov1beta1.ForeignClusterSpec{ClusterID: id},
		}
		for k, v := range extraLabels {
			fc.Labels[k] = v
		}
		return fc
	}
	selectNames := func() []string {
		scheme := runtime.NewScheme()
		Expect(liqov1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(offloadingv1beta1.AddToScheme(scheme)).To(Succeed())
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

		policies, err := Select(ctx, cl, clusterID)
		Expect(err).ToNot(HaveOccurred())
		names := make([]string, 0, len(policies))
		for i := range policies {
			names = append(names, policies[i].Name)
		}
		return names
	}

	BeforeEach(func() {
		ctx = context.Background()
		objects = []client.Object{
			policy("all", metav1.LabelSelector{}),
			policy("by-id", metav1.LabelSelector{MatchLabels: map[string]string{consts.RemoteClusterID: string(clusterID)}}),
			policy("other-id", metav1.LabelSelector{MatchLabels: map[string]string{consts.RemoteClusterID: "other"}}),
			policy("trusted", metav1.LabelSelector{MatchLabels: map[string]string{"tier": "trusted"}}),
			policy("not-trusted", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"trusted"},
			}}}),
		}
	})

	It("selects the policies matching the ForeignCluster labels, including those with an empty selector", func() {
		objects = append(objects, foreignCluster(clusterID, map[string]string{"tier": "trusted"}), foreignCluster("other", nil))
		Expect(selectNames()).To(ConsistOf("all", "by-id", "trusted"))
	})

	It("selects the policies matching the remote cluster ID when the ForeignCluster does not exist", func() {
		Expect(selectNames()).To(ConsistOf("all", "by-id", "not-trusted"))
	})

	It("selects nothing when no policy exists", func() {
		objects = []client.Object{foreignCluster(clusterID, nil)}
		Expect(selectNames()).To(BeEmpty())
	})

	It("fails when a policy has an invalid selector", func() {
		objects = append(objects, policy("invalid", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tier", Operator: "Invalid",
		}}}))

		scheme := runtime.NewScheme()
		Expect(liqov1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(offloadingv1beta1.AddToScheme(scheme)).To(Succeed())
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

		_, err := Select(ctx, cl, clusterID)
		Expect(err).To(MatchError(ContainSubstring(`invalid cluster selector of OffloadingSecurityPolicy "invalid"`)))
	})
})

var _ = Describe("Resolve", func() {
	const clusterID liqov1beta1.ClusterID = "consumer"

	var objects []client.Object

	resolve := func() (offloadingv1beta1.OffloadingSecurityPolicySpec, error) {
		scheme := runtime.NewScheme()
		Expect(liqov1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(offloadingv1beta1.AddToScheme(scheme)).To(Succeed())
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
		return Resolve(context.Background(), cl, clusterID)
	}

	BeforeEach(func() {
		objects = []client.Object{&offloadingv1beta1.OffloadingSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "relax"},
			Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{
				ClusterSelector: metav1.LabelSelector{MatchLabels: map[string]string{consts.RemoteClusterID: string(clusterID)}},
				Allow: offloadingv1beta1.OffloadingSecurityPolicyAllowances{
					HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
				},
			},
		}}
	})

	It("enforces nothing when no policy exists", func() {
		objects = nil
		spec, err := resolve()
		Expect(err).ToNot(HaveOccurred())
		Expect(spec.Level).To(Equal(offloadingv1beta1.PodSecurityLevelPrivileged))
		Expect(spec.Allow).To(BeZero())
	})

	It("enforces nothing when the existing policies select other clusters only", func() {
		objects[0].(*offloadingv1beta1.OffloadingSecurityPolicy).Spec.ClusterSelector.MatchLabels[consts.RemoteClusterID] = "other"
		spec, err := resolve()
		Expect(err).ToNot(HaveOccurred())
		Expect(spec.Level).To(Equal(offloadingv1beta1.PodSecurityLevelPrivileged))
		Expect(spec.Allow).To(BeZero())
	})

	It("enforces the restricted level, plus the allowances, when the selecting policies set no level", func() {
		spec, err := resolve()
		Expect(err).ToNot(HaveOccurred())
		Expect(spec.Level).To(Equal(offloadingv1beta1.PodSecurityLevelRestricted))
		Expect(spec.Allow.HostNamespaces).To(ConsistOf(offloadingv1beta1.HostNamespaceNetwork))
	})

	It("merges the policies selecting the cluster", func() {
		objects = append(objects,
			&offloadingv1beta1.OffloadingSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "all"},
				Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{
					Level: offloadingv1beta1.PodSecurityLevelBaseline,
					Allow: offloadingv1beta1.OffloadingSecurityPolicyAllowances{Sysctls: []string{"net.core.somaxconn"}},
				},
			},
			&offloadingv1beta1.OffloadingSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "other"},
				Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{
					ClusterSelector: metav1.LabelSelector{MatchLabels: map[string]string{consts.RemoteClusterID: "other"}},
					Level:           offloadingv1beta1.PodSecurityLevelPrivileged,
				},
			},
		)

		spec, err := resolve()
		Expect(err).ToNot(HaveOccurred())
		Expect(spec.Level).To(Equal(offloadingv1beta1.PodSecurityLevelBaseline))
		Expect(spec.Allow.HostNamespaces).To(ConsistOf(offloadingv1beta1.HostNamespaceNetwork))
		Expect(spec.Allow.Sysctls).To(ConsistOf("net.core.somaxconn"))
	})
})
