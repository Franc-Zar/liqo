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

package shadowpod

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/utils/testutil"
)

var _ = Describe("ShadowPod offloading security policy enforcement", func() {
	var (
		objects       []client.Object
		basePolicy    *offloadingv1beta1.OffloadingSecurityPolicy
		shadowpod     *offloadingv1beta1.ShadowPod
		response      admission.Response
	)

	hostNetworkPolicy := &offloadingv1beta1.OffloadingSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "host-network"},
		Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{
			ClusterSelector: metav1.LabelSelector{MatchLabels: map[string]string{consts.RemoteClusterID: string(clusterID)}},
			Allow: offloadingv1beta1.OffloadingSecurityPolicyAllowances{
				HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
			},
		},
	}

	BeforeEach(func() {
		basePolicy = forgeBaselineSecurityPolicy()
		objects = []client.Object{testutil.FakeNamespaceWithClusterID(clusterID, testNamespace), foreignCluster, basePolicy}
		shadowpod = forgeShadowPodWithClusterID(clusterID, userName, testNamespace)
		shadowpod.Spec.Pod.HostNetwork = true
	})

	JustBeforeEach(func() {
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
		validator := NewValidator(cl, false)
		response = validator.Handle(ctx, forgeRequest(admissionv1.Create, shadowpod, nil))
	})

	When("no policy selects the origin cluster", func() {
		BeforeEach(func() {
			objects = []client.Object{testutil.FakeNamespaceWithClusterID(clusterID, testNamespace), foreignCluster}
			shadowpod.Spec.Pod.HostPID = true
			shadowpod.Spec.Pod.Containers = []corev1.Container{{Name: "app", Image: "app",
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)}}}
		})

		It("enforces nothing, admitting even a privileged shadow pod", func() {
			Expect(response.Allowed).To(BeTrue())
		})
	})

	When("only the baseline policy selects the origin cluster", func() {
		It("denies the shadow pod violating the baseline level, tagging the violations", func() {
			Expect(response.Allowed).To(BeFalse())
			Expect(response.Result.Code).To(BeNumerically("==", http.StatusForbidden))
			Expect(response.Result.Message).To(ContainSubstring("violates the offloading security policy: host namespaces (hostNetwork=true)"))
			Expect(response.Result.Details).ToNot(BeNil())
			Expect(response.Result.Details.Causes).To(ConsistOf(metav1.StatusCause{
				Type: offloadingv1beta1.OffloadingSecurityPolicyViolationCause, Message: "host namespaces (hostNetwork=true)",
			}))
		})
	})

	When("a policy selecting the origin cluster allows the shadow pod", func() {
		BeforeEach(func() { objects = append(objects, hostNetworkPolicy) })

		It("admits the shadow pod", func() {
			Expect(response.Allowed).To(BeTrue())
		})
	})

	When("the policy allows only part of what the shadow pod requires", func() {
		BeforeEach(func() {
			objects = append(objects, hostNetworkPolicy)
			shadowpod.Spec.Pod.HostPID = true
		})

		It("denies the shadow pod", func() {
			Expect(response.Allowed).To(BeFalse())
			Expect(response.Result.Details.Causes).To(ConsistOf(HaveField("Message", ContainSubstring("hostPID=true"))))
		})
	})

	When("the shadow pod complies with the baseline level", func() {
		BeforeEach(func() {
			shadowpod.Spec.Pod = corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app"}}}
		})

		It("admits the shadow pod", func() {
			Expect(response.Allowed).To(BeTrue())
		})
	})

	When("only a relaxation-only policy selects the origin cluster", func() {
		BeforeEach(func() {
			objects = []client.Object{testutil.FakeNamespaceWithClusterID(clusterID, testNamespace), foreignCluster, hostNetworkPolicy}
			shadowpod.Spec.Pod.Containers = []corev1.Container{{Name: "app", Image: "app"}}
		})

		It("grants the relaxation on top of the restricted level, without loosening it", func() {
			Expect(response.Allowed).To(BeFalse())
			Expect(response.Result.Details.Causes).ToNot(ContainElement(HaveField("Message", ContainSubstring("hostNetwork"))))
			Expect(response.Result.Details.Causes).To(ContainElement(HaveField("Message", ContainSubstring("runAsNonRoot"))))
		})
	})

	When("a policy selecting the origin cluster sets the privileged level", func() {
		BeforeEach(func() {
			basePolicy.Spec.Level = offloadingv1beta1.PodSecurityLevelPrivileged
			shadowpod.Spec.Pod.HostPID = true
		})

		It("admits the shadow pod", func() {
			Expect(response.Allowed).To(BeTrue())
		})
	})
})
