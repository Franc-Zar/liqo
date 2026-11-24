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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

var _ = Describe("Requirements", func() {
	const (
		privileged = offloadingv1beta1.PodSecurityLevelPrivileged
		baseline   = offloadingv1beta1.PodSecurityLevelBaseline
		restricted = offloadingv1beta1.PodSecurityLevelRestricted
	)

	var spec *corev1.PodSpec

	// restrictedPod returns a pod complying with the restricted level.
	restrictedPod := func() *corev1.PodSpec {
		return &corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{Name: "app", Image: "app", SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr.To(false),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			}}},
		}
	}
	requirements := func() []Requirement { return Requirements(&metav1.ObjectMeta{}, spec) }

	It("requires nothing for a pod complying with the restricted level", func() {
		spec = restrictedPod()
		Expect(requirements()).To(BeNil())
	})

	It("requires a non-restricted level for a pod complying with the baseline level only", func() {
		spec = &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app"}}}
		Expect(requirements()).To(Equal([]Requirement{{Levels: []offloadingv1beta1.PodSecurityLevel{baseline, privileged}}}))
	})

	It("requires the features relaxing the baseline controls, at any feasible level", func() {
		spec = restrictedPod()
		spec.HostNetwork = true
		Expect(requirements()).To(Equal([]Requirement{
			{Levels: []offloadingv1beta1.PodSecurityLevel{restricted}, Features: []Feature{FeatureHostNetwork}},
			{Levels: []offloadingv1beta1.PodSecurityLevel{baseline, privileged}, Features: []Feature{FeatureHostNetwork}},
		}))
	})

	It("does not require the host ports when waived by the host network, as the provider cluster does", func() {
		spec = &corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{
			Name: "app", Image: "app", Ports: []corev1.ContainerPort{{ContainerPort: 8080, HostPort: 8080}},
		}}}
		Expect(requirements()).To(Equal([]Requirement{
			{Levels: []offloadingv1beta1.PodSecurityLevel{baseline, privileged}, Features: []Feature{FeatureHostNetwork}},
		}))
	})

	It("requires the features at the level they are needed at only", func() {
		// CHOWN is allowed by the baseline level, but not by the restricted one.
		spec = restrictedPod()
		spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"CHOWN"}
		Expect(requirements()).To(Equal([]Requirement{
			{Levels: []offloadingv1beta1.PodSecurityLevel{restricted}, Features: []Feature{FeatureCapabilities}},
			{Levels: []offloadingv1beta1.PodSecurityLevel{baseline, privileged}},
		}))
	})

	It("requires several features at once", func() {
		spec = &corev1.PodSpec{HostPID: true, Containers: []corev1.Container{{
			Name: "app", Image: "app", SecurityContext: &corev1.SecurityContext{
				Privileged:   ptr.To(true),
				Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
			},
		}}}
		Expect(requirements()).To(Equal([]Requirement{{
			Levels:   []offloadingv1beta1.PodSecurityLevel{baseline, privileged},
			Features: []Feature{FeatureHostPID, FeaturePrivileged, FeatureCapabilities},
		}}))
	})

	It("requires the privileged level for a pod no allowance can admit", func() {
		spec = &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app", SecurityContext: &corev1.SecurityContext{
			SELinuxOptions: &corev1.SELinuxOptions{User: "system_u"},
		}}}}
		Expect(requirements()).To(Equal([]Requirement{{Levels: []offloadingv1beta1.PodSecurityLevel{privileged}}}))
	})

	It("is consistent with the evaluation of the policies satisfying the requirements", func() {
		spec = restrictedPod()
		spec.HostNetwork = true
		spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
		for _, requirement := range requirements() {
			policy := offloadingv1beta1.OffloadingSecurityPolicySpec{Level: requirement.Levels[0], Allow: allowEverything(spec)}
			Expect(Evaluate(&metav1.ObjectMeta{}, spec, &policy)).To(BeEmpty())
		}
	})
})

var _ = Describe("NodeSelectorTerms", func() {
	It("matches the advertised level and features, accepting the partially relaxed ones", func() {
		Expect(NodeSelectorTerms([]Requirement{
			{Levels: []offloadingv1beta1.PodSecurityLevel{offloadingv1beta1.PodSecurityLevelRestricted}, Features: []Feature{FeatureHostNetwork}},
			{Levels: []offloadingv1beta1.PodSecurityLevel{offloadingv1beta1.PodSecurityLevelPrivileged}},
		})).To(Equal([]corev1.NodeSelectorTerm{
			{MatchExpressions: []corev1.NodeSelectorRequirement{
				{Key: LevelNodeLabel, Operator: corev1.NodeSelectorOpIn, Values: []string{"restricted"}},
				{Key: FeatureHostNetwork.NodeLabel(), Operator: corev1.NodeSelectorOpIn, Values: []string{FeatureAllowed, FeaturePartial}},
			}},
			{MatchExpressions: []corev1.NodeSelectorRequirement{
				{Key: LevelNodeLabel, Operator: corev1.NodeSelectorOpIn, Values: []string{"privileged"}},
			}},
		}))
	})
})
