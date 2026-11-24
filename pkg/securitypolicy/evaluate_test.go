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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

var _ = Describe("Evaluate", func() {
	type allowances = offloadingv1beta1.OffloadingSecurityPolicyAllowances

	const appArmorAnnotation = corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix + "app"

	// pod returns a pod compliant with the restricted level, modified by the given mutators.
	pod := func(mutators ...func(*metav1.ObjectMeta, *corev1.PodSpec)) (*metav1.ObjectMeta, *corev1.PodSpec) {
		metadata := &metav1.ObjectMeta{Name: "pod"}
		spec := &corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "app",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr.To(false),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
		}
		for _, mutate := range mutators {
			mutate(metadata, spec)
		}
		return metadata, spec
	}
	container := func(mutate func(*corev1.Container)) func(*metav1.ObjectMeta, *corev1.PodSpec) {
		return func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) { mutate(&spec.Containers[0]) }
	}
	hostNetwork := func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) { spec.HostNetwork = true }
	hostPID := func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) { spec.HostPID = true }
	privileged := container(func(c *corev1.Container) { c.SecurityContext.Privileged = ptr.To(true) })
	addCapability := func(capability corev1.Capability) func(*metav1.ObjectMeta, *corev1.PodSpec) {
		return container(func(c *corev1.Container) {
			c.SecurityContext.Capabilities.Add = append(c.SecurityContext.Capabilities.Add, capability)
		})
	}
	hostPath := func(path string) func(*metav1.ObjectMeta, *corev1.PodSpec) {
		return func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) {
			spec.Volumes = append(spec.Volumes, corev1.Volume{
				Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path}},
			})
		}
	}
	hostPort := func(port int32) func(*metav1.ObjectMeta, *corev1.PodSpec) {
		return container(func(c *corev1.Container) {
			c.Ports = append(c.Ports, corev1.ContainerPort{ContainerPort: port, HostPort: port})
		})
	}
	sysctl := func(name string) func(*metav1.ObjectMeta, *corev1.PodSpec) {
		return func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) {
			spec.SecurityContext.Sysctls = append(spec.SecurityContext.Sysctls, corev1.Sysctl{Name: name, Value: "1"})
		}
	}
	seLinux := func(opts corev1.SELinuxOptions) func(*metav1.ObjectMeta, *corev1.PodSpec) {
		return container(func(c *corev1.Container) { c.SecurityContext.SELinuxOptions = &opts })
	}
	unconfinedSeccomp := container(func(c *corev1.Container) {
		c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
	})
	unconfinedAppArmor := container(func(c *corev1.Container) {
		c.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
	})
	unconfinedAppArmorAnnotation := func(metadata *metav1.ObjectMeta, _ *corev1.PodSpec) {
		metadata.Annotations = map[string]string{appArmorAnnotation: corev1.DeprecatedAppArmorBetaProfileNameUnconfined}
	}
	unmaskedProcMount := container(func(c *corev1.Container) { c.SecurityContext.ProcMount = ptr.To(corev1.UnmaskedProcMount) })
	hostProcess := func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) {
		spec.HostNetwork = true
		spec.SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: ptr.To(true)}
	}
	ephemeralPrivileged := func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) {
		spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debug", SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
		}}}
	}

	type testCase struct {
		mutators   []func(*metav1.ObjectMeta, *corev1.PodSpec)
		level      offloadingv1beta1.PodSecurityLevel // the baseline level, when unset
		allow      allowances
		violations []string // expected violations, matched by substring; empty means compliant
	}
	mutators := func(m ...func(*metav1.ObjectMeta, *corev1.PodSpec)) []func(*metav1.ObjectMeta, *corev1.PodSpec) {
		return m
	}

	DescribeTable("evaluates the pod against the policy",
		func(tc testCase) {
			metadata, spec := pod(tc.mutators...)
			level := cmp.Or(tc.level, offloadingv1beta1.PodSecurityLevelBaseline)
			violations := Evaluate(metadata, spec, &offloadingv1beta1.OffloadingSecurityPolicySpec{Level: level, Allow: tc.allow})
			if len(tc.violations) == 0 {
				Expect(violations).To(BeEmpty())
				return
			}
			Expect(violations).To(HaveLen(len(tc.violations)))
			for i := range tc.violations {
				Expect(violations[i]).To(ContainSubstring(tc.violations[i]))
			}
		},

		// Levels.
		Entry("restricted pod, restricted level", testCase{level: offloadingv1beta1.PodSecurityLevelRestricted}),
		Entry("unset level is baseline", testCase{mutators: mutators(hostNetwork), violations: []string{"host namespaces"}}),
		Entry("privileged level allows everything", testCase{
			level: offloadingv1beta1.PodSecurityLevelPrivileged, mutators: mutators(hostNetwork, privileged, hostPath("/")),
		}),
		Entry("restricted level forbids what baseline allows", testCase{
			level:      offloadingv1beta1.PodSecurityLevelRestricted,
			mutators:   mutators(container(func(c *corev1.Container) { c.SecurityContext.AllowPrivilegeEscalation = nil })),
			violations: []string{"allowPrivilegeEscalation != false"},
		}),
		Entry("multiple violations are all reported", testCase{
			mutators: mutators(hostPID, privileged), violations: []string{"host namespaces (hostPID=true)", "privileged"},
		}),

		// Host namespaces.
		Entry("host network denied", testCase{mutators: mutators(hostNetwork), violations: []string{"hostNetwork=true"}}),
		Entry("host network allowed", testCase{
			mutators: mutators(hostNetwork),
			allow:    allowances{HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork}},
		}),
		Entry("host network allowed does not allow host PID", testCase{
			mutators:   mutators(hostNetwork, hostPID),
			allow:      allowances{HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork}},
			violations: []string{"hostPID=true"},
		}),
		Entry("host network allowed covers its host ports", testCase{
			mutators: mutators(hostNetwork, hostPort(8080)),
			allow:    allowances{HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork}},
		}),

		// Privileged.
		Entry("privileged denied", testCase{mutators: mutators(privileged), violations: []string{"privileged"}}),
		Entry("privileged allowed", testCase{mutators: mutators(privileged), allow: allowances{Privileged: true}}),
		Entry("privileged ephemeral container denied", testCase{
			mutators: mutators(ephemeralPrivileged), violations: []string{"privileged"},
		}),
		Entry("privileged ephemeral container allowed", testCase{
			mutators: mutators(ephemeralPrivileged), allow: allowances{Privileged: true},
		}),

		// Capabilities.
		Entry("capability denied", testCase{mutators: mutators(addCapability("NET_ADMIN")), violations: []string{"NET_ADMIN"}}),
		Entry("capability allowed", testCase{
			mutators: mutators(addCapability("NET_ADMIN")), allow: allowances{Capabilities: []corev1.Capability{"NET_ADMIN"}},
		}),
		Entry("only the allowed capabilities", testCase{
			mutators: mutators(addCapability("NET_ADMIN"), addCapability("SYS_ADMIN")),
			allow:    allowances{Capabilities: []corev1.Capability{"NET_ADMIN"}},
			// The violation is reported by the upstream check, listing every non-default capability.
			violations: []string{`non-default capabilities (container "app" must not include "NET_ADMIN", "SYS_ADMIN"`},
		}),
		Entry("capability allowed at restricted level", testCase{
			level:    offloadingv1beta1.PodSecurityLevelRestricted,
			mutators: mutators(addCapability("NET_ADMIN")), allow: allowances{Capabilities: []corev1.Capability{"NET_ADMIN"}},
		}),

		// Host paths.
		Entry("host path denied", testCase{mutators: mutators(hostPath("/var/log")), violations: []string{"hostPath volumes"}}),
		Entry("host path under allowed prefix", testCase{
			mutators: mutators(hostPath("/var/log/app")), allow: allowances{HostPaths: []string{"/var/log/"}},
		}),
		Entry("host path equal to allowed prefix", testCase{
			mutators: mutators(hostPath("/var/log")), allow: allowances{HostPaths: []string{"/var/log"}},
		}),
		Entry("host path sharing a name prefix only", testCase{
			mutators: mutators(hostPath("/variable")), allow: allowances{HostPaths: []string{"/var"}},
			violations: []string{"hostPath volumes"},
		}),
		Entry("host path escaping allowed prefix", testCase{
			mutators: mutators(hostPath("/var/log/../../etc")), allow: allowances{HostPaths: []string{"/var/log"}},
			violations: []string{"hostPath volumes"},
		}),
		Entry("root prefix allows every host path", testCase{
			mutators: mutators(hostPath("/etc")), allow: allowances{HostPaths: []string{"/"}},
		}),

		// Host ports.
		Entry("host port denied", testCase{mutators: mutators(hostPort(8080)), violations: []string{"hostPort"}}),
		Entry("host port in allowed range", testCase{
			mutators: mutators(hostPort(8080)), allow: allowances{HostPorts: []offloadingv1beta1.HostPortRange{{Min: 8000, Max: 9000}}},
		}),
		Entry("host port outside allowed range", testCase{
			mutators: mutators(hostPort(9090)), allow: allowances{HostPorts: []offloadingv1beta1.HostPortRange{{Min: 8000, Max: 9000}}},
			violations: []string{"9090"},
		}),

		// Sysctls.
		Entry("unsafe sysctl denied", testCase{mutators: mutators(sysctl("kernel.msgmax")), violations: []string{"kernel.msgmax"}}),
		Entry("unsafe sysctl allowed by name", testCase{
			mutators: mutators(sysctl("kernel.msgmax")), allow: allowances{Sysctls: []string{"kernel.msgmax"}},
		}),
		Entry("unsafe sysctl allowed by prefix", testCase{
			mutators: mutators(sysctl("kernel.msgmax")), allow: allowances{Sysctls: []string{"kernel.*"}},
		}),
		Entry("unsafe sysctl not matching prefix", testCase{
			mutators: mutators(sysctl("kernel.msgmax")), allow: allowances{Sysctls: []string{"net.*"}},
			violations: []string{"kernel.msgmax"},
		}),

		// SELinux.
		Entry("SELinux type denied", testCase{
			mutators: mutators(seLinux(corev1.SELinuxOptions{Type: "spc_t"})), violations: []string{"spc_t"},
		}),
		Entry("SELinux type allowed", testCase{
			mutators: mutators(seLinux(corev1.SELinuxOptions{Type: "spc_t"})), allow: allowances{SELinuxTypes: []string{"spc_t"}},
		}),
		Entry("SELinux user still denied", testCase{
			mutators: mutators(seLinux(corev1.SELinuxOptions{Type: "spc_t", User: "system_u"})),
			allow:    allowances{SELinuxTypes: []string{"spc_t"}}, violations: []string{"user"},
		}),

		// Seccomp.
		Entry("unconfined seccomp denied", testCase{mutators: mutators(unconfinedSeccomp), violations: []string{"seccompProfile"}}),
		Entry("unconfined seccomp allowed", testCase{mutators: mutators(unconfinedSeccomp), allow: allowances{UnconfinedSeccomp: true}}),
		Entry("unconfined seccomp allowed at restricted level", testCase{
			level: offloadingv1beta1.PodSecurityLevelRestricted, mutators: mutators(unconfinedSeccomp),
			allow: allowances{UnconfinedSeccomp: true},
		}),

		// AppArmor.
		Entry("unconfined AppArmor denied", testCase{mutators: mutators(unconfinedAppArmor), violations: []string{"forbidden AppArmor profile"}}),
		Entry("unconfined AppArmor allowed", testCase{mutators: mutators(unconfinedAppArmor), allow: allowances{UnconfinedAppArmor: true}}),
		Entry("unconfined AppArmor annotation denied", testCase{
			mutators: mutators(unconfinedAppArmorAnnotation), violations: []string{appArmorAnnotation},
		}),
		Entry("unconfined AppArmor annotation allowed", testCase{
			mutators: mutators(unconfinedAppArmorAnnotation), allow: allowances{UnconfinedAppArmor: true},
		}),

		// Proc mount.
		Entry("unmasked proc mount denied", testCase{mutators: mutators(unmaskedProcMount), violations: []string{"procMount"}}),
		Entry("unmasked proc mount allowed", testCase{mutators: mutators(unmaskedProcMount), allow: allowances{UnmaskedProcMount: true}}),

		// Windows host process (it requires the host network).
		Entry("host process denied", testCase{
			mutators:   mutators(hostProcess),
			allow:      allowances{HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork}},
			violations: []string{"hostProcess"},
		}),
		Entry("host process allowed", testCase{
			mutators: mutators(hostProcess),
			allow: allowances{
				HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork}, HostProcess: true,
			},
		}),
	)

	It("does not modify the provided pod", func() {
		metadata, spec := pod(hostNetwork, privileged, addCapability("NET_ADMIN"), hostPath("/var/log"), hostPort(8080),
			sysctl("kernel.msgmax"), unconfinedSeccomp, unconfinedAppArmorAnnotation, unmaskedProcMount)
		metadataCopy, specCopy := metadata.DeepCopy(), spec.DeepCopy()

		Expect(Evaluate(metadata, spec, &offloadingv1beta1.OffloadingSecurityPolicySpec{Allow: allowances{
			HostNamespaces:     []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
			Privileged:         true,
			Capabilities:       []corev1.Capability{"NET_ADMIN"},
			HostPaths:          []string{"/var/log"},
			Sysctls:            []string{"kernel.*"},
			UnconfinedSeccomp:  true,
			UnconfinedAppArmor: true,
			UnmaskedProcMount:  true,
		}})).To(BeEmpty())

		Expect(metadata).To(Equal(metadataCopy))
		Expect(spec).To(Equal(specCopy))
	})

	It("accepts nil pod metadata", func() {
		_, spec := pod(hostNetwork)
		Expect(Evaluate(nil, spec, &offloadingv1beta1.OffloadingSecurityPolicySpec{})).To(ConsistOf(ContainSubstring("hostNetwork")))
	})
})
