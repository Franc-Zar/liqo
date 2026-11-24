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
	"reflect"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	psaapi "k8s.io/pod-security-admission/api"
	psapolicy "k8s.io/pod-security-admission/policy"
	"k8s.io/utils/ptr"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

// The tests in this file verify that the waivers stay aligned with the upstream ones, so that a change of the
// pod-security-admission library (e.g. a new safe sysctl or volume type) is detected when it is updated.

// upstreamCorpus returns pods exercising every value the waivers treat differently.
func upstreamCorpus() map[string]*corev1.PodSpec {
	corpus := map[string]*corev1.PodSpec{}
	add := func(name string, mutate func(spec *corev1.PodSpec)) {
		spec := &corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{},
			Containers: []corev1.Container{{
				Name: "app", SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{}},
			}},
		}
		mutate(spec)
		corpus[name] = spec
	}

	// Host namespaces.
	for _, network := range []bool{false, true} {
		for _, pid := range []bool{false, true} {
			for _, ipc := range []bool{false, true} {
				add(fmt.Sprintf("host namespaces %t/%t/%t", network, pid, ipc), func(spec *corev1.PodSpec) {
					spec.HostNetwork, spec.HostPID, spec.HostIPC = network, pid, ipc
				})
			}
		}
	}

	// Capabilities, with and without dropping all of them, also on Windows.
	capabilities := []corev1.Capability{
		"AUDIT_CONTROL", "AUDIT_READ", "AUDIT_WRITE", "BLOCK_SUSPEND", "BPF",
		"CHECKPOINT_RESTORE", "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "IPC_LOCK", "IPC_OWNER",
		"KILL", "LEASE", "LINUX_IMMUTABLE", "MAC_ADMIN", "MAC_OVERRIDE", "MKNOD", "NET_ADMIN", "NET_BIND_SERVICE",
		"NET_BROADCAST", "NET_RAW", "PERFMON", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYSLOG", "SYS_ADMIN",
		"SYS_BOOT", "SYS_CHROOT", "SYS_MODULE", "SYS_NICE", "SYS_PACCT", "SYS_PTRACE", "SYS_RAWIO", "SYS_RESOURCE",
		"SYS_TIME", "SYS_TTY_CONFIG", "WAKE_ALARM", "ALL", "CAP_SYS_ADMIN", "sys_admin",
	}
	for _, capability := range capabilities {
		for _, dropAll := range []bool{false, true} {
			add(fmt.Sprintf("capability %s drop all %t", capability, dropAll), func(spec *corev1.PodSpec) {
				spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{capability}
				if dropAll {
					spec.Containers[0].SecurityContext.Capabilities.Drop = []corev1.Capability{capabilityAll}
				}
			})
		}
	}
	add("capabilities on windows", func(spec *corev1.PodSpec) {
		spec.OS = &corev1.PodOS{Name: corev1.Windows}
		spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
	})
	add("no security context", func(spec *corev1.PodSpec) {
		spec.SecurityContext = nil
		spec.Containers[0].SecurityContext = nil
	})
	add("multiple containers", func(spec *corev1.PodSpec) {
		spec.InitContainers = []corev1.Container{{Name: "init", SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_RAW", "SYS_ADMIN"}},
		}}}
		spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debug", Ports: []corev1.ContainerPort{{HostPort: 9090}},
		}}}
		spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
		spec.Containers[0].Ports = []corev1.ContainerPort{{HostPort: 80}, {HostPort: 8080}}
	})

	// Every volume type, discovered from the volume source fields.
	sourceType := reflect.TypeFor[corev1.VolumeSource]()
	for i := range sourceType.NumField() {
		field := sourceType.Field(i)
		add("volume "+field.Name, func(spec *corev1.PodSpec) {
			volume := corev1.Volume{Name: field.Name}
			reflect.ValueOf(&volume.VolumeSource).Elem().Field(i).Set(reflect.New(field.Type.Elem()))
			spec.Volumes = []corev1.Volume{volume, {Name: "empty", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		})
	}
	add("volumes", func(spec *corev1.PodSpec) {
		spec.Volumes = []corev1.Volume{
			{Name: "a", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/a"}}},
			{Name: "b", VolumeSource: corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{}}},
			{Name: "c", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/c"}}},
		}
	})

	// Host ports.
	for _, port := range []int32{0, 1, 80, 65535} {
		add(fmt.Sprintf("host port %d", port), func(spec *corev1.PodSpec) {
			spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: port}}
		})
	}

	// Sysctls: the upstream safe ones and some unsafe ones.
	sysctls := append(baselineSysctls.UnsortedList(), "kernel.msgmax", "kernel.sem", "net.core.somaxconn",
		"net.ipv4.ip_forward", "net.ipv4.conf.all.forwarding", "net.ipv4.tcp_tw_reuse", "net.ipv4.tcp_max_syn_backlog",
		"net.ipv4.tcp_congestion_control", "net.ipv6.conf.all.disable_ipv6", "vm.max_map_count", "fs.file-max",
		"net/ipv4/ip_local_port_range")
	for _, sysctl := range sysctls {
		add("sysctl "+sysctl, func(spec *corev1.PodSpec) {
			spec.SecurityContext.Sysctls = []corev1.Sysctl{{Name: sysctl, Value: "1"}}
		})
	}

	// SELinux options, at pod and container level.
	seLinuxTypes := append(baselineSELinuxTypes.UnsortedList(), "spc_t", "unconfined_t", "container_logreader_t")
	for _, seLinuxType := range seLinuxTypes {
		for _, opts := range []corev1.SELinuxOptions{{Type: seLinuxType}, {Type: seLinuxType, User: "u"}, {Type: seLinuxType, Role: "r"}} {
			add(fmt.Sprintf("selinux pod %+v", opts), func(spec *corev1.PodSpec) { spec.SecurityContext.SELinuxOptions = &opts })
			add(fmt.Sprintf("selinux container %+v", opts), func(spec *corev1.PodSpec) {
				spec.Containers[0].SecurityContext.SELinuxOptions = &opts
			})
		}
	}

	// Seccomp profiles, at pod and container level, also on Windows.
	profiles := []*corev1.SeccompProfile{
		nil,
		{Type: corev1.SeccompProfileTypeRuntimeDefault},
		{Type: corev1.SeccompProfileTypeLocalhost},
		{Type: corev1.SeccompProfileTypeUnconfined},
		{Type: "Invalid"},
	}
	for _, podProfile := range profiles {
		for _, containerProfile := range profiles {
			for _, windows := range []bool{false, true} {
				add(fmt.Sprintf("seccomp %v/%v windows %t", podProfile, containerProfile, windows), func(spec *corev1.PodSpec) {
					spec.SecurityContext.SeccompProfile = podProfile
					spec.Containers[0].SecurityContext.SeccompProfile = containerProfile
					if windows {
						spec.OS = &corev1.PodOS{Name: corev1.Windows}
					}
				})
			}
		}
	}

	return corpus
}

func isWindows(spec *corev1.PodSpec) bool {
	return spec.OS != nil && spec.OS.Name == corev1.Windows
}

var _ = Describe("Alignment with the upstream checks", func() {
	noAllowances := &offloadingv1beta1.OffloadingSecurityPolicyAllowances{}
	metadata := &metav1.ObjectMeta{}

	It("relaxes only controls whose upstream checks override each other consistently", func() {
		for _, check := range psapolicy.DefaultChecks() {
			for _, overridden := range check.Versions[len(check.Versions)-1].OverrideCheckIDs {
				idx := slices.IndexFunc(controls, func(c control) bool { return c.restrictedCheck == check.ID })
				Expect(idx).ToNot(Equal(-1), "check %q overrides %q, but it is not the restricted check of a control", check.ID, overridden)
				Expect(controls[idx].baselineCheck).To(Equal(overridden), "check %q", check.ID)
			}
		}
	})

	// The waivers are consulted only when the upstream check fails. With no allowances, they must agree with the
	// upstream checks, so that they waive nothing more than the allowances permit and are not stricter than upstream.
	// Windows pods are skipped, since the restricted checks always accept them without consulting the waivers.
	It("agree with the upstream checks when nothing is allowed", func() {
		corpus := upstreamCorpus()
		for i := range controls {
			for id, waived := range map[psapolicy.CheckID]waiver{
				controls[i].baselineCheck: controls[i].baseline, controls[i].restrictedCheck: controls[i].restricted,
			} {
				// The restricted seccomp waiver accepts the Unconfined profile by design: it is verified below.
				if id == "" || waived == nil || id == "seccompProfile_restricted" {
					continue
				}
				for name, spec := range corpus {
					if isWindows(spec) {
						continue
					}
					Expect(waived(spec, noAllowances)).To(Equal(upstreamChecks[id](metadata, spec).Allowed), "check %q, pod %q", id, name)
				}
			}
		}
	})

	It("agree with the upstream restricted seccomp check, except for the Unconfined profile", func() {
		usesUnconfined := func(spec *corev1.PodSpec) bool {
			unconfined := func(profile *corev1.SeccompProfile) bool {
				return profile != nil && profile.Type == corev1.SeccompProfileTypeUnconfined
			}
			return (spec.SecurityContext != nil && unconfined(spec.SecurityContext.SeccompProfile)) ||
				(spec.Containers[0].SecurityContext != nil && unconfined(spec.Containers[0].SecurityContext.SeccompProfile))
		}

		for name, spec := range upstreamCorpus() {
			if isWindows(spec) {
				continue
			}
			expected := upstreamChecks["seccompProfile_restricted"](metadata, spec).Allowed
			if usesUnconfined(spec) && !expected {
				continue
			}
			Expect(seccompProfileRestrictedAllowed(spec, noAllowances)).To(Equal(expected), "pod %q", name)
		}
	})

	It("returns the same violations as the upstream evaluator when nothing is allowed", func() {
		upstream, err := psapolicy.NewEvaluator(psapolicy.DefaultChecks(), nil)
		Expect(err).ToNot(HaveOccurred())

		mutators := map[string]func(*metav1.ObjectMeta, *corev1.PodSpec){
			"as is": func(*metav1.ObjectMeta, *corev1.PodSpec) {},
			"privileged": func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) {
				spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: ptr.To(true)}
			},
			"unconfined AppArmor": func(meta *metav1.ObjectMeta, _ *corev1.PodSpec) {
				meta.Annotations = map[string]string{corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix + "app": "unconfined"}
			},
			"unmasked proc mount": func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) {
				spec.Containers[0].SecurityContext = &corev1.SecurityContext{ProcMount: ptr.To(corev1.UnmaskedProcMount)}
			},
			"host process": func(_ *metav1.ObjectMeta, spec *corev1.PodSpec) {
				spec.SecurityContext = &corev1.PodSecurityContext{
					WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: ptr.To(true)},
				}
			},
		}

		for name, original := range upstreamCorpus() {
			for mutatorName, mutate := range mutators {
				meta, spec := &metav1.ObjectMeta{}, original.DeepCopy()
				mutate(meta, spec)
				for _, level := range []offloadingv1beta1.PodSecurityLevel{
					offloadingv1beta1.PodSecurityLevelBaseline, offloadingv1beta1.PodSecurityLevelRestricted,
				} {
					expected := psapolicy.AggregateCheckResults(upstream.EvaluatePod(
						psaapi.LevelVersion{Level: psaapi.Level(level), Version: psaapi.LatestVersion()}, meta, spec))
					violations := Evaluate(meta, spec, &offloadingv1beta1.OffloadingSecurityPolicySpec{Level: level})
					Expect(violations).To(HaveLen(len(expected.ForbiddenReasons)), "pod %q (%s), level %s", name, mutatorName, level)
					for i := range expected.ForbiddenReasons {
						Expect(violations).To(ContainElement(HavePrefix(expected.ForbiddenReasons[i])),
							"pod %q (%s), level %s", name, mutatorName, level)
					}
				}
			}
		}
	})
})
