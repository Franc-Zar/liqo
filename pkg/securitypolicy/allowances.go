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
	"path"
	"reflect"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

// The waivers decide whether the allowances cover every reason why the corresponding upstream check forbids the pod.
// They are evaluated only when the upstream check fails, and they accept exactly what the upstream check accepts plus
// what the allowances permit, as verified by the tests.

const (
	capabilityAll            corev1.Capability = "ALL"
	capabilityNetBindService corev1.Capability = "NET_BIND_SERVICE"
)

// The following sets mirror unexported values of the latest upstream checks.
var (
	// baselineCapabilities are the capabilities containers may add at the baseline level.
	baselineCapabilities = sets.New[corev1.Capability]("AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID",
		"KILL", "MKNOD", capabilityNetBindService, "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT")
	// baselineSysctls are the sysctls pods may set at the baseline level.
	baselineSysctls = sets.New("kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.tcp_syncookies",
		"net.ipv4.ping_group_range", "net.ipv4.ip_unprivileged_port_start", "net.ipv4.ip_local_reserved_ports",
		"net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_keepalive_intvl",
		"net.ipv4.tcp_keepalive_probes", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem")
	// baselineSELinuxTypes are the SELinux types pods may set at the baseline level.
	baselineSELinuxTypes = sets.New("", "container_t", "container_init_t", "container_kvm_t", "container_engine_t")
	// restrictedVolumeTypes are the volume types pods may use at the restricted level, named after their field.
	restrictedVolumeTypes = sets.New("configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "image",
		"persistentVolumeClaim", "projected", "secret")
)

// hostNamespacesAllowed waives the hostNamespaces check when every host namespace the pod shares is allowed.
func hostNamespacesAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	allowed := sets.New(allow.HostNamespaces...)
	return (!podSpec.HostNetwork || allowed.Has(offloadingv1beta1.HostNamespaceNetwork)) &&
		(!podSpec.HostPID || allowed.Has(offloadingv1beta1.HostNamespacePID)) &&
		(!podSpec.HostIPC || allowed.Has(offloadingv1beta1.HostNamespaceIPC))
}

// capabilitiesBaselineAllowed waives the capabilities_baseline check when every added capability is either a
// baseline one or an allowed one.
func capabilitiesBaselineAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	allowed := baselineCapabilities.Union(sets.New(allow.Capabilities...))
	return allContainers(podSpec, func(container *corev1.Container) bool {
		sc := container.SecurityContext
		return sc == nil || sc.Capabilities == nil || allowed.HasAll(sc.Capabilities.Add...)
	})
}

// capabilitiesRestrictedAllowed waives the capabilities_restricted check when every container drops all the
// capabilities and adds only NET_BIND_SERVICE or allowed ones.
func capabilitiesRestrictedAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	allowed := sets.New(allow.Capabilities...).Insert(capabilityNetBindService)
	return allContainers(podSpec, func(container *corev1.Container) bool {
		sc := container.SecurityContext
		return sc != nil && sc.Capabilities != nil && slices.Contains(sc.Capabilities.Drop, capabilityAll) &&
			allowed.HasAll(sc.Capabilities.Add...)
	})
}

// hostPathVolumesAllowed waives the hostPathVolumes check when every hostPath volume is under an allowed path.
func hostPathVolumesAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	return !slices.ContainsFunc(podSpec.Volumes, func(volume corev1.Volume) bool {
		return volume.HostPath != nil && !hostPathAllowed(volume.HostPath.Path, allow.HostPaths)
	})
}

// restrictedVolumesAllowed waives the restrictedVolumes check when every volume is either of a restricted type or a
// hostPath volume under an allowed path.
func restrictedVolumesAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	return !slices.ContainsFunc(podSpec.Volumes, func(volume corev1.Volume) bool {
		return !restrictedVolumeTypes.Has(volumeSourceType(&volume.VolumeSource)) &&
			(volume.HostPath == nil || !hostPathAllowed(volume.HostPath.Path, allow.HostPaths))
	})
}

// hostPortsAllowed waives the hostPorts check when every host port is within an allowed range. When the host network
// is allowed and used, every host port is accepted, since such a pod can bind any port of the host anyway.
func hostPortsAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	if podSpec.HostNetwork && hostNetworkAllowed(allow) {
		return true
	}
	return allContainers(podSpec, func(container *corev1.Container) bool {
		return !slices.ContainsFunc(container.Ports, func(port corev1.ContainerPort) bool {
			return port.HostPort != 0 && !hostPortAllowed(port.HostPort, allow.HostPorts)
		})
	})
}

// sysctlsAllowed waives the sysctls check when every sysctl is either a baseline one or an allowed one.
func sysctlsAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	return podSpec.SecurityContext == nil || !slices.ContainsFunc(podSpec.SecurityContext.Sysctls, func(sysctl corev1.Sysctl) bool {
		return !baselineSysctls.Has(sysctl.Name) && !sysctlAllowed(sysctl.Name, allow.Sysctls)
	})
}

// seLinuxOptionsAllowed waives the seLinuxOptions check when every SELinux type is either a baseline one or an allowed
// one, and neither the SELinux user nor the role is set.
func seLinuxOptionsAllowed(podSpec *corev1.PodSpec, allow *allowances) bool {
	allowed := baselineSELinuxTypes.Union(sets.New(allow.SELinuxTypes...))
	valid := func(opts *corev1.SELinuxOptions) bool {
		return opts == nil || (allowed.Has(opts.Type) && opts.User == "" && opts.Role == "")
	}

	if podSpec.SecurityContext != nil && !valid(podSpec.SecurityContext.SELinuxOptions) {
		return false
	}
	return allContainers(podSpec, func(container *corev1.Container) bool {
		return container.SecurityContext == nil || valid(container.SecurityContext.SELinuxOptions)
	})
}

// seccompProfileRestrictedAllowed waives the seccompProfile_restricted check when every container has a seccomp
// profile, set either by itself or by the pod, and the profile is RuntimeDefault, Localhost or the allowed Unconfined.
func seccompProfileRestrictedAllowed(podSpec *corev1.PodSpec, _ *allowances) bool {
	valid := func(profile *corev1.SeccompProfile) bool {
		return profile.Type == corev1.SeccompProfileTypeRuntimeDefault || profile.Type == corev1.SeccompProfileTypeLocalhost ||
			profile.Type == corev1.SeccompProfileTypeUnconfined
	}

	var podProfile *corev1.SeccompProfile
	if podSpec.SecurityContext != nil {
		podProfile = podSpec.SecurityContext.SeccompProfile
	}
	if podProfile != nil && !valid(podProfile) {
		return false
	}
	return allContainers(podSpec, func(container *corev1.Container) bool {
		if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
			return valid(container.SecurityContext.SeccompProfile)
		}
		return podProfile != nil
	})
}

// hostNetworkAllowed returns whether the allowances permit the host network namespace.
func hostNetworkAllowed(allow *allowances) bool {
	return slices.Contains(allow.HostNamespaces, offloadingv1beta1.HostNamespaceNetwork)
}

// hostPathAllowed returns whether the host path is one of the allowed paths or one of their descendants. The
// comparison is made on whole path elements, so that "/var" allows "/var/log" but not "/variable".
func hostPathAllowed(hostPath string, allowed []string) bool {
	hostPath = path.Clean(hostPath)
	return slices.ContainsFunc(allowed, func(prefix string) bool {
		prefix = path.Clean(prefix)
		return prefix == "/" || hostPath == prefix || strings.HasPrefix(hostPath, prefix+"/")
	})
}

// hostPortAllowed returns whether the host port is within one of the allowed ranges.
func hostPortAllowed(port int32, allowed []offloadingv1beta1.HostPortRange) bool {
	return slices.ContainsFunc(allowed, func(r offloadingv1beta1.HostPortRange) bool {
		return port >= r.Min && port <= r.Max
	})
}

// sysctlAllowed returns whether the sysctl matches one of the allowed names, where a trailing '*' matches any suffix.
func sysctlAllowed(sysctl string, allowed []string) bool {
	return slices.ContainsFunc(allowed, func(name string) bool {
		if prefix, ok := strings.CutSuffix(name, "*"); ok {
			return strings.HasPrefix(sysctl, prefix)
		}
		return sysctl == name
	})
}

// volumeSourceType returns the type of the volume, named after the field of the volume source that is set.
func volumeSourceType(source *corev1.VolumeSource) string {
	value := reflect.ValueOf(source).Elem()
	for i := range value.NumField() {
		if field := value.Field(i); field.Kind() == reflect.Pointer && !field.IsNil() {
			name, _, _ := strings.Cut(value.Type().Field(i).Tag.Get("json"), ",")
			return name
		}
	}
	return "unknown"
}

// allContainers returns whether the predicate holds for every init, regular and ephemeral container of the pod spec.
func allContainers(podSpec *corev1.PodSpec, predicate func(container *corev1.Container) bool) bool {
	for i := range podSpec.InitContainers {
		if !predicate(&podSpec.InitContainers[i]) {
			return false
		}
	}
	for i := range podSpec.Containers {
		if !predicate(&podSpec.Containers[i]) {
			return false
		}
	}
	for i := range podSpec.EphemeralContainers {
		// EphemeralContainerCommon has the same fields as Container, as relied upon by the upstream checks too.
		if !predicate((*corev1.Container)(&podSpec.EphemeralContainers[i].EphemeralContainerCommon)) {
			return false
		}
	}
	return true
}
