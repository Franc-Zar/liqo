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

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OffloadingSecurityPolicyKind is the kind name used to register the OffloadingSecurityPolicy CRD.
const OffloadingSecurityPolicyKind = "OffloadingSecurityPolicy"

// OffloadingSecurityPolicyViolationCause is the type of the status causes with which the provider cluster denies the
// shadow pods violating its OffloadingSecurityPolicy, allowing the consumer cluster to recognize these denials.
const OffloadingSecurityPolicyViolationCause metav1.CauseType = "OffloadingSecurityPolicyViolation"

// PodSecurityLevel is a Pod Security Standards profile.
// +kubebuilder:validation:Enum=privileged;baseline;restricted
type PodSecurityLevel string

const (
	// PodSecurityLevelPrivileged is the unrestricted profile: every pod is allowed.
	PodSecurityLevelPrivileged PodSecurityLevel = "privileged"
	// PodSecurityLevelBaseline is the minimally restrictive profile, preventing known privilege escalations.
	PodSecurityLevelBaseline PodSecurityLevel = "baseline"
	// PodSecurityLevelRestricted is the heavily restricted profile, following pod hardening best practices.
	PodSecurityLevelRestricted PodSecurityLevel = "restricted"
)

// HostNamespace is a host namespace a pod can share.
// +kubebuilder:validation:Enum=HostNetwork;HostPID;HostIPC
type HostNamespace string

const (
	// HostNamespaceNetwork is the host network namespace (spec.hostNetwork).
	HostNamespaceNetwork HostNamespace = "HostNetwork"
	// HostNamespacePID is the host PID namespace (spec.hostPID).
	HostNamespacePID HostNamespace = "HostPID"
	// HostNamespaceIPC is the host IPC namespace (spec.hostIPC).
	HostNamespaceIPC HostNamespace = "HostIPC"
)

// HostPortRange is an inclusive range of host ports.
// +kubebuilder:validation:XValidation:rule="self.max >= self.min",message="max must be greater than or equal to min"
type HostPortRange struct {
	// Min is the first port of the range.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Min int32 `json:"min"`
	// Max is the last port of the range.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Max int32 `json:"max"`
}

// OffloadingSecurityPolicyAllowances lists what the policy allows on top of its level.
// Every field only relaxes the level: allowances are never used to restrict. They cover the baseline controls only,
// so the controls added by the restricted level cannot be relaxed.
// +kubebuilder:validation:MinProperties=1
type OffloadingSecurityPolicyAllowances struct {
	// HostNamespaces are the host namespaces offloaded pods may share.
	// +listType=set
	// +optional
	HostNamespaces []HostNamespace `json:"hostNamespaces,omitempty"`
	// Privileged allows privileged containers.
	// +optional
	Privileged bool `json:"privileged,omitempty"`
	// Capabilities are the Linux capabilities containers may add on top of those allowed by the level.
	// +listType=set
	// +optional
	Capabilities []corev1.Capability `json:"capabilities,omitempty"`
	// HostPaths are the hostPath volume path prefixes offloaded pods may mount.
	// +listType=set
	// +optional
	HostPaths []string `json:"hostPaths,omitempty"`
	// HostPorts are the host port ranges containers may bind.
	// +listType=atomic
	// +optional
	HostPorts []HostPortRange `json:"hostPorts,omitempty"`
	// Sysctls are the sysctls pods may set on top of the safe set allowed by the level.
	// A trailing '*' matches every sysctl with that prefix (e.g. "net.ipv4.*").
	// +listType=set
	// +optional
	Sysctls []string `json:"sysctls,omitempty"`
	// SELinuxTypes are the SELinux types pods may set on top of those allowed by the level.
	// +listType=set
	// +optional
	SELinuxTypes []string `json:"seLinuxTypes,omitempty"`
	// UnconfinedSeccomp allows the Unconfined seccomp profile.
	// +optional
	UnconfinedSeccomp bool `json:"unconfinedSeccomp,omitempty"`
	// UnconfinedAppArmor allows the unconfined AppArmor profile.
	// +optional
	UnconfinedAppArmor bool `json:"unconfinedAppArmor,omitempty"`
	// UnmaskedProcMount allows the Unmasked procMount type.
	// +optional
	UnmaskedProcMount bool `json:"unmaskedProcMount,omitempty"`
	// HostProcess allows Windows HostProcess containers.
	// +optional
	HostProcess bool `json:"hostProcess,omitempty"`
}

// OffloadingSecurityPolicySpec defines the security policy enforced on the pods offloaded by the selected consumer clusters.
// +kubebuilder:validation:XValidation:rule="has(self.level) || has(self.allow)",message="at least one of level and allow must be set"
type OffloadingSecurityPolicySpec struct {
	// ClusterSelector selects the consumer clusters the policy applies to, matching the labels of their
	// ForeignCluster (e.g. liqo.io/remote-cluster-id). An empty selector selects every consumer.
	ClusterSelector metav1.LabelSelector `json:"clusterSelector"`
	// Level is the Pod Security Standards profile the policy grants. The most permissive level among the policies
	// selecting a consumer cluster applies, or the restricted one when none of them sets it. When unset, the policy
	// only grants its allowances on top of the level set by the others (restricted, if none sets it).
	// +optional
	Level PodSecurityLevel `json:"level,omitempty"`
	// Allow lists what the policy allows on top of the level, and takes precedence over it.
	// Allowances relax the baseline controls at any level, while the controls added only by the restricted level
	// (e.g. runAsNonRoot, allowPrivilegeEscalation, volume types) cannot be relaxed: use the baseline level instead.
	// Allow is ignored when the level is privileged.
	// +optional
	Allow OffloadingSecurityPolicyAllowances `json:"allow,omitzero"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,categories=liqo,shortName=offsecpol;osp
// +kubebuilder:printcolumn:name="Level",type=string,JSONPath=`.spec.level`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +genclient
// +genclient:nonNamespaced

// OffloadingSecurityPolicy defines the security policy the provider enforces on the pods offloaded by the selected consumer clusters.
//
// Policies behave like NetworkPolicies: a consumer cluster selected by no policy is unrestricted, consistently with
// Kubernetes, which enforces no Pod Security Standard unless configured to. Once a policy selects it, only what the
// selecting policies grant is admitted, and the order they are applied in does not matter: the effective level is the
// most permissive one they set (restricted if none sets it), and the effective allowances are the union of theirs.
// Liqo creates no policy. The OffloadingSecurityPolicy lives only in the provider cluster and is never replicated.
type OffloadingSecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OffloadingSecurityPolicySpec `json:"spec"`
}

// +kubebuilder:object:root=true

// OffloadingSecurityPolicyList contains a list of OffloadingSecurityPolicy.
type OffloadingSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OffloadingSecurityPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OffloadingSecurityPolicy{}, &OffloadingSecurityPolicyList{})
}
