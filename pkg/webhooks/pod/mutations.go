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

package pod

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
	liqoconst "github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/securitypolicy"
	"github.com/liqotech/liqo/pkg/utils"
)

// getVirtualNodeToleration returns a new Toleration for the Liqo's virtual-nodes.
func getVirtualNodeToleration() corev1.Toleration {
	return corev1.Toleration{
		Key:      liqoconst.VirtualNodeTolerationKey,
		Operator: corev1.TolerationOpExists,
		Effect:   corev1.TaintEffectNoExecute,
	}
}

// createTolerationFromNamespaceOffloading creates a new virtualNodeToleration in case of LocalAndRemotePodOffloadingStrategyType
// or RemotePodOffloadingStrategyType. In case of PodOffloadingStrategyType not recognized, returns an error.
func createTolerationFromNamespaceOffloading(strategy offloadingv1beta1.PodOffloadingStrategyType) (corev1.Toleration, error) {
	var toleration corev1.Toleration
	switch strategy {
	case offloadingv1beta1.LocalAndRemotePodOffloadingStrategyType, offloadingv1beta1.RemotePodOffloadingStrategyType:
		// The virtual-node toleration must be added.
		toleration = getVirtualNodeToleration()
	case offloadingv1beta1.LocalPodOffloadingStrategyType:
		return toleration, nil
	default:
		err := fmt.Errorf("unknown PodOffloadingStrategyType %q", strategy)
		return toleration, err
	}
	return toleration, nil
}

// createNodeSelectorFromNamespaceOffloading creates the right NodeSelector according to the PodOffloadingStrategy chosen.
func createNodeSelectorFromNamespaceOffloading(nsoff *offloadingv1beta1.NamespaceOffloading) (*corev1.NodeSelector, error) {
	nodeSelector := nsoff.Spec.ClusterSelector
	switch nsoff.Spec.PodOffloadingStrategy {
	case offloadingv1beta1.RemotePodOffloadingStrategyType:
		// To ensure that the pod is not scheduled on local nodes is necessary to add to every NodeSelectorTerm a
		// new NodeSelectorRequirement. This NodeSelectorRequirement requires explicitly the label
		// "liqo.io/type=virtual-node" to exclude local nodes from the scheduler choice.
		if len(nodeSelector.NodeSelectorTerms) == 0 {
			nodeSelector.NodeSelectorTerms = []corev1.NodeSelectorTerm{{}}
		}

		for i := range nodeSelector.NodeSelectorTerms {
			nodeSelector.NodeSelectorTerms[i].MatchExpressions = append(nodeSelector.NodeSelectorTerms[i].MatchExpressions,
				corev1.NodeSelectorRequirement{
					Key:      liqoconst.TypeLabel,
					Operator: corev1.NodeSelectorOpIn,
					Values:   []string{liqoconst.TypeNode},
				})
		}

	case offloadingv1beta1.LocalAndRemotePodOffloadingStrategyType:
		// In case the selector is empty, it is not necessary to modify anything, as it already allows pods to be scheduled on all nodes.
		if len(nodeSelector.NodeSelectorTerms) == 0 {
			return nil, nil
		}

		// Otherwise, let add a new NodeSelectorTerm that allows scheduling pods also on local nodes.
		newNodeSelectorTerm := corev1.NodeSelectorTerm{
			MatchExpressions: []corev1.NodeSelectorRequirement{{
				Key:      liqoconst.TypeLabel,
				Operator: corev1.NodeSelectorOpNotIn,
				Values:   []string{liqoconst.TypeNode},
			}},
		}
		nodeSelector.NodeSelectorTerms = append(nodeSelector.NodeSelectorTerms, newNodeSelectorTerm)
	case offloadingv1beta1.LocalPodOffloadingStrategyType:
		return nil, nil
	default:
		err := fmt.Errorf("unknown PodOffloadingStrategyType %q", nsoff.Spec.PodOffloadingStrategy)
		return nil, err
	}
	return &nodeSelector, nil
}

// fillPodWithTheNewNodeSelector gets the previously computed NodeSelector imposed by the PodOffloadingStrategy and
// merges it with the Pod NodeSelector if it is already present. It simply adds it to the Pod if previously unset.
func fillPodWithTheNewNodeSelector(imposedNodeSelector *corev1.NodeSelector, pod *corev1.Pod) {
	// No need to modify the pod affinities in case of empty selector.
	if imposedNodeSelector == nil {
		return
	}

	// To preserve the Pod Affinity content, it is necessary to add the imposedNodeSelector according to what
	// is already present in the Pod Affinity.
	switch {
	case pod.Spec.Affinity == nil:
		pod.Spec.Affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: imposedNodeSelector,
			},
		}
	case pod.Spec.Affinity.NodeAffinity == nil:
		pod.Spec.Affinity.NodeAffinity = &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: imposedNodeSelector,
		}
	case pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil ||
		len(pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms) == 0:
		pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = imposedNodeSelector
	default:
		*pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution =
			utils.MergeNodeSelector(pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution, imposedNodeSelector)
	}
}

// fillPodWithSecurityPolicyNodeSelector restricts the virtual nodes the pod can be scheduled on to those whose provider
// cluster admits it, according to the offloading security policy they advertise (see securitypolicy.NodeLabels), so
// that the pod is not denied upon offloading. Local nodes are still allowed if allowLocal is true, while the pod is not
// modified if any provider cluster admits it.
func fillPodWithSecurityPolicyNodeSelector(pod *corev1.Pod, allowLocal bool) {
	requirements := securitypolicy.Requirements(&pod.ObjectMeta, &pod.Spec)
	if len(requirements) == 0 {
		return
	}

	nodeSelector := &corev1.NodeSelector{NodeSelectorTerms: securitypolicy.NodeSelectorTerms(requirements)}
	if allowLocal {
		nodeSelector.NodeSelectorTerms = append(nodeSelector.NodeSelectorTerms, corev1.NodeSelectorTerm{
			MatchExpressions: []corev1.NodeSelectorRequirement{{
				Key:      liqoconst.TypeLabel,
				Operator: corev1.NodeSelectorOpNotIn,
				Values:   []string{liqoconst.TypeNode},
			}},
		})
	}

	klog.V(5).Infof("Offloading security policy NodeSelector: %s", nodeSelector)
	fillPodWithTheNewNodeSelector(nodeSelector, pod)
}

// mutatePod checks the NamespaceOffloading CR associated with the Pod's Namespace.
// The pod is modified in different ways according to the PodOffloadingStrategyType
// chosen in the CR. Three possible modifications:
// - The VirtualNodeToleration is added to the Pod Toleration if necessary.
// - The old Pod NodeSelector is substituted with a new one according to the PodOffloadingStrategyType.
// - The virtual nodes the pod can be scheduled on are restricted to those whose offloading security policy admits it.
// The first two are not applied when the Liqo runtime class is specified, as it already enforces the scheduling on
// virtual nodes, while the last one is applied whenever the pod may be offloaded, including with the runtime class.
func mutatePod(namespaceOffloading *offloadingv1beta1.NamespaceOffloading, pod *corev1.Pod, liqoRuntimeClassName string) error {
	// The NamespaceOffloading CR contains information about the PodOffloadingStrategy and
	// the NodeSelector inserted by the user (ClusterSelector field).
	strategy := namespaceOffloading.Spec.PodOffloadingStrategy
	klog.V(5).Infof("Chosen strategy: %s", strategy)

	hasLiqoRuntimeClass := pod.Spec.RuntimeClassName != nil && *pod.Spec.RuntimeClassName == liqoRuntimeClassName

	// If strategy is equal to LocalPodOffloadingStrategy, the pod is never offloaded, unless it has the Liqo runtime class.
	if strategy == offloadingv1beta1.LocalPodOffloadingStrategyType {
		if hasLiqoRuntimeClass {
			fillPodWithSecurityPolicyNodeSelector(pod, true)
		}
		return nil
	}

	// Mutate Pod affinity and tolerations only if the Pod has NOT the Liqo runtime class.
	if !hasLiqoRuntimeClass {
		// Create the right Toleration according to the PodOffloadingStrategy case.
		toleration, err := createTolerationFromNamespaceOffloading(namespaceOffloading.Spec.PodOffloadingStrategy)
		if err != nil {
			wErr := fmt.Errorf("unable to define tolerations for pod %q in namespace %q: %w",
				pod.Name, namespaceOffloading.Namespace, err)
			klog.Error(wErr)
			return wErr
		}
		klog.V(5).Infof("Generated Toleration: %s", toleration.String())

		// It is necessary to add the just created toleration.
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, toleration)

		// Create the right NodeSelector according to the PodOffloadingStrategy case.
		imposedNodeSelector, err := createNodeSelectorFromNamespaceOffloading(namespaceOffloading)
		if err != nil {
			wErr := fmt.Errorf("unable to define node selectors for pod %q in namespace %q: %w",
				pod.Name, namespaceOffloading.Namespace, err)
			klog.Error(wErr)
			return wErr
		}
		klog.V(5).Infof("ImposedNodeSelector: %s", imposedNodeSelector)

		// Enforce the new NodeSelector policy imposed by the NamespaceOffloading creator.
		fillPodWithTheNewNodeSelector(imposedNodeSelector, pod)
		klog.V(5).Infof("Pod NodeSelector: %s", imposedNodeSelector)
	}

	// The local nodes remain allowed, unless the strategy requires the pod to be offloaded.
	fillPodWithSecurityPolicyNodeSelector(pod, strategy != offloadingv1beta1.RemotePodOffloadingStrategyType)
	return nil
}
