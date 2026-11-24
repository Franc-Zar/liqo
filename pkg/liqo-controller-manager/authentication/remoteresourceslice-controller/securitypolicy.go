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

package remoteresourceslicecontroller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	klog "k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authv1beta1 "github.com/liqotech/liqo/apis/authentication/v1beta1"
	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	"github.com/liqotech/liqo/internal/crdReplicator/reflection"
	"github.com/liqotech/liqo/pkg/securitypolicy"
	"github.com/liqotech/liqo/pkg/utils/getters"
	liqolabels "github.com/liqotech/liqo/pkg/utils/labels"
)

// securityPolicyNodeLabels returns the labels advertising the OffloadingSecurityPolicy enforced on the pods offloaded
// by the consumer cluster of the given ResourceSlice, to be set on the corresponding virtual node.
func (r *RemoteResourceSliceReconciler) securityPolicyNodeLabels(ctx context.Context,
	resourceSlice *authv1beta1.ResourceSlice) (map[string]string, error) {
	policy, err := securitypolicy.Resolve(ctx, r.Client, *resourceSlice.Spec.ConsumerClusterID)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve the offloading security policy of cluster %q: %w", *resourceSlice.Spec.ConsumerClusterID, err)
	}

	return securitypolicy.NodeLabels(&policy), nil
}

// securityPolicyEnquer enqueues all the remote ResourceSlices when an OffloadingSecurityPolicy changes, since its
// cluster selector might select any consumer cluster.
func (r *RemoteResourceSliceReconciler) securityPolicyEnquer() func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, _ client.Object) []reconcile.Request {
		selector := reflection.ReplicatedResourcesLabelSelector()
		sel, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil {
			klog.Errorf("Failed to build the selector of the remote ResourceSlices: %v", err)
			return nil
		}
		return r.resourceSliceRequests(ctx, sel)
	}
}

// foreignClusterEnquer enqueues the remote ResourceSlices of a consumer cluster when the labels of its ForeignCluster
// change, since they determine the OffloadingSecurityPolicies selecting it.
func (r *RemoteResourceSliceReconciler) foreignClusterEnquer() func(ctx context.Context, obj client.Object) []reconcile.Request {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		fc, ok := obj.(*liqov1beta1.ForeignCluster)
		if !ok || fc.Spec.ClusterID == "" {
			return nil
		}
		return r.resourceSliceRequests(ctx, liqolabels.RemoteLabelSelectorForCluster(string(fc.Spec.ClusterID)))
	}
}

// resourceSliceRequests returns the reconcile requests for the ResourceSlices matching the given selector.
func (r *RemoteResourceSliceReconciler) resourceSliceRequests(ctx context.Context, selector labels.Selector) []reconcile.Request {
	resSlices, err := getters.ListResourceSlicesByLabel(ctx, r.Client, corev1.NamespaceAll, selector)
	if err != nil {
		klog.Errorf("Failed to retrieve the ResourceSlices matching %q: %v", selector, err)
		return nil
	}

	reqs := make([]reconcile.Request, len(resSlices))
	for i := range resSlices {
		reqs[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: resSlices[i].Name, Namespace: resSlices[i].Namespace}}
	}
	return reqs
}
