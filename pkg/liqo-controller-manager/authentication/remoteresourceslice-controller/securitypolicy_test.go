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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authv1beta1 "github.com/liqotech/liqo/apis/authentication/v1beta1"
	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/securitypolicy"
)

var _ = Describe("Offloading security policy advertisement", func() {
	const consumerID liqov1beta1.ClusterID = "consumer"

	var (
		ctx        context.Context
		objects    []client.Object
		recorder   *record.FakeRecorder
		reconciler *RemoteResourceSliceReconciler
	)

	remoteSlice := func(name, namespace string, origin liqov1beta1.ClusterID) *authv1beta1.ResourceSlice {
		return &authv1beta1.ResourceSlice{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
				consts.ReplicationOriginLabel: string(origin), consts.ReplicationStatusLabel: "true",
			}},
			Spec: authv1beta1.ResourceSliceSpec{ConsumerClusterID: ptr.To(origin)},
		}
	}
	basePolicy := func() *offloadingv1beta1.OffloadingSecurityPolicy {
		return &offloadingv1beta1.OffloadingSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "baseline"},
			Spec:       offloadingv1beta1.OffloadingSecurityPolicySpec{Level: offloadingv1beta1.PodSecurityLevelBaseline},
		}
	}

	BeforeEach(func() {
		ctx = context.Background()
		objects = []client.Object{
			remoteSlice("consumer-slice", "tenant-consumer", consumerID),
			remoteSlice("other-slice", "tenant-other", "other"),
			// A local ResourceSlice (not replicated), which must never be enqueued.
			&authv1beta1.ResourceSlice{ObjectMeta: metav1.ObjectMeta{Name: "local-slice", Namespace: "tenant-other"}},
		}
	})

	JustBeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(authv1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(liqov1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(offloadingv1beta1.AddToScheme(scheme)).To(Succeed())
		recorder = record.NewFakeRecorder(10)
		reconciler = &RemoteResourceSliceReconciler{
			Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(),
			eventRecorder: recorder,
		}
	})

	Describe("the securityPolicyNodeLabels function", func() {
		var (
			labels map[string]string
			err    error
		)

		JustBeforeEach(func() {
			labels, err = reconciler.securityPolicyNodeLabels(ctx, remoteSlice("consumer-slice", "tenant-consumer", consumerID))
		})

		When("no policy selects the consumer cluster", func() {
			It("advertises the privileged level, with every feature allowed", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(labels).To(HaveKeyWithValue(securitypolicy.LevelNodeLabel, "privileged"))
				for _, feature := range securitypolicy.Features {
					Expect(labels).To(HaveKeyWithValue(feature.NodeLabel(), securitypolicy.FeatureAllowed))
				}
			})
		})

		When("a policy relaxes the baseline one for the consumer cluster", func() {
			BeforeEach(func() {
				objects = append(objects, basePolicy(), &offloadingv1beta1.OffloadingSecurityPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "relax"},
					Spec: offloadingv1beta1.OffloadingSecurityPolicySpec{
						ClusterSelector: metav1.LabelSelector{MatchLabels: map[string]string{consts.RemoteClusterID: string(consumerID)}},
						Allow: offloadingv1beta1.OffloadingSecurityPolicyAllowances{
							HostNamespaces: []offloadingv1beta1.HostNamespace{offloadingv1beta1.HostNamespaceNetwork},
						},
					},
				})
			})

			It("advertises the effective policy", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(labels).To(Equal(map[string]string{
					securitypolicy.LevelNodeLabel:                 "baseline",
					securitypolicy.FeatureHostNetwork.NodeLabel(): securitypolicy.FeatureAllowed,
				}))
			})
		})
	})

	It("enqueues all the remote ResourceSlices when a policy changes", func() {
		Expect(reconciler.securityPolicyEnquer()(ctx, basePolicy())).To(ConsistOf(
			reconcile.Request{NamespacedName: types.NamespacedName{Name: "consumer-slice", Namespace: "tenant-consumer"}},
			reconcile.Request{NamespacedName: types.NamespacedName{Name: "other-slice", Namespace: "tenant-other"}},
		))
	})

	It("enqueues the remote ResourceSlices of the cluster when its ForeignCluster labels change", func() {
		fc := &liqov1beta1.ForeignCluster{Spec: liqov1beta1.ForeignClusterSpec{ClusterID: consumerID}}
		Expect(reconciler.foreignClusterEnquer()(ctx, fc)).To(ConsistOf(
			reconcile.Request{NamespacedName: types.NamespacedName{Name: "consumer-slice", Namespace: "tenant-consumer"}},
		))
	})
})
