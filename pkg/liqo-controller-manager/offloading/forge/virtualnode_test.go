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

package forge_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/liqo-controller-manager/offloading/forge"
)

var _ = Describe("MutateVirtualNode", func() {
	const clusterID liqov1beta1.ClusterID = "provider"

	var virtualNode *offloadingv1beta1.VirtualNode

	mutate := func(nodeLabels map[string]string) {
		Expect(forge.MutateVirtualNode(context.Background(), nil, virtualNode, clusterID,
			&forge.VirtualNodeOptions{NodeLabels: nodeLabels}, nil, nil, nil)).To(Succeed())
	}

	BeforeEach(func() {
		virtualNode = forge.VirtualNode("name", "namespace")
		virtualNode.Spec.Labels = map[string]string{
			"user-label":     "value",
			"provider-label": "old",
			consts.SecurityPolicyNodeLabelPrefix + "level":        "privileged",
			consts.SecurityPolicyNodeLabelPrefix + "host-network": "allowed",
		}
	})

	It("replaces the security policy labels with the ones of the ResourceSlice, dropping the stale ones", func() {
		mutate(map[string]string{
			"provider-label": "new",
			consts.SecurityPolicyNodeLabelPrefix + "level": "baseline",
		})
		Expect(virtualNode.Spec.Labels).To(Equal(map[string]string{
			"user-label":           "value",
			"provider-label":       "new",
			consts.RemoteClusterID: string(clusterID),
			consts.SecurityPolicyNodeLabelPrefix + "level": "baseline",
		}))
	})
})
