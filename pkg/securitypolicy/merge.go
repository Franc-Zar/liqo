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
	offloadingv1beta1 "github.com/liqotech/liqo/apis/offloading/v1beta1"
)

// Merge returns the spec of the effective policy enforced when the provided [offloadingv1beta1.OffloadingSecurityPolicy]
// objects selecting a consumer cluster are all applied together. Policies are additive: the level is the most
// permissive one they set (restricted, when none sets it), and the allowances are the union of theirs. The
// ClusterSelector of the returned spec is unset, since the effective policy is never matched against clusters.
func Merge(policies ...offloadingv1beta1.OffloadingSecurityPolicy) offloadingv1beta1.OffloadingSecurityPolicySpec {
	return offloadingv1beta1.OffloadingSecurityPolicySpec{
		Level: getEffectiveLevel(policies...),
		Allow: getEffectiveAllowances(policies...),
	}
}
