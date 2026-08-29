// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strings"
	"testing"

	"github.com/becash143/authz-graph/internal/graph"
	"github.com/becash143/authz-graph/internal/steampipe"
)

func TestKubernetesRBAC_AgainstFakeSteampipe(t *testing.T) {
	client := &steampipe.Client{Binary: "../steampipe/testdata/fake_steampipe.sh"}
	result, err := KubernetesRBAC(client)
	if err != nil {
		t.Fatalf("KubernetesRBAC: %v", err)
	}

	g := graph.New()
	if err := result.MergeInto(g); err != nil {
		t.Fatalf("MergeInto: %v", err)
	}

	// web-app ServiceAccount is bound (via pod-reader-binding) to the
	// pod-reader Role, which grants get/list/watch on pods, per the
	// fake fixture.
	paths, err := graph.WhyAccess(g, "k8s:sa:prod/web-app", "get", "pods")
	if err != nil {
		t.Fatalf("WhyAccess: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path for web-app's pod-reader access, got %d: %+v", len(paths), paths)
	}
	if len(paths[0].Hops) != 2 {
		t.Fatalf("expected bound_by -> grants (2 hops), got %d", len(paths[0].Hops))
	}

	// web-app should have no access to a resource pod-reader doesn't
	// grant.
	paths, err = graph.WhyAccess(g, "k8s:sa:prod/web-app", "delete", "secrets")
	if err != nil {
		t.Fatalf("WhyAccess: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected no path for an ungranted verb/resource, got %d: %+v", len(paths), paths)
	}

	// The fake fixture's ClusterRoleBinding references ServiceAccount
	// kube-system/bootstrap-signer, which kubernetes_service_account
	// never returns (mirrors a real cluster where the ingest
	// credential can read bindings cluster-wide but can't list
	// ServiceAccounts in every namespace). This must not crash the
	// ingest/merge, must still produce a working access path, and
	// must be surfaced as unresolved so the gap is visible.
	paths, err = graph.WhyAccess(g, "k8s:sa:kube-system/bootstrap-signer", "get", "configmaps")
	if err != nil {
		t.Fatalf("WhyAccess for auto-vivified ServiceAccount: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path for bootstrap-signer's inferred access, got %d: %+v", len(paths), paths)
	}

	found := false
	for _, u := range result.UnresolvedPrincipals {
		if strings.Contains(u, "k8s:sa:kube-system/bootstrap-signer") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected bootstrap-signer to be flagged in UnresolvedPrincipals, got %+v", result.UnresolvedPrincipals)
	}

	// The fake fixture also binds ClusterRole eks:fargate-scheduler to
	// User subject "eks:fargate-scheduler" -- a built-in EKS identity
	// with no backing k8s object at all (unlike ServiceAccounts, there
	// is no list query that could ever return it). This must be
	// queryable via why/effective rather than erroring "unknown
	// principal", since the binding itself proves the principal has
	// real access that a security tool needs to be able to audit.
	paths, err = graph.WhyAccess(g, "k8s:User/eks:fargate-scheduler", "get", "pods")
	if err != nil {
		t.Fatalf("WhyAccess for auto-vivified User principal: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path for eks:fargate-scheduler's inferred access, got %d: %+v", len(paths), paths)
	}

	found = false
	for _, u := range result.UnresolvedPrincipals {
		if strings.Contains(u, "k8s:User/eks:fargate-scheduler") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected eks:fargate-scheduler to be flagged in UnresolvedPrincipals, got %+v", result.UnresolvedPrincipals)
	}
}
