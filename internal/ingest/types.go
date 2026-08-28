// SPDX-License-Identifier: Apache-2.0
// Package ingest turns steampipe query results into graph.Node/graph.Edge
// values -- one file per source system (aws_iam.go, kubernetes_rbac.go),
// each producing a Result the caller merges into a shared graph.Graph.
package ingest

import "github.com/becash143/authz-graph/internal/graph"

// Result is what every ingester returns -- nodes and edges to merge into
// the target graph. Kept as a plain struct rather than each ingester
// writing directly into a shared *graph.Graph so ingestion is easy to
// unit test in isolation (assert on the Result) before touching a real
// graph at all.
type Result struct {
	Nodes []graph.Node
	Edges []graph.Edge
	// UnresolvedPrincipals collects anything an ingester recognized as
	// permission-relevant but couldn't resolve to a graph node -- e.g. a
	// cross-account ARN in an AWS role trust policy, or a Kubernetes
	// RoleBinding subject referencing a User/Group (not a
	// ServiceAccount, which has no backing Kubernetes object to
	// ingest). Surfaced explicitly rather than silently dropped: an
	// authorization graph that quietly ignores edges it couldn't
	// resolve is actively dangerous, since "no path found" would look
	// identical to "this principal genuinely has no access."
	UnresolvedPrincipals []string
}

func (r *Result) MergeInto(g *graph.Graph) error {
	for _, n := range r.Nodes {
		g.AddNode(n)
	}
	for _, e := range r.Edges {
		if err := g.AddEdge(e); err != nil {
			return err
		}
	}
	return nil
}
