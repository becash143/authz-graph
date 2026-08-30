// SPDX-License-Identifier: Apache-2.0
// Package graph is the normalized permission model every ingester
// (internal/ingest) writes into and every query (internal/graph's own
// traversal, the CLI's `why` command) reads from -- the canonical
// "(principal, action, resource, condition, granted_via)" edge schema
// from the product plan, plus the identity/membership edges needed to
// walk multi-hop chains (user -> group -> role -> policy) rather than
// requiring ingestion to flatten those chains away before they reach
// the graph.
package graph

import "fmt"

type NodeKind string

const (
	NodeAWSIAMUser        NodeKind = "aws_iam_user"
	NodeAWSIAMGroup       NodeKind = "aws_iam_group"
	NodeAWSIAMRole        NodeKind = "aws_iam_role"
	NodeK8sServiceAccount NodeKind = "k8s_service_account"
	NodeK8sRole           NodeKind = "k8s_role"
	NodeK8sClusterRole    NodeKind = "k8s_cluster_role"
	NodeK8sUser           NodeKind = "k8s_user"
	NodeK8sGroup          NodeKind = "k8s_group"
)

// Node is any principal or role/policy-bearing entity in the graph.
// Namespace is only meaningful for namespaced Kubernetes kinds.
type Node struct {
	ID        string // stable, globally unique: e.g. "aws:iam:role/deploy-role", "k8s:sa:prod/web-app"
	Kind      NodeKind
	Name      string
	Namespace string // Kubernetes only
	Source    string // "aws" or "kubernetes" -- which ingester produced this node; used by RemoveNodesBySource for idempotent re-ingestion, so keep this a clean, stable value, not a descriptive sentence
	// Provenance is an optional human-readable caveat about how this
	// node was discovered, separate from Source so Source stays
	// reliable for exact-match filtering: e.g. "inferred from a
	// RoleBinding subject -- no backing object was directly observed."
	// Empty for directly-observed nodes (the normal case).
	Provenance string
}

type EdgeKind string

const (
	// Identity/membership edges -- traversed to build the "effective
	// principal set" reachable from a starting principal, but carry no
	// permission information themselves.
	EdgeMemberOf  EdgeKind = "member_of"  // AWS IAM user -> group
	EdgeCanAssume EdgeKind = "can_assume" // principal -> role, from the role's trust policy
	EdgeBoundBy   EdgeKind = "bound_by"   // k8s ServiceAccount -> Role/ClusterRole, from a (Cluster)RoleBinding

	// Grant edges -- the only edge kind that carries actual permission
	// data (Action/Resource/Effect/Condition). Every other edge kind
	// leaves these fields empty.
	EdgeGrants EdgeKind = "grants"
)

// Edge is one link in the graph. For EdgeGrants, Action/Resource/Effect
// describe what's actually permitted; for identity edges, only
// GrantedVia (which policy/binding produced this edge) and PathDetail
// are meaningful.
type Edge struct {
	From       string // Node.ID
	To         string // Node.ID
	Kind       EdgeKind
	Action     string // e.g. "s3:GetObject", "get"/"list" for k8s verbs -- only for EdgeGrants
	Resource   string // ARN pattern or k8s resource pattern -- only for EdgeGrants
	Effect     string // "Allow" or "Deny" -- only for EdgeGrants
	Condition  string // raw condition JSON, empty if none -- only for EdgeGrants
	GrantedVia string // provenance: the policy ARN / binding name that produced this edge
}

// Graph is an in-memory adjacency-list store. Dependency-free by
// design: an MVP CLI tool doesn't need a graph database yet, and
// keeping Graph's interface narrow (AddNode/AddEdge/Neighbors) means
// swapping in Postgres-with-recursive-CTEs or Neo4j later (per the
// product plan's own phasing) only touches internal/store, never the
// traversal logic in traverse.go.
type Graph struct {
	Nodes map[string]Node
	// outEdges and inEdges are both kept so traversal can walk forward
	// ("what can this principal reach") and backward ("what reaches
	// this resource") without a full scan either direction.
	outEdges map[string][]Edge
	inEdges  map[string][]Edge
}

func New() *Graph {
	return &Graph{
		Nodes:    make(map[string]Node),
		outEdges: make(map[string][]Edge),
		inEdges:  make(map[string][]Edge),
	}
}

func (g *Graph) AddNode(n Node) {
	g.Nodes[n.ID] = n // last write wins -- re-ingesting the same node just refreshes it
}

func (g *Graph) AddEdge(e Edge) error {
	if _, ok := g.Nodes[e.From]; !ok {
		return fmt.Errorf("edge references unknown node %q as From", e.From)
	}
	if e.Kind != EdgeGrants { // grant edges' "To" is often a resource pattern, not a node in the graph
		if _, ok := g.Nodes[e.To]; !ok {
			return fmt.Errorf("edge references unknown node %q as To", e.To)
		}
	}
	g.outEdges[e.From] = append(g.outEdges[e.From], e)
	g.inEdges[e.To] = append(g.inEdges[e.To], e)
	return nil
}

func (g *Graph) OutEdges(nodeID string) []Edge { return g.outEdges[nodeID] }
func (g *Graph) InEdges(nodeID string) []Edge  { return g.inEdges[nodeID] }

func (g *Graph) AllEdges() []Edge {
	var all []Edge
	for _, edges := range g.outEdges {
		all = append(all, edges...)
	}
	return all
}

// RemoveNodesBySource deletes every node with an exact Source match,
// plus every edge touching any of those nodes (as either From or To),
// and returns (nodes removed, edges removed).
//
// This exists so ingestion can be idempotent: re-running `ingest-aws`
// or `ingest-k8s` reflects the CURRENT state of that system, rather
// than accumulating a duplicate copy of every node/edge on every run.
// Before this existed, running ingest-k8s twice against the same graph
// file (a completely normal thing to do while iterating, or on a
// schedule) silently doubled every edge -- confirmed against a real
// run: the same RoleBinding->ClusterRole->grants chain came back 2-4x
// in a `why` result. Called by cmd/authz-graph's ingest commands
// before merging a fresh Result in, not left as something the caller
// has to remember to do.
func (g *Graph) RemoveNodesBySource(source string) (nodesRemoved, edgesRemoved int) {
	toRemove := make(map[string]bool)
	for id, n := range g.Nodes {
		if n.Source == source {
			toRemove[id] = true
			delete(g.Nodes, id)
			nodesRemoved++
		}
	}
	if nodesRemoved == 0 {
		return 0, 0
	}

	keep := func(e Edge) bool { return !toRemove[e.From] && !toRemove[e.To] }

	// Count removed edges once, from outEdges only -- every edge is
	// stored in both outEdges (keyed by From) and inEdges (keyed by
	// To), so counting from both would double-count the same edge.
	for _, edges := range g.outEdges {
		for _, e := range edges {
			if !keep(e) {
				edgesRemoved++
			}
		}
	}

	for id, edges := range g.outEdges {
		filtered := edges[:0]
		for _, e := range edges {
			if keep(e) {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			delete(g.outEdges, id)
		} else {
			g.outEdges[id] = filtered
		}
	}
	for id, edges := range g.inEdges {
		filtered := edges[:0]
		for _, e := range edges {
			if keep(e) {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			delete(g.inEdges, id)
		} else {
			g.inEdges[id] = filtered
		}
	}

	// Drop any remaining out/in edge-list entries keyed directly by a
	// removed node ID (a removed node's own adjacency-list entry).
	for id := range toRemove {
		delete(g.outEdges, id)
		delete(g.inEdges, id)
	}

	return nodesRemoved, edgesRemoved
}
