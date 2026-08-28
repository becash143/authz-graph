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
)

// Node is any principal or role/policy-bearing entity in the graph.
// Namespace is only meaningful for namespaced Kubernetes kinds.
type Node struct {
	ID        string // stable, globally unique: e.g. "aws:iam:role/deploy-role", "k8s:sa:prod/web-app"
	Kind      NodeKind
	Name      string
	Namespace string // Kubernetes only
	Source    string // "aws" or "kubernetes" -- which ingester produced this node
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
