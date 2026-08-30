// SPDX-License-Identifier: Apache-2.0
package graph

import "fmt"

// Hop is one step in a path the traversal found -- either an identity
// hop (member_of/can_assume/bound_by) or the final grant hop. Rendered
// in sequence, a []Hop is the full "why does this access exist" answer:
// exactly the chain the product plan's #1 priority capability asks for.
type Hop struct {
	Edge Edge
	From Node
	To   Node // zero-value Node{} when Edge.Kind == EdgeGrants and To is a resource pattern, not a graph node
}

// Path is one complete explanation: principal -> ... -> the edge that
// actually grants the access.
type Path struct {
	Hops []Hop
}

// String renders a Path as a human-readable chain, e.g.:
//
//	aws_iam_user/alice --member_of--> aws_iam_group/engineers --grants[Allow]--> s3:GetObject on arn:aws:s3:::prod-data-bucket/* (via arn:...:policy/S3ReadOnly)
func (p Path) String() string {
	out := ""
	for i, hop := range p.Hops {
		if i == 0 {
			out += fmt.Sprintf("%s (%s)", hop.From.ID, hop.From.Kind)
		}
		if hop.Edge.Kind == EdgeGrants {
			out += fmt.Sprintf("\n  --[%s: %s]--> %s %q on %q (via %s)",
				hop.Edge.Kind, hop.Edge.Effect, hop.Edge.Action, hop.Edge.Action, hop.Edge.Resource, hop.Edge.GrantedVia)
			out += fmt.Sprintf("\n     resource pattern: %s", hop.Edge.Resource)
		} else {
			out += fmt.Sprintf("\n  --[%s via %s]--> %s (%s)", hop.Edge.Kind, hop.Edge.GrantedVia, hop.To.ID, hop.To.Kind)
		}
	}
	return out
}

// WhyAccess answers the product plan's #1 capability: does
// startPrincipalID have access to perform action on a resource matching
// resourcePattern, and if so, via what chain? Returns every distinct
// path found (a principal can reach the same grant through more than
// one route -- e.g. two different group memberships -- and that's
// itself useful information, not noise to collapse away).
func WhyAccess(g *Graph, startPrincipalID, action, resourcePattern string) ([]Path, error) {
	if _, ok := g.Nodes[startPrincipalID]; !ok {
		return nil, fmt.Errorf("unknown principal %q", startPrincipalID)
	}

	var results []Path
	visited := make(map[string]bool) // cycle guard -- AWS trust policies can form cycles (rare, but real)

	var walk func(nodeID string, pathSoFar []Hop)
	walk = func(nodeID string, pathSoFar []Hop) {
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true
		defer func() { visited[nodeID] = false }() // allow revisiting on a different branch

		for _, edge := range g.OutEdges(nodeID) {
			switch edge.Kind {
			case EdgeGrants:
				if !MatchPattern(edge.Action, action) && !MatchPattern(action, edge.Action) {
					continue
				}
				if !MatchPattern(edge.Resource, resourcePattern) && !MatchPattern(resourcePattern, edge.Resource) {
					continue
				}
				fromNode := g.Nodes[nodeID]
				fullPath := append(append([]Hop{}, pathSoFar...), Hop{Edge: edge, From: fromNode})
				results = append(results, Path{Hops: fullPath})
			case EdgeMemberOf, EdgeCanAssume, EdgeBoundBy:
				fromNode, toNode := g.Nodes[nodeID], g.Nodes[edge.To]
				nextPath := append(append([]Hop{}, pathSoFar...), Hop{Edge: edge, From: fromNode, To: toNode})
				walk(edge.To, nextPath)
			}
		}
	}

	walk(startPrincipalID, nil)
	return results, nil
}

// EffectivePrincipals returns every node reachable from startID via
// identity/membership edges only (not grants) -- the "effective
// principal set": everything startID's access is actually composed of,
// used for blast-radius analysis in a later phase and exposed now via
// the CLI's `effective` command as a smaller, standalone useful result.
func EffectivePrincipals(g *Graph, startID string) ([]Node, error) {
	if _, ok := g.Nodes[startID]; !ok {
		return nil, fmt.Errorf("unknown principal %q", startID)
	}
	visited := map[string]bool{startID: true}
	queue := []string{startID}
	var out []Node
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		out = append(out, g.Nodes[id])
		for _, edge := range g.OutEdges(id) {
			if edge.Kind == EdgeGrants || visited[edge.To] {
				continue
			}
			visited[edge.To] = true
			queue = append(queue, edge.To)
		}
	}
	return out, nil
}

// Grant is one direct permission reachable from a starting principal --
// AllGrants' unit of output, pairing the actual grants Edge with which
// node in the effective principal set is the one holding it (not
// necessarily startID itself -- usually a group/role reached via
// membership).
type Grant struct {
	HeldBy Node
	Edge   Edge
}

// AllGrants answers a different question than WhyAccess: not "can this
// principal do X to Y" (which requires already knowing what to ask
// about), but "what can this principal do at all" -- every grants edge
// reachable from startID's effective principal set (EffectivePrincipals
// above), deduplicated. This is what the CLI's `grants` command and the
// product plan's "why does this access exist" work backward from in
// practice: you usually don't already know the specific action/resource
// pair to ask WhyAccess about until you've first seen the full list
// here.
func AllGrants(g *Graph, startID string) ([]Grant, error) {
	principals, err := EffectivePrincipals(g, startID)
	if err != nil {
		return nil, err
	}

	var out []Grant
	seen := make(map[string]bool) // dedupe identical (holder, action, resource, effect, grantedVia) tuples -- the same grant can be reached via more than one membership path, same reasoning as WhyAccess returning multiple paths, but here we only want the grant listed once per holder
	for _, p := range principals {
		for _, edge := range g.OutEdges(p.ID) {
			if edge.Kind != EdgeGrants {
				continue
			}
			key := p.ID + "|" + edge.Action + "|" + edge.Resource + "|" + edge.Effect + "|" + edge.GrantedVia
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Grant{HeldBy: p, Edge: edge})
		}
	}
	return out, nil
}
