// SPDX-License-Identifier: Apache-2.0

package graph

import "testing"

// buildTestGraph mirrors the fake steampipe fixture's scenario:
// alice --member_of--> engineers --grants--> s3:GetObject on prod-data-bucket/*
// alice --member_of--> engineers --can_assume--> deploy-role --grants--> cloudformation:* on *
func buildTestGraph(t *testing.T) *Graph {
	t.Helper()
	g := New()
	g.AddNode(Node{ID: "aws:iam:user/alice", Kind: NodeAWSIAMUser, Name: "alice", Source: "aws"})
	g.AddNode(Node{ID: "aws:iam:group/engineers", Kind: NodeAWSIAMGroup, Name: "engineers", Source: "aws"})
	g.AddNode(Node{ID: "aws:iam:role/deploy-role", Kind: NodeAWSIAMRole, Name: "deploy-role", Source: "aws"})

	must(t, g.AddEdge(Edge{From: "aws:iam:user/alice", To: "aws:iam:group/engineers", Kind: EdgeMemberOf, GrantedVia: "group membership"}))
	must(t, g.AddEdge(Edge{From: "aws:iam:group/engineers", To: "aws:iam:role/deploy-role", Kind: EdgeCanAssume, GrantedVia: "deploy-role trust policy"}))

	must(t, g.AddEdge(Edge{
		From: "aws:iam:group/engineers", Kind: EdgeGrants, Effect: "Allow",
		Action: "s3:GetObject", Resource: "arn:aws:s3:::prod-data-bucket/*",
		GrantedVia: "arn:aws:iam::111111111111:policy/S3ReadOnly",
	}))
	must(t, g.AddEdge(Edge{
		From: "aws:iam:role/deploy-role", Kind: EdgeGrants, Effect: "Allow",
		Action: "cloudformation:*", Resource: "*",
		GrantedVia: "arn:aws:iam::111111111111:policy/DeployPolicy",
	}))
	return g
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWhyAccess_DirectGroupGrant(t *testing.T) {
	g := buildTestGraph(t)
	paths, err := WhyAccess(g, "aws:iam:user/alice", "s3:GetObject", "arn:aws:s3:::prod-data-bucket/report.csv")
	if err != nil {
		t.Fatalf("WhyAccess: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d: %+v", len(paths), paths)
	}
	if len(paths[0].Hops) != 2 {
		t.Fatalf("expected a 2-hop path (member_of, then grants), got %d hops", len(paths[0].Hops))
	}
	if paths[0].Hops[0].Edge.Kind != EdgeMemberOf {
		t.Errorf("expected first hop to be member_of, got %s", paths[0].Hops[0].Edge.Kind)
	}
	if paths[0].Hops[1].Edge.Kind != EdgeGrants {
		t.Errorf("expected second hop to be grants, got %s", paths[0].Hops[1].Edge.Kind)
	}
}

func TestWhyAccess_ThroughAssumedRole(t *testing.T) {
	g := buildTestGraph(t)
	paths, err := WhyAccess(g, "aws:iam:user/alice", "cloudformation:CreateStack", "arn:aws:cloudformation:us-east-1:111111111111:stack/anything")
	if err != nil {
		t.Fatalf("WhyAccess: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path through the assumed role, got %d", len(paths))
	}
	if len(paths[0].Hops) != 3 {
		t.Fatalf("expected a 3-hop path (member_of, can_assume, grants), got %d", len(paths[0].Hops))
	}
}

func TestWhyAccess_NoMatchingAccess(t *testing.T) {
	g := buildTestGraph(t)
	paths, err := WhyAccess(g, "aws:iam:user/alice", "ec2:TerminateInstances", "*")
	if err != nil {
		t.Fatalf("WhyAccess: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected no paths for an ungranted action, got %d: %+v", len(paths), paths)
	}
}

func TestWhyAccess_UnknownPrincipal(t *testing.T) {
	g := buildTestGraph(t)
	_, err := WhyAccess(g, "aws:iam:user/does-not-exist", "s3:GetObject", "*")
	if err == nil {
		t.Fatal("expected an error for an unknown principal, got nil")
	}
}

func TestEffectivePrincipals(t *testing.T) {
	g := buildTestGraph(t)
	nodes, err := EffectivePrincipals(g, "aws:iam:user/alice")
	if err != nil {
		t.Fatalf("EffectivePrincipals: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("expected alice + engineers + deploy-role = 3 nodes, got %d: %+v", len(nodes), nodes)
	}
}

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "anything", true},
		{"s3:*", "s3:GetObject", true},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:PutObject", false},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key.txt", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::other-bucket/key.txt", false},
		{"exact", "exact", true},
		{"exact", "not-exact", false},
	}
	for _, c := range cases {
		got := MatchPattern(c.pattern, c.value)
		if got != c.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}
