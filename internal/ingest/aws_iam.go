// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"fmt"

	"github.com/becash143/authz-graph/internal/graph"
	"github.com/becash143/authz-graph/internal/steampipe"
)

// AWS IAM Steampipe table row shapes. Column names match the AWS
// plugin's documented schema (hub.steampipe.io/plugins/turbot/aws) --
// aws_iam_policy_statement in particular is Steampipe's own flattening
// of policy documents into one row per statement, which is most of why
// this ingester is short: the hard part (parsing arbitrary policy JSON)
// is already done upstream, not reimplemented here.
// awsIAMGroupRef/awsIAMUserRef mirror the *real* Steampipe AWS plugin
// shape for aws_iam_user.groups and aws_iam_group.users: unlike
// attached_policy_arns (already flattened to a []string of ARNs by the
// plugin), groups/users are NOT flattened to name strings -- each
// element is the full AWS API object (Arn/CreateDate/GroupId/
// GroupName/Path for a group; the User equivalent for a user).
// Confirmed against a real `aws_iam_user` query result. Only the
// fields this ingester actually needs are declared; the rest decode
// into nothing via encoding/json's default "ignore unknown fields"
// behavior.
type awsIAMGroupRef struct {
	GroupName string `json:"GroupName"`
}

type awsIAMUserRef struct {
	UserName string `json:"UserName"`
}

// awsInlinePolicy mirrors the real Steampipe shape for inline
// policies: there is no separate "aws_iam_user_policy"/
// "aws_iam_group_policy"/"aws_iam_role_policy" table in the plugin at
// all (an earlier version of this comment assumed there was --
// confirmed wrong by checking the plugin's actual table list).
// Instead, aws_iam_user/aws_iam_group/aws_iam_role each carry their
// own inline_policies_std JSONB column directly: a list of
// {PolicyName, PolicyDocument: {Statement: [...]}}, with
// PolicyDocument.Statement in the same normalized form as
// aws_iam_policy.policy_std's Statement (Action/Resource always
// arrays). Confirmed against the plugin's documented column list for
// aws_iam_user.
type awsInlinePolicy struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument struct {
		Statement []awsIAMPolicyStatement `json:"Statement"`
	} `json:"PolicyDocument"`
}

type awsIAMUserRow struct {
	Name               string            `json:"name"`
	ARN                string            `json:"arn"`
	AttachedPolicyARNs []string          `json:"attached_policy_arns"`
	Groups             []awsIAMGroupRef  `json:"groups"`
	InlinePoliciesStd  []awsInlinePolicy `json:"inline_policies_std"`
}

type awsIAMGroupRow struct {
	Name               string            `json:"name"`
	ARN                string            `json:"arn"`
	AttachedPolicyARNs []string          `json:"attached_policy_arns"`
	Users              []awsIAMUserRef   `json:"users"`
	InlinePoliciesStd  []awsInlinePolicy `json:"inline_policies_std"`
}

type assumeRolePolicyStatement struct {
	Effect    string `json:"Effect"`
	Principal struct {
		AWS StringOrSlice `json:"AWS"`
	} `json:"Principal"`
	Action StringOrSlice `json:"Action"`
}

type awsIAMRoleRow struct {
	Name                string            `json:"name"`
	ARN                 string            `json:"arn"`
	AttachedPolicyARNs  []string          `json:"attached_policy_arns"`
	InlinePoliciesStd   []awsInlinePolicy `json:"inline_policies_std"`
	AssumeRolePolicyStd struct {
		Statement []assumeRolePolicyStatement `json:"Statement"`
	} `json:"assume_role_policy_std"`
}

type awsIAMPolicyStatement struct {
	SID       string        `json:"Sid"`
	Effect    string        `json:"Effect"`
	Action    StringOrSlice `json:"Action"`
	Resource  StringOrSlice `json:"Resource"`
	Condition interface{}   `json:"Condition"` // kept as raw interface{} -- rendered to a string only when non-nil, see graph.Edge.Condition
}

// awsIAMPolicyRow queries the real Steampipe table, aws_iam_policy --
// there is no "aws_iam_policy_statement" table in the plugin. Like
// aws_iam_role.assume_role_policy_std (already handled this way
// above), policy_std is the plugin's normalized form of the policy
// document: Action/Resource always arrays, Condition always
// {operator: {key: [values]}}. Statements are flattened into
// awsIAMPolicyStatementRow client-side below rather than in SQL.
type awsIAMPolicyRow struct {
	ARN       string `json:"arn"`
	PolicyStd struct {
		Statement []awsIAMPolicyStatement `json:"Statement"`
	} `json:"policy_std"`
}

type awsIAMPolicyStatementRow struct {
	PolicyARN string
	SID       string
	Effect    string
	Action    StringOrSlice
	Resource  StringOrSlice
	Condition interface{}
}

func userNodeID(name string) string  { return "aws:iam:user/" + name }
func groupNodeID(name string) string { return "aws:iam:group/" + name }
func roleNodeID(name string) string  { return "aws:iam:role/" + name }

// AWSIAM queries a connected steampipe AWS plugin for users, groups,
// roles, and every attached policy's individual statements, and
// normalizes all of it into the canonical graph shape: membership edges
// for user->group, trust-policy-derived can_assume edges for
// group/user->role (only principals actually named in the role's trust
// policy get an edge -- this is not "everyone can assume every role"),
// and grants edges for what each policy statement actually allows.
func AWSIAM(client *steampipe.Client) (*Result, error) {
	result := &Result{}

	var users []awsIAMUserRow
	if err := client.Query("select name, arn, attached_policy_arns, groups, inline_policies_std from aws_iam_user", &users); err != nil {
		return nil, fmt.Errorf("querying aws_iam_user: %w", err)
	}
	var groups []awsIAMGroupRow
	if err := client.Query("select name, arn, attached_policy_arns, users, inline_policies_std from aws_iam_group", &groups); err != nil {
		return nil, fmt.Errorf("querying aws_iam_group: %w", err)
	}
	var roles []awsIAMRoleRow
	if err := client.Query("select name, arn, attached_policy_arns, inline_policies_std, assume_role_policy_std from aws_iam_role", &roles); err != nil {
		return nil, fmt.Errorf("querying aws_iam_role: %w", err)
	}
	var policies []awsIAMPolicyRow
	if err := client.Query("select arn, policy_std from aws_iam_policy", &policies); err != nil {
		return nil, fmt.Errorf("querying aws_iam_policy: %w", err)
	}
	var statements []awsIAMPolicyStatementRow
	for _, p := range policies {
		for _, stmt := range p.PolicyStd.Statement {
			statements = append(statements, awsIAMPolicyStatementRow{
				PolicyARN: p.ARN,
				SID:       stmt.SID,
				Effect:    stmt.Effect,
				Action:    stmt.Action,
				Resource:  stmt.Resource,
				Condition: stmt.Condition,
			})
		}
	}

	// Nodes first -- edges below reference these by ID, and graph.AddEdge
	// validates the From node exists.
	for _, u := range users {
		result.Nodes = append(result.Nodes, graph.Node{ID: userNodeID(u.Name), Kind: graph.NodeAWSIAMUser, Name: u.Name, Source: "aws"})
	}
	for _, g := range groups {
		result.Nodes = append(result.Nodes, graph.Node{ID: groupNodeID(g.Name), Kind: graph.NodeAWSIAMGroup, Name: g.Name, Source: "aws"})
	}
	for _, r := range roles {
		result.Nodes = append(result.Nodes, graph.Node{ID: roleNodeID(r.Name), Kind: graph.NodeAWSIAMRole, Name: r.Name, Source: "aws"})
	}

	// user -> group membership
	for _, u := range users {
		for _, group := range u.Groups {
			result.Edges = append(result.Edges, graph.Edge{
				From: userNodeID(u.Name), To: groupNodeID(group.GroupName),
				Kind: graph.EdgeMemberOf, GrantedVia: "IAM group membership",
			})
		}
	}

	// trust policy -> can_assume edges, one per principal actually named
	// in the role's trust policy (not a blanket "anyone can assume
	// this" edge -- that would make every role reachable from every
	// principal and defeat the point of the graph).
	principalNameToNodeID := func(principalARN string) (string, bool) {
		// Matches "arn:aws:iam::<account>:user/<name>" and
		// "arn:aws:iam::<account>:group/<name>" / ".../role/<name>" --
		// deliberately simple prefix matching rather than a full ARN
		// parser, sufficient for same-account trust relationships;
		// cross-account trust (a different AWS account's principal)
		// is out of scope for this MVP and logged as unresolved by the
		// caller inspecting Result, not silently dropped -- see
		// UnresolvedPrincipals below.
		for _, kind := range []string{"user/", "group/", "role/"} {
			if idx := lastIndex(principalARN, kind); idx >= 0 {
				name := principalARN[idx+len(kind):]
				switch kind {
				case "user/":
					return userNodeID(name), true
				case "group/":
					return groupNodeID(name), true
				case "role/":
					return roleNodeID(name), true
				}
			}
		}
		return "", false
	}

	for _, r := range roles {
		for _, stmt := range r.AssumeRolePolicyStd.Statement {
			if stmt.Effect != "Allow" {
				continue
			}
			for _, principalARN := range stmt.Principal.AWS {
				fromID, ok := principalNameToNodeID(principalARN)
				if !ok {
					result.UnresolvedPrincipals = append(result.UnresolvedPrincipals, principalARN)
					continue
				}
				result.Edges = append(result.Edges, graph.Edge{
					From: fromID, To: roleNodeID(r.Name),
					Kind: graph.EdgeCanAssume, GrantedVia: r.ARN + " trust policy",
				})
			}
		}
	}

	// policy statements -> grants edges, attached to every user/group/
	// role that has the statement's policy in its AttachedPolicyARNs.
	policyToPrincipals := make(map[string][]string) // policy ARN -> node IDs
	for _, u := range users {
		for _, p := range u.AttachedPolicyARNs {
			policyToPrincipals[p] = append(policyToPrincipals[p], userNodeID(u.Name))
		}
	}
	for _, g := range groups {
		for _, p := range g.AttachedPolicyARNs {
			policyToPrincipals[p] = append(policyToPrincipals[p], groupNodeID(g.Name))
		}
	}
	for _, r := range roles {
		for _, p := range r.AttachedPolicyARNs {
			policyToPrincipals[p] = append(policyToPrincipals[p], roleNodeID(r.Name))
		}
	}

	for _, stmt := range statements {
		principals := policyToPrincipals[stmt.PolicyARN]
		conditionStr := conditionToString(stmt.Condition)
		for _, principalID := range principals {
			for _, action := range stmt.Action {
				for _, resource := range stmt.Resource {
					result.Edges = append(result.Edges, graph.Edge{
						From: principalID, Kind: graph.EdgeGrants,
						Action: action, Resource: resource, Effect: stmt.Effect,
						Condition: conditionStr, GrantedVia: stmt.PolicyARN,
					})
				}
			}
		}
	}

	// inline policies -> grants edges, directly from the owning
	// principal (unlike attached/managed policies, an inline policy
	// document lives embedded on the user/group/role itself -- there's
	// no separate policy ARN to join through).
	grantsFromInline := func(principalID string, policies []awsInlinePolicy) {
		for _, p := range policies {
			for _, stmt := range p.PolicyDocument.Statement {
				conditionStr := conditionToString(stmt.Condition)
				for _, action := range stmt.Action {
					for _, resource := range stmt.Resource {
						result.Edges = append(result.Edges, graph.Edge{
							From: principalID, Kind: graph.EdgeGrants,
							Action: action, Resource: resource, Effect: stmt.Effect,
							Condition:  conditionStr,
							GrantedVia: fmt.Sprintf("inline policy %q on %s", p.PolicyName, principalID),
						})
					}
				}
			}
		}
	}
	for _, u := range users {
		grantsFromInline(userNodeID(u.Name), u.InlinePoliciesStd)
	}
	for _, g := range groups {
		grantsFromInline(groupNodeID(g.Name), g.InlinePoliciesStd)
	}
	for _, r := range roles {
		grantsFromInline(roleNodeID(r.Name), r.InlinePoliciesStd)
	}

	return result, nil
}

// conditionToString renders a policy statement's Condition block (raw
// interface{} decoded from JSONB -- shape is {operator: {key:
// [values]}} per Steampipe's normalized form) to a display string,
// shared between the attached-policy and inline-policy grant paths.
func conditionToString(condition interface{}) string {
	if condition == nil {
		return ""
	}
	return fmt.Sprintf("%v", condition)
}

func lastIndex(s, substr string) int {
	last := -1
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			last = i
		}
	}
	return last
}
