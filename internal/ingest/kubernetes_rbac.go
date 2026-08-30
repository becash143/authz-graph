// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"fmt"

	"github.com/becash143/authz-graph/internal/graph"
	"github.com/becash143/authz-graph/internal/steampipe"
)

// Kubernetes RBAC Steampipe table row shapes, matching the objects'
// native structure (Role/ClusterRole .rules, RoleBinding/
// ClusterRoleBinding .roleRef + .subjects) -- the Kubernetes Steampipe
// plugin's columns mirror the underlying API object fields closely, so
// these shapes should need little adjustment against a real plugin
// install, but confirm against `steampipe query "select * from
// kubernetes_role limit 1"` before relying on this in production.
type k8sServiceAccountRow struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type k8sRoleRule struct {
	APIGroups []string `json:"api_groups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type k8sRoleRow struct {
	Name      string        `json:"name"`
	Namespace string        `json:"namespace"`
	Rules     []k8sRoleRule `json:"rules"`
}

type k8sRoleRef struct {
	Kind string // "Role" or "ClusterRole"
	Name string
}

type k8sSubject struct {
	Kind      string `json:"kind"` // "ServiceAccount", "User", or "Group"
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// k8sRoleBindingRow mirrors the *flattened* shape the real Steampipe
// Kubernetes plugin returns for kubernetes_role_binding /
// kubernetes_cluster_role_binding: there is no single "role_ref"
// struct/JSON column. RoleRef.Kind/Name/APIGroup are each their own
// scalar column (role_kind, role_name, role_api_group). Only
// "subjects" (a list) stays as JSON. Confirmed against
// table_kubernetes_role_binding.go / table_kubernetes_cluster_role_binding.go
// in github.com/turbot/steampipe-plugin-kubernetes.
type k8sRoleBindingRow struct {
	Name         string       `json:"name"`
	Namespace    string       `json:"namespace"`
	RoleName     string       `json:"role_name"`
	RoleAPIGroup string       `json:"role_api_group"`
	RoleKind     string       `json:"role_kind"`
	Subjects     []k8sSubject `json:"subjects"`
}

func (r k8sRoleBindingRow) roleRef() k8sRoleRef {
	return k8sRoleRef{Kind: r.RoleKind, Name: r.RoleName}
}

func saNodeID(namespace, name string) string { return fmt.Sprintf("k8s:sa:%s/%s", namespace, name) }
func roleNodeIDK8s(namespace, name string) string {
	return fmt.Sprintf("k8s:role:%s/%s", namespace, name)
}
func clusterRoleNodeID(name string) string { return "k8s:clusterrole/" + name }

// KubernetesRBAC queries a connected steampipe Kubernetes plugin for
// ServiceAccounts, Roles, ClusterRoles, RoleBindings, and
// ClusterRoleBindings, normalizing into the same canonical graph shape
// the AWS IAM ingester produces: bound_by edges for
// ServiceAccount->Role/ClusterRole (from bindings), and grants edges for
// each Role/ClusterRole's rules.
func KubernetesRBAC(client *steampipe.Client) (*Result, error) {
	result := &Result{}

	var sas []k8sServiceAccountRow
	if err := client.Query("select name, namespace from kubernetes_service_account", &sas); err != nil {
		return nil, fmt.Errorf("querying kubernetes_service_account: %w", err)
	}
	var roles []k8sRoleRow
	if err := client.Query("select name, namespace, rules from kubernetes_role", &roles); err != nil {
		return nil, fmt.Errorf("querying kubernetes_role: %w", err)
	}
	var clusterRoles []k8sRoleRow // ClusterRole has the same shape as Role minus namespace
	if err := client.Query("select name, rules from kubernetes_cluster_role", &clusterRoles); err != nil {
		return nil, fmt.Errorf("querying kubernetes_cluster_role: %w", err)
	}
	var roleBindings []k8sRoleBindingRow
	if err := client.Query("select name, namespace, role_name, role_api_group, role_kind, subjects from kubernetes_role_binding", &roleBindings); err != nil {
		return nil, fmt.Errorf("querying kubernetes_role_binding: %w", err)
	}
	var clusterRoleBindings []k8sRoleBindingRow
	if err := client.Query("select name, role_name, role_api_group, role_kind, subjects from kubernetes_cluster_role_binding", &clusterRoleBindings); err != nil {
		return nil, fmt.Errorf("querying kubernetes_cluster_role_binding: %w", err)
	}

	knownSAs := make(map[string]bool, len(sas))
	for _, sa := range sas {
		id := saNodeID(sa.Namespace, sa.Name)
		result.Nodes = append(result.Nodes, graph.Node{
			ID: id, Kind: graph.NodeK8sServiceAccount,
			Name: sa.Name, Namespace: sa.Namespace, Source: "kubernetes",
		})
		knownSAs[id] = true
	}
	for _, r := range roles {
		result.Nodes = append(result.Nodes, graph.Node{
			ID: roleNodeIDK8s(r.Namespace, r.Name), Kind: graph.NodeK8sRole,
			Name: r.Name, Namespace: r.Namespace, Source: "kubernetes",
		})
	}
	for _, cr := range clusterRoles {
		result.Nodes = append(result.Nodes, graph.Node{
			ID: clusterRoleNodeID(cr.Name), Kind: graph.NodeK8sClusterRole,
			Name: cr.Name, Source: "kubernetes",
		})
	}

	resolveRoleRef := func(bindingNamespace string, ref k8sRoleRef) (string, bool) {
		switch ref.Kind {
		case "Role":
			return roleNodeIDK8s(bindingNamespace, ref.Name), true
		case "ClusterRole":
			return clusterRoleNodeID(ref.Name), true
		default:
			return "", false
		}
	}

	// knownExternalPrincipals dedupes auto-vivified User/Group nodes
	// across bindings (the same OIDC user/group is often referenced by
	// multiple RoleBindings/ClusterRoleBindings).
	knownExternalPrincipals := make(map[string]bool)

	bind := func(bindingName, bindingNamespace string, ref k8sRoleRef, subjects []k8sSubject) {
		roleID, ok := resolveRoleRef(bindingNamespace, ref)
		if !ok {
			return
		}
		for _, s := range subjects {
			if s.Kind != "ServiceAccount" {
				// User/Group subjects have no backing Kubernetes
				// object -- they come from an external OIDC/auth
				// provider (or, for EKS, built-in system identities
				// like eks:fargate-scheduler). There's nothing to
				// "list" and confirm the way ServiceAccounts can be
				// double-checked, but the binding itself proves the
				// principal is real and does have access. Auto-vivify
				// a node so `why`/`effective` can actually be queried
				// against these -- refusing to create a node here
				// would make it impossible to audit access for exactly
				// the class of built-in system/OIDC identities this
				// tool most needs to cover. Still flagged as
				// unresolved so it's clear the node is inferred from
				// a binding reference, not a directly-observed object.
				var kind graph.NodeKind
				switch s.Kind {
				case "User":
					kind = graph.NodeK8sUser
				case "Group":
					kind = graph.NodeK8sGroup
				default:
					// Genuinely unrecognized subject kind -- no safe
					// node type to create, so surface it and skip
					// rather than guess.
					result.UnresolvedPrincipals = append(result.UnresolvedPrincipals,
						fmt.Sprintf("k8s:%s/%s (unrecognized subject kind, referenced by binding %s/%s)", s.Kind, s.Name, bindingNamespace, bindingName))
					continue
				}
				subjectID := fmt.Sprintf("k8s:%s/%s", s.Kind, s.Name)
				if !knownExternalPrincipals[subjectID] {
					result.Nodes = append(result.Nodes, graph.Node{
						ID: subjectID, Kind: kind, Name: s.Name,
						Source:     "kubernetes",
						Provenance: "inferred from a RoleBinding/ClusterRoleBinding subject -- no backing k8s object; external OIDC identity or built-in system principal",
					})
					knownExternalPrincipals[subjectID] = true
					result.UnresolvedPrincipals = append(result.UnresolvedPrincipals,
						fmt.Sprintf("%s (referenced by binding %s/%s)", subjectID, bindingNamespace, bindingName))
				}
				result.Edges = append(result.Edges, graph.Edge{
					From: subjectID, To: roleID,
					Kind: graph.EdgeBoundBy, GrantedVia: fmt.Sprintf("RoleBinding %s/%s", bindingNamespace, bindingName),
				})
				continue
			}
			subjectNamespace := s.Namespace
			if subjectNamespace == "" {
				subjectNamespace = bindingNamespace
			}
			subjectID := saNodeID(subjectNamespace, s.Name)
			if !knownSAs[subjectID] {
				// A binding referenced a ServiceAccount that
				// kubernetes_service_account never returned --
				// most likely the credential steampipe is using
				// can list bindings cluster-wide but lacks `list`
				// on ServiceAccounts in that namespace (or the
				// account was deleted after the binding was
				// created). Auto-vivify the node so the edge --
				// and any access path through it -- still shows
				// up: dropping the edge here would make "no path
				// found" indistinguishable from "no access",
				// which is exactly the failure mode this tool
				// exists to avoid. Still flagged as unresolved so
				// the gap in what was actually enumerated is
				// visible to the operator.
				result.Nodes = append(result.Nodes, graph.Node{
					ID: subjectID, Kind: graph.NodeK8sServiceAccount,
					Name: s.Name, Namespace: subjectNamespace,
					Source:     "kubernetes",
					Provenance: "inferred from a RoleBinding/ClusterRoleBinding subject -- not returned by kubernetes_service_account; verify it still exists and check the ingest credential's list access to this namespace",
				})
				knownSAs[subjectID] = true
				result.UnresolvedPrincipals = append(result.UnresolvedPrincipals,
					fmt.Sprintf("%s (ServiceAccount referenced by binding %s/%s but not returned by kubernetes_service_account)", subjectID, bindingNamespace, bindingName))
			}
			result.Edges = append(result.Edges, graph.Edge{
				From: subjectID, To: roleID,
				Kind: graph.EdgeBoundBy, GrantedVia: fmt.Sprintf("RoleBinding %s/%s", bindingNamespace, bindingName),
			})
		}
	}

	for _, rb := range roleBindings {
		bind(rb.Name, rb.Namespace, rb.roleRef(), rb.Subjects)
	}
	for _, crb := range clusterRoleBindings {
		bind(crb.Name, "" /* cluster-scoped */, crb.roleRef(), crb.Subjects)
	}

	grantsFromRules := func(roleID string, rules []k8sRoleRule, source string) {
		for _, rule := range rules {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					result.Edges = append(result.Edges, graph.Edge{
						From: roleID, Kind: graph.EdgeGrants,
						Action: verb, Resource: resource, Effect: "Allow",
						GrantedVia: source,
					})
				}
			}
		}
	}
	for _, r := range roles {
		grantsFromRules(roleNodeIDK8s(r.Namespace, r.Name), r.Rules, fmt.Sprintf("Role %s/%s", r.Namespace, r.Name))
	}
	for _, cr := range clusterRoles {
		grantsFromRules(clusterRoleNodeID(cr.Name), cr.Rules, "ClusterRole "+cr.Name)
	}

	return result, nil
}
