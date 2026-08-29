// SPDX-License-Identifier: Apache-2.0
// Command authz-graph is the Phase 0 CLI: ingest AWS IAM and/or
// Kubernetes RBAC via steampipe into a local graph file, then ask
// "why does this access exist" against it. No cobra/external CLI
// framework -- stdlib flag only, keeping the dependency footprint at
// zero; swapping to cobra later is a small, isolated change confined
// to this file.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/becash143/authz-graph/internal/graph"
	"github.com/becash143/authz-graph/internal/ingest"
	"github.com/becash143/authz-graph/internal/steampipe"
	"github.com/becash143/authz-graph/internal/store"
)

const defaultGraphPath = "authz-graph.json"

// version is overridden at release-build time via:
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/authz-graph
//
// Left as "dev" for plain `go build`/`go run`, so a local build never
// misreports itself as a tagged release.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ingest-aws":
		cmdIngestAWS(os.Args[2:])
	case "ingest-k8s":
		cmdIngestK8s(os.Args[2:])
	case "why":
		cmdWhy(os.Args[2:])
	case "grants":
		cmdGrants(os.Args[2:])
	case "effective":
		cmdEffective(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("authz-graph " + version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `authz-graph -- Authorization Graph MVP (Phase 0)

Commands:
  ingest-aws   [--graph FILE] [--steampipe-bin PATH]   Ingest AWS IAM via steampipe, merge into the graph file
  ingest-k8s   [--graph FILE] [--steampipe-bin PATH]   Ingest Kubernetes RBAC via steampipe, merge into the graph file
  why          [--graph FILE] --principal ID --action ACTION --resource RESOURCE
                                                         Explain every path by which principal can perform action on resource
  grants       [--graph FILE] --principal ID [--full]   List everything principal can do, deduped to one line per distinct
                                                         (effect, action, resource, granted-via) -- pass --full for every
                                                         individual path (same traversal as 'why' with wildcards, undeduped)
  effective    [--graph FILE] --principal ID            List every principal/role reachable from ID via membership/assume/binding
  list         [--graph FILE] [--kind KIND]             List every node in the graph, optionally filtered by kind
  version                                                Print the authz-graph version

Run 'ingest-aws' and/or 'ingest-k8s' first (against a steampipe install with the AWS and/or
Kubernetes plugins configured) before 'why'/'effective'/'list' -- they read the graph file those write.
`)
}

func openOrNewGraph(path string) *graph.Graph {
	g, err := store.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return graph.New()
		}
		fatalf("loading graph file %s: %v", path, err)
	}
	return g
}

func cmdIngestAWS(args []string) {
	fs := flag.NewFlagSet("ingest-aws", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to read and merge into")
	steampipeBin := fs.String("steampipe-bin", "steampipe", "path to the steampipe binary")
	fs.Parse(args)

	client := &steampipe.Client{Binary: *steampipeBin}
	result, err := ingest.AWSIAM(client)
	if err != nil {
		fatalf("ingesting AWS IAM: %v", err)
	}

	g := openOrNewGraph(*graphPath)
	if err := result.MergeInto(g); err != nil {
		fatalf("merging AWS IAM data into graph: %v", err)
	}
	if err := store.Save(*graphPath, g); err != nil {
		fatalf("saving graph file: %v", err)
	}

	fmt.Printf("Ingested AWS IAM: %d nodes, %d edges added. Graph saved to %s.\n", len(result.Nodes), len(result.Edges), *graphPath)
	if len(result.UnresolvedPrincipals) > 0 {
		fmt.Printf("\n%d principal(s) referenced in trust policies could not be resolved to a graph node (cross-account ARNs are out of scope for this MVP -- see internal/ingest/aws_iam.go):\n", len(result.UnresolvedPrincipals))
		for _, p := range result.UnresolvedPrincipals {
			fmt.Printf("  - %s\n", p)
		}
	}
}

func cmdIngestK8s(args []string) {
	fs := flag.NewFlagSet("ingest-k8s", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to read and merge into")
	steampipeBin := fs.String("steampipe-bin", "steampipe", "path to the steampipe binary")
	fs.Parse(args)

	client := &steampipe.Client{Binary: *steampipeBin}
	result, err := ingest.KubernetesRBAC(client)
	if err != nil {
		fatalf("ingesting Kubernetes RBAC: %v", err)
	}

	g := openOrNewGraph(*graphPath)
	if err := result.MergeInto(g); err != nil {
		fatalf("merging Kubernetes RBAC data into graph: %v", err)
	}
	if err := store.Save(*graphPath, g); err != nil {
		fatalf("saving graph file: %v", err)
	}

	fmt.Printf("Ingested Kubernetes RBAC: %d nodes, %d edges added. Graph saved to %s.\n", len(result.Nodes), len(result.Edges), *graphPath)
	if len(result.UnresolvedPrincipals) > 0 {
		fmt.Printf("\n%d principal(s) added to the graph as inferred/unverified (queryable via `why`/`effective`, but not directly confirmed against a live object -- see internal/ingest/kubernetes_rbac.go):\n", len(result.UnresolvedPrincipals))
		for _, p := range result.UnresolvedPrincipals {
			fmt.Printf("  - %s\n", p)
		}
	}
}

func cmdWhy(args []string) {
	fs := flag.NewFlagSet("why", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to read")
	principal := fs.String("principal", "", "principal node ID, e.g. aws:iam:user/alice or k8s:sa:prod/web-app")
	action := fs.String("action", "", "action to check, e.g. s3:GetObject or get")
	resource := fs.String("resource", "", "resource to check, e.g. an ARN or k8s resource name")
	fs.Parse(args)

	if *principal == "" || *action == "" || *resource == "" {
		fatalf("--principal, --action, and --resource are all required")
	}

	g := openOrNewGraph(*graphPath)
	paths, err := graph.WhyAccess(g, *principal, *action, *resource)
	if err != nil {
		fatalf("%s", unknownPrincipalHint(err))
	}
	if len(paths) == 0 {
		fmt.Printf("No path found: %s cannot perform %s on %s (as far as this graph currently knows -- re-run ingest-aws/ingest-k8s if the graph is stale).\n", *principal, *action, *resource)
		return
	}
	fmt.Printf("%d path(s) found:\n\n", len(paths))
	for i, p := range paths {
		fmt.Printf("Path %d:\n%s\n\n", i+1, p.String())
	}
}

// cmdGrants answers "what can this principal actually do" without
// requiring the caller to already know an action/resource pair to
// check -- reuses the same traversal as `why` with wildcards, but
// deduped: a grant reached via two different paths (e.g. two group
// memberships landing on the same policy statement) collapses to one
// line by default, since for a "what can X do" summary the distinct
// grant is what matters, not how many routes reach it. --full falls
// back to one block per individual path (same output as
// `why --action "*" --resource "*"`) for when the routing itself is
// what's being audited.
func cmdGrants(args []string) {
	fs := flag.NewFlagSet("grants", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to read")
	principal := fs.String("principal", "", "principal node ID")
	full := fs.Bool("full", false, "show every individual path instead of a deduped summary")
	fs.Parse(args)

	if *principal == "" {
		fatalf("--principal is required")
	}

	g := openOrNewGraph(*graphPath)
	paths, err := graph.WhyAccess(g, *principal, "*", "*")
	if err != nil {
		fatalf("%s", unknownPrincipalHint(err))
	}
	if len(paths) == 0 {
		fmt.Printf("No grants found for %s (as far as this graph currently knows -- re-run ingest-aws/ingest-k8s if the graph is stale).\n", *principal)
		return
	}

	if *full {
		fmt.Printf("%d grant path(s) found:\n\n", len(paths))
		for i, p := range paths {
			fmt.Printf("Path %d:\n%s\n\n", i+1, p.String())
		}
		return
	}

	type grantKey struct{ effect, action, resource, via string }
	seen := make(map[grantKey]bool)
	var lines []string
	for _, p := range paths {
		last := p.Hops[len(p.Hops)-1]
		k := grantKey{last.Edge.Effect, last.Edge.Action, last.Edge.Resource, last.Edge.GrantedVia}
		if seen[k] {
			continue
		}
		seen[k] = true
		lines = append(lines, fmt.Sprintf("%s: %s on %s  (via %s)", last.Edge.Effect, last.Edge.Action, last.Edge.Resource, last.Edge.GrantedVia))
	}
	sort.Strings(lines)

	fmt.Printf("%s can do %d distinct thing(s) (%d total path(s) found -- some reached more than one way; pass --full to see every path):\n\n", *principal, len(lines), len(paths))
	for _, l := range lines {
		fmt.Println(l)
	}
}

func cmdEffective(args []string) {
	fs := flag.NewFlagSet("effective", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to read")
	principal := fs.String("principal", "", "principal node ID")
	fs.Parse(args)

	if *principal == "" {
		fatalf("--principal is required")
	}

	g := openOrNewGraph(*graphPath)
	nodes, err := graph.EffectivePrincipals(g, *principal)
	if err != nil {
		fatalf("%s", unknownPrincipalHint(err))
	}
	fmt.Printf("%s's effective principal set (%d, via membership/assume/binding):\n", *principal, len(nodes))
	for _, n := range nodes {
		fmt.Printf("  - %s (%s)\n", n.ID, n.Kind)
	}
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to read")
	kind := fs.String("kind", "", "filter by node kind, e.g. aws_iam_role")
	fs.Parse(args)

	g := openOrNewGraph(*graphPath)
	count := 0
	for _, n := range g.Nodes {
		if *kind != "" && string(n.Kind) != *kind {
			continue
		}
		fmt.Printf("%s\t%s\n", n.Kind, n.ID)
		count++
	}
	fmt.Fprintf(os.Stderr, "\n%d node(s)\n", count)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

// unknownPrincipalHint appends actionable guidance to a graph
// "unknown principal" error rather than surfacing it bare: the two
// realistic causes are (1) the graph file predates a change to what
// gets ingested as a node -- e.g. Kubernetes User/Group binding
// subjects only started being auto-vivified in a later version of
// this tool, so a graph ingested before that change won't have nodes
// for them even though the underlying binding is real -- or (2) the
// principal genuinely was never referenced by any binding/policy this
// tool ingested, which is itself a legitimate (and often reassuring)
// finding. Re-ingesting resolves (1); if the error persists after
// that, it's (2).
func unknownPrincipalHint(err error) string {
	if !strings.Contains(err.Error(), "unknown principal") {
		return err.Error()
	}
	return fmt.Sprintf("%v -- this node isn't in the graph. Try re-running ingest-aws/ingest-k8s "+
		"(older graph files may predate node types this tool now creates), then retry. If it's still "+
		"unknown after a fresh ingest, nothing this tool ingested actually references this principal.", err)
}
