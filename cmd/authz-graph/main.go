// SPDX-License-Identifier: Apache-2.0
// Command authz-graph is the Phase 0 CLI: ingest AWS IAM and/or
// Kubernetes RBAC via steampipe into a local graph file, then ask
// "why does this access exist" against it. No cobra/external CLI
// framework -- stdlib flag only, keeping the dependency footprint at
// zero; swapping to cobra later is a small, isolated change confined
// to this file.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/becash143/authz-graph/internal/api"
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
	case "effective":
		cmdEffective(os.Args[2:])
	case "grants":
		cmdGrants(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
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
  effective    [--graph FILE] --principal ID            List every principal/role reachable from ID via membership/assume/binding
  grants       [--graph FILE] --principal ID            List every actual permission (action+resource) reachable from ID -- use this BEFORE 'why' when you don't yet know which specific action/resource to ask about
  list         [--graph FILE] [--kind KIND]             List every node in the graph, optionally filtered by kind
  serve        [--graph FILE] [--addr ADDR] [--token T] [--allow-remote]
                                                         Serve a web UI + JSON API over the graph file (default: loopback-only, 127.0.0.1:8080)
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
	nodesPurged, edgesPurged := g.RemoveNodesBySource("aws")
	if err := result.MergeInto(g); err != nil {
		fatalf("merging AWS IAM data into graph: %v", err)
	}
	if err := store.Save(*graphPath, g); err != nil {
		fatalf("saving graph file: %v", err)
	}

	if nodesPurged > 0 {
		fmt.Printf("Replaced previous AWS data: %d stale node(s) and %d stale edge(s) removed before merging the fresh ingest.\n", nodesPurged, edgesPurged)
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
	nodesPurged, edgesPurged := g.RemoveNodesBySource("kubernetes")
	if err := result.MergeInto(g); err != nil {
		fatalf("merging Kubernetes RBAC data into graph: %v", err)
	}
	if err := store.Save(*graphPath, g); err != nil {
		fatalf("saving graph file: %v", err)
	}

	if nodesPurged > 0 {
		fmt.Printf("Replaced previous Kubernetes data: %d stale node(s) and %d stale edge(s) removed before merging the fresh ingest.\n", nodesPurged, edgesPurged)
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
		fatalf("%v", err)
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
		fatalf("%v", err)
	}
	fmt.Printf("%s's effective principal set (%d, via membership/assume/binding):\n", *principal, len(nodes))
	for _, n := range nodes {
		fmt.Printf("  - %s (%s)\n", n.ID, n.Kind)
	}
}

func cmdGrants(args []string) {
	fs := flag.NewFlagSet("grants", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to read")
	principal := fs.String("principal", "", "principal node ID")
	fs.Parse(args)

	if *principal == "" {
		fatalf("--principal is required")
	}

	g := openOrNewGraph(*graphPath)
	grants, err := graph.AllGrants(g, *principal)
	if err != nil {
		fatalf("%v", err)
	}
	if len(grants) == 0 {
		fmt.Printf("No grants found for %s (or anything it can reach via membership/assume/binding).\n", *principal)
		return
	}
	fmt.Printf("%d grant(s) reachable from %s:\n\n", len(grants), *principal)
	for _, gr := range grants {
		holder := ""
		if gr.HeldBy.ID != *principal {
			holder = fmt.Sprintf(" (via %s, %s)", gr.HeldBy.ID, gr.HeldBy.Kind)
		}
		fmt.Printf("  %s: %s on %q%s\n    via %s\n", gr.Edge.Effect, gr.Edge.Action, gr.Edge.Resource, holder, gr.Edge.GrantedVia)
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

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	graphPath := fs.String("graph", defaultGraphPath, "graph file to serve")
	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on -- defaults to loopback-only (see --allow-remote before changing this)")
	token := fs.String("token", "", "shared-secret bearer token required on /api/* requests (Authorization: Bearer <token>, or ?token=<token> for browser convenience). Required if --allow-remote is set; optional (and rarely useful) on the loopback-only default.")
	allowRemote := fs.Bool("allow-remote", false, "acknowledge that --addr binds somewhere other than loopback (127.0.0.1/localhost/::1), making this port reachable from other machines. Requires --token -- this serves your account/cluster's full authorization graph, don't put it on the network with no authentication in front of it.")
	fs.Parse(args)

	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		fatalf("--addr %q is not a valid host:port: %v", *addr, err)
	}
	if !isLoopbackHost(host) {
		if !*allowRemote {
			fatalf("--addr %q is not loopback-only -- this would expose your full authorization graph (every principal, role, and grant) to anything that can reach this port.\n  Either use a loopback address (127.0.0.1:PORT, localhost:PORT) -- the default -- or pass both --allow-remote and --token to acknowledge this explicitly.", *addr)
		}
		if *token == "" {
			fatalf("--allow-remote requires --token -- serving this graph beyond loopback with no authentication at all is the one thing this tool refuses to do by default.")
		}
	}

	g, err := store.Load(*graphPath)
	if err != nil {
		fatalf("loading graph file %s: %v (run ingest-aws/ingest-k8s first)", *graphPath, err)
	}

	srv := &api.Server{Graph: g}
	httpServer := &http.Server{
		Addr:              net.JoinHostPort(host, port),
		Handler:           srv.Handler(*token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	displayHost := host
	if displayHost == "" || displayHost == "0.0.0.0" || displayHost == "::" {
		displayHost = "localhost" // "listen on every interface" isn't a browsable hostname -- show something you can actually click
	}
	fmt.Printf("Serving %d node(s), %d edge(s) from %s on http://%s\n", len(g.Nodes), len(g.AllEdges()), *graphPath, net.JoinHostPort(displayHost, port))
	if *token != "" {
		fmt.Printf("Token required on /api/*: append ?token=%s to a URL, or send Authorization: Bearer %s\n", *token, *token)
	}
	fmt.Println("Note: this loads the graph once at startup -- re-run ingest-aws/ingest-k8s then restart `serve` to pick up fresh data, there is no live-reload yet.")

	// Graceful shutdown on Ctrl+C/SIGTERM: let any in-flight request
	// finish (bounded by the timeout below) instead of the previous
	// bare log.Fatal(ListenAndServe(...)), which dropped every open
	// connection the instant the process received a signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.ListenAndServe() }()

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			fatalf("serving: %v", err)
		}
	case <-ctx.Done():
		fmt.Println("\nShutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			fatalf("shutting down: %v", err)
		}
	}
}

// isLoopbackHost reports whether host is a form of "this machine only."
// An empty host (net/http binds every interface when Addr's host part
// is empty, e.g. ":8080") does NOT count, deliberately -- that's
// exactly the accidentally-exposed-to-the-network case --allow-remote
// exists to catch.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
