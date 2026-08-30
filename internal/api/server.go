// SPDX-License-Identifier: Apache-2.0

// Package api exposes a graph.Graph over HTTP: JSON endpoints for the
// same three questions the CLI answers (why, effective, list), plus a
// full graph dump for the embedded UI's visualization. Deliberately
// stdlib net/http only, consistent with the rest of this project's
// zero-external-dependency stance -- see internal/steampipe's doc
// comment for why that stance exists in the first place.
package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"sort"

	"github.com/becash143/authz-graph/internal/graph"
)

//go:embed web
var webFS embed.FS

// Server holds the graph this API answers questions against. The graph
// is loaded once at `authz-graph serve` startup -- see cmd/authz-graph's
// serve command for the reload story (there isn't live-reload yet; the
// server needs restarting after a fresh ingest, which is called out in
// the README's UI section rather than silently left as a surprise).
type Server struct {
	Graph *graph.Graph
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		// Only possible if the embed directive above is broken at
		// build time -- a programmer error, not a runtime condition
		// to recover from.
		log.Fatalf("internal/api: embedding web assets: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("/api/graph", s.handleGraph)
	mux.HandleFunc("/api/principals", s.handlePrincipals)
	mux.HandleFunc("/api/actions", s.handleActions)
	mux.HandleFunc("/api/resources", s.handleResources)
	mux.HandleFunc("/api/why", s.handleWhy)
	mux.HandleFunc("/api/effective", s.handleEffective)

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("internal/api: encoding response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// graphDump is the full-graph shape the UI's visualization renders.
// Deliberately the same Node/Edge types the CLI's `store` package
// persists -- one source of truth for the graph's shape, not a
// parallel API-only representation that could drift from it.
type graphDump struct {
	Nodes []graph.Node `json:"nodes"`
	Edges []graph.Edge `json:"edges"`
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	dump := graphDump{Edges: s.Graph.AllEdges()}
	for _, n := range s.Graph.Nodes {
		dump.Nodes = append(dump.Nodes, n)
	}
	writeJSON(w, http.StatusOK, dump)
}

type principalSummary struct {
	ID   string         `json:"id"`
	Kind graph.NodeKind `json:"kind"`
	Name string         `json:"name"`
}

func (s *Server) handlePrincipals(w http.ResponseWriter, r *http.Request) {
	out := make([]principalSummary, 0, len(s.Graph.Nodes))
	for _, n := range s.Graph.Nodes {
		out = append(out, principalSummary{ID: n.ID, Kind: n.Kind, Name: n.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleActions and handleResources back the Action/Resource datalists
// in the UI with real values actually present in the ingested graph's
// `grants` edges -- not a guessed/hardcoded list, which would either
// miss real values or suggest ones that don't apply to this cluster/
// account at all. Only `grants` edges carry Action/Resource (every
// other edge kind is identity/membership and leaves both empty), so
// this only ever needs to look at that one edge kind.
func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, distinctGrantValues(s.Graph, func(e graph.Edge) string { return e.Action }))
}

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, distinctGrantValues(s.Graph, func(e graph.Edge) string { return e.Resource }))
}

func distinctGrantValues(g *graph.Graph, field func(graph.Edge) string) []string {
	seen := make(map[string]bool)
	for _, e := range g.AllEdges() {
		if e.Kind != graph.EdgeGrants {
			continue
		}
		if v := field(e); v != "" {
			seen[v] = true
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleWhy(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	principal, action, resource := q.Get("principal"), q.Get("action"), q.Get("resource")
	if principal == "" || action == "" || resource == "" {
		writeError(w, http.StatusBadRequest, "principal, action, and resource query parameters are all required")
		return
	}
	paths, err := graph.WhyAccess(s.Graph, principal, action, resource)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"paths": paths})
}

func (s *Server) handleEffective(w http.ResponseWriter, r *http.Request) {
	principal := r.URL.Query().Get("principal")
	if principal == "" {
		writeError(w, http.StatusBadRequest, "principal query parameter is required")
		return
	}
	nodes, err := graph.EffectivePrincipals(s.Graph, principal)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": nodes})
}
