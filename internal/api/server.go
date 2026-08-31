// SPDX-License-Identifier: Apache-2.0

// Package api exposes a graph.Graph over HTTP: JSON endpoints for the
// same three questions the CLI answers (why, effective, list), plus a
// full graph dump for the embedded UI's visualization. Deliberately
// stdlib net/http only, consistent with the rest of this project's
// zero-external-dependency stance -- see internal/steampipe's doc
// comment for why that stance exists in the first place.
package api

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strings"

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

func (s *Server) Handler(authToken string) http.Handler {
	mux := http.NewServeMux()

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		// Only possible if the embed directive above is broken at
		// build time -- a programmer error, not a runtime condition
		// to recover from.
		log.Fatalf("internal/api: embedding web assets: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Auth applies to /api/* only, not the static UI shell -- the HTML/
	// JS/vendored graph libraries reveal nothing about the org's actual
	// IAM/RBAC data, only the API responses do. When authToken is ""
	// (the loopback-only default in cmd/authz-graph's cmdServe never
	// sets one), requireToken is a pass-through -- correct, since
	// nothing outside the local machine can reach this port anyway.
	api := http.NewServeMux()
	api.HandleFunc("/api/graph", s.handleGraph)
	api.HandleFunc("/api/principals", s.handlePrincipals)
	api.HandleFunc("/api/actions", s.handleActions)
	api.HandleFunc("/api/resources", s.handleResources)
	api.HandleFunc("/api/why", s.handleWhy)
	api.HandleFunc("/api/effective", s.handleEffective)
	api.HandleFunc("/api/grants", s.handleGrants)
	mux.Handle("/api/", requireToken(authToken, api))

	return mux
}

// requireToken enforces a shared-secret bearer token on every request to
// next, checked against either the standard `Authorization: Bearer
// <token>` header or a `?token=` query parameter -- the header is the
// correct mechanism, but a browser tab hitting one of these JSON
// endpoints directly (e.g. for debugging) can't set custom headers via
// the address bar, so the query-param fallback exists purely for that
// interactive convenience. Documented tradeoff, not an oversight: query
// params can end up in server logs/browser history in a way headers
// don't -- fine for a token whose job is "keep casual/opportunistic
// access off this port," not a substitute for real secret hygiene if
// this is ever run somewhere genuinely hostile.
func requireToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.URL.Query().Get("token")
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			provided = strings.TrimPrefix(h, "Bearer ")
		}
		// Constant-time compare: this token guards a graph of exactly
		// who-can-access-what, so it deserves the same care as any
		// other bearer credential, not a plain == that leaks timing
		// information about how many leading characters matched.
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid token (Authorization: Bearer <token> header, or ?token=<token>)")
			return
		}
		next.ServeHTTP(w, r)
	})
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

	// EffectivePrincipals returns the reachable NODE set; the UI also
	// wants to draw how they connect, so pull the real identity edges
	// (member_of/can_assume/bound_by -- never `grants`, which targets a
	// resource pattern string, not another node in this set) where BOTH
	// endpoints are in that set. These are genuine edges from the graph,
	// not synthesized -- every one of them is exactly why its target
	// node is reachable in the first place.
	inSet := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		inSet[n.ID] = true
	}
	var edges []graph.Edge
	for _, e := range s.Graph.AllEdges() {
		if e.Kind != graph.EdgeGrants && inSet[e.From] && inSet[e.To] {
			edges = append(edges, e)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": nodes, "edges": edges})
}

func (s *Server) handleGrants(w http.ResponseWriter, r *http.Request) {
	principal := r.URL.Query().Get("principal")
	if principal == "" {
		writeError(w, http.StatusBadRequest, "principal query parameter is required")
		return
	}
	grants, err := graph.AllGrants(s.Graph, principal)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"grants": grants})
}
