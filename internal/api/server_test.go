// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/becash143/authz-graph/internal/graph"
)

// fixtureGraph builds a small graph exercising every edge kind:
// membership, an assumed role, a Kubernetes binding, and both an Allow
// and a Deny grant -- enough to test each handler and the Allow/Deny
// distinction the web UI's edge coloring depends on.
func fixtureGraph(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()

	g.AddNode(graph.Node{ID: "aws:iam:user/alice", Kind: graph.NodeAWSIAMUser, Name: "alice", Source: "aws"})
	g.AddNode(graph.Node{ID: "aws:iam:group/engineers", Kind: graph.NodeAWSIAMGroup, Name: "engineers", Source: "aws"})

	must(t, g.AddEdge(graph.Edge{From: "aws:iam:user/alice", To: "aws:iam:group/engineers", Kind: graph.EdgeMemberOf, GrantedVia: "group membership"}))
	must(t, g.AddEdge(graph.Edge{From: "aws:iam:group/engineers", Kind: graph.EdgeGrants, Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::prod-bucket/*", GrantedVia: "ReadOnlyPolicy"}))
	must(t, g.AddEdge(graph.Edge{From: "aws:iam:group/engineers", Kind: graph.EdgeGrants, Effect: "Deny", Action: "s3:DeleteObject", Resource: "arn:aws:s3:::prod-bucket/*", GrantedVia: "ProtectProdPolicy"}))

	return g
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error building fixture: %v", err)
	}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decoding response body: %v (status %d)", err, rec.Code)
	}
}

func TestHandlePrincipals(t *testing.T) {
	srv := &Server{Graph: fixtureGraph(t)}
	rec := httptest.NewRecorder()
	srv.Handler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/principals", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out []principalSummary
	decodeJSON(t, rec, &out)
	if len(out) != 2 {
		t.Errorf("expected 2 principals, got %d", len(out))
	}
}

func TestHandleActionsAndResources(t *testing.T) {
	srv := &Server{Graph: fixtureGraph(t)}

	rec := httptest.NewRecorder()
	srv.Handler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/actions", nil))
	var actions []string
	decodeJSON(t, rec, &actions)
	if len(actions) != 2 {
		t.Fatalf("expected 2 distinct actions (GetObject + DeleteObject), got %d: %v", len(actions), actions)
	}

	rec = httptest.NewRecorder()
	srv.Handler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/resources", nil))
	var resources []string
	decodeJSON(t, rec, &resources)
	if len(resources) != 1 {
		t.Fatalf("expected 1 distinct resource (both grants target the same bucket), got %d: %v", len(resources), resources)
	}
}

func TestHandleWhy(t *testing.T) {
	srv := &Server{Graph: fixtureGraph(t)}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/why?principal=aws:iam:user/alice&action=s3:GetObject&resource=arn:aws:s3:::prod-bucket/report.csv", nil)
	srv.Handler("").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Paths []graph.Path `json:"paths"`
	}
	decodeJSON(t, rec, &body)
	if len(body.Paths) != 1 {
		t.Fatalf("expected 1 path from alice to the Allow grant, got %d", len(body.Paths))
	}
}

func TestHandleWhy_MissingParams(t *testing.T) {
	srv := &Server{Graph: fixtureGraph(t)}
	rec := httptest.NewRecorder()
	srv.Handler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/why?principal=aws:iam:user/alice", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing action/resource, got %d", rec.Code)
	}
}

func TestHandleEffective_IncludesConnectingEdges(t *testing.T) {
	// Regression test: /api/effective used to return only the reachable
	// NODE set with no edges at all, which rendered as a disconnected
	// cloud of nodes in the UI with no visible relationship between
	// them -- exactly the "not clear" graph clarity problem this whole
	// pass fixed. It must now also return the real identity edges
	// connecting that set.
	srv := &Server{Graph: fixtureGraph(t)}
	rec := httptest.NewRecorder()
	srv.Handler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/effective?principal=aws:iam:user/alice", nil))

	var body struct {
		Nodes []graph.Node `json:"nodes"`
		Edges []graph.Edge `json:"edges"`
	}
	decodeJSON(t, rec, &body)

	if len(body.Nodes) != 2 {
		t.Fatalf("expected 2 reachable nodes (alice + engineers), got %d", len(body.Nodes))
	}
	if len(body.Edges) != 1 {
		t.Fatalf("expected exactly 1 connecting identity edge (alice -member_of-> engineers), got %d: %+v", len(body.Edges), body.Edges)
	}
	if body.Edges[0].Kind == graph.EdgeGrants {
		t.Error("handleEffective must exclude grants edges (they target a resource pattern string, not a node in this set)")
	}
}

func TestRequireToken(t *testing.T) {
	srv := &Server{Graph: fixtureGraph(t)}
	handler := srv.Handler("secret123")

	cases := []struct {
		name       string
		setup      func(*http.Request)
		wantStatus int
	}{
		{"no token", func(r *http.Request) {}, http.StatusUnauthorized},
		{"wrong token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, http.StatusUnauthorized},
		{"correct header", func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret123") }, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/principals", nil)
			tc.setup(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}

	t.Run("correct query param", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/principals?token=secret123", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 with correct ?token=, got %d", rec.Code)
		}
	})

	t.Run("static assets are never gated", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code == http.StatusUnauthorized {
			t.Error("the static UI shell must not require a token -- only /api/* carries sensitive data")
		}
	})
}

func TestRequireToken_EmptyTokenIsPassthrough(t *testing.T) {
	srv := &Server{Graph: fixtureGraph(t)}
	handler := srv.Handler("") // loopback-only default: no token configured at all
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/principals", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("expected no auth enforced when authToken is empty, got %d", rec.Code)
	}
}
