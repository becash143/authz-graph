// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/becash143/authz-graph/internal/graph"
	"github.com/becash143/authz-graph/internal/ingest"
	"github.com/becash143/authz-graph/internal/steampipe"
)

// buildTestGraph reuses the same fake-Steampipe fixture the ingest
// package's own tests are built on, so a failure here means this
// package's API disagrees with data the ingest tests already treat as
// ground truth -- not a second, possibly-drifted fixture.
func buildTestGraph(t *testing.T) *graph.Graph {
	t.Helper()
	client := &steampipe.Client{Binary: "../steampipe/testdata/fake_steampipe.sh"}
	result, err := ingest.AWSIAM(client)
	if err != nil {
		t.Fatalf("AWSIAM: %v", err)
	}
	g := graph.New()
	if err := result.MergeInto(g); err != nil {
		t.Fatalf("MergeInto: %v", err)
	}
	return g
}

func doJSON(t *testing.T, h http.Handler, method, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	if len(rec.Body.Bytes()) > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding response body from %s %s: %v (body: %s)", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func TestEndpoints_NoAuth(t *testing.T) {
	srv := &Server{Graph: buildTestGraph(t)} // AuthToken unset -- matches --no-auth
	h := srv.Handler()

	t.Run("graph", func(t *testing.T) {
		code, body := doJSON(t, h, http.MethodGet, "/api/graph")
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %+v", code, body)
		}
		if _, ok := body["nodes"]; !ok {
			t.Fatalf("expected a nodes field, got %+v", body)
		}
	})

	t.Run("principals", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/principals", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var principals []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &principals); err != nil {
			t.Fatalf("decoding principals: %v", err)
		}
		found := false
		for _, p := range principals {
			if p["id"] == "aws:iam:user/alice" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected aws:iam:user/alice in principals, got %+v", principals)
		}
	})

	t.Run("actions and resources are real grant values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/actions", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var actions []string
		if err := json.Unmarshal(rec.Body.Bytes(), &actions); err != nil {
			t.Fatalf("decoding actions: %v", err)
		}
		if len(actions) == 0 {
			t.Fatal("expected at least one known action")
		}

		req = httptest.NewRequest(http.MethodGet, "/api/resources", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var resources []string
		if err := json.Unmarshal(rec.Body.Bytes(), &resources); err != nil {
			t.Fatalf("decoding resources: %v", err)
		}
		if len(resources) == 0 {
			t.Fatal("expected at least one known resource")
		}
	})

	t.Run("why matches the CLI's own proven case", func(t *testing.T) {
		code, body := doJSON(t, h, http.MethodGet,
			"/api/why?principal=aws%3Aiam%3Auser%2Falice&action=s3%3AGetObject&resource=arn%3Aaws%3As3%3A%3A%3Aprod-data-bucket%2Freport.csv")
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %+v", code, body)
		}
		paths, ok := body["paths"].([]any)
		if !ok || len(paths) == 0 {
			t.Fatalf("expected at least one path, got %+v", body)
		}
	})

	t.Run("why missing params is 400", func(t *testing.T) {
		code, body := doJSON(t, h, http.MethodGet, "/api/why?principal=aws%3Aiam%3Auser%2Falice")
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %+v", code, body)
		}
	})

	t.Run("why unknown principal is 404", func(t *testing.T) {
		code, body := doJSON(t, h, http.MethodGet,
			"/api/why?principal=aws%3Aiam%3Auser%2Fnobody&action=%2A&resource=%2A")
		if code != http.StatusNotFound {
			t.Fatalf("expected 404 for an unknown principal, got %d: %+v", code, body)
		}
		if _, ok := body["error"]; !ok {
			t.Fatalf("expected an error field, got %+v", body)
		}
	})

	t.Run("effective", func(t *testing.T) {
		code, body := doJSON(t, h, http.MethodGet, "/api/effective?principal=aws%3Aiam%3Auser%2Falice")
		if code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %+v", code, body)
		}
		nodes, ok := body["nodes"].([]any)
		if !ok || len(nodes) == 0 {
			t.Fatalf("expected at least one reachable node, got %+v", body)
		}
	})

	t.Run("static index page is served", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for /, got %d", rec.Code)
		}
	})

	t.Run("vendored cytoscape asset is served, not loaded from a CDN", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vendor/cytoscape.min.js", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for the vendored cytoscape asset, got %d -- internal/api/web/vendor/cytoscape.min.js may be missing", rec.Code)
		}
		if rec.Body.Len() < 1000 {
			t.Fatalf("vendored cytoscape.min.js looks too small (%d bytes) to be the real file", rec.Body.Len())
		}
	})
}

func TestAuth_APIGatedWhenTokenSet(t *testing.T) {
	const tok = "test-token-12345"
	srv := &Server{Graph: buildTestGraph(t), AuthToken: tok}
	h := srv.Handler()

	t.Run("no token is 401", func(t *testing.T) {
		code, body := doJSON(t, h, http.MethodGet, "/api/principals")
		if code != http.StatusUnauthorized {
			t.Fatalf("expected 401 with no token, got %d: %+v", code, body)
		}
	})

	t.Run("wrong token is 401", func(t *testing.T) {
		code, body := doJSON(t, h, http.MethodGet, "/api/principals?token=wrong")
		if code != http.StatusUnauthorized {
			t.Fatalf("expected 401 with a wrong token, got %d: %+v", code, body)
		}
	})

	t.Run("correct token via query param is 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/principals?token="+tok, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 with the correct token, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("correct token via Authorization header is 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/principals", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 with a valid Authorization header, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("static assets stay open even with a token set", func(t *testing.T) {
		// Deliberate: a <script src="/vendor/..."> tag can't attach a
		// query-string token, so gating static assets would silently
		// break the page even for someone who opened the correct
		// tokened URL. Only /api/* is gated -- see server.go's Server
		// doc comment for the full reasoning.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected static / to stay open with no token even when AuthToken is set, got %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodGet, "/vendor/cytoscape.min.js", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected the vendored cytoscape asset to stay open with no token even when AuthToken is set, got %d", rec.Code)
		}
	})
}
