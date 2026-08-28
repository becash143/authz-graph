// SPDX-License-Identifier: Apache-2.0

package steampipe

import "testing"

// TestQuery_RealEnvelopeShape pins down the actual `steampipe query
// --output json` output shape -- {"columns": [...], "rows": [...]},
// not a bare array -- against a fixture confirmed by a real `steampipe
// query` run against a live Kubernetes cluster. This test exists
// specifically because an earlier version of this package (and its
// test fixture) both assumed a bare array, passed against itself, and
// only failed once run against a real steampipe install. Don't relax
// this fixture back to a bare array without re-confirming against a
// real install first.
func TestQuery_RealEnvelopeShape(t *testing.T) {
	c := &Client{Binary: "testdata/fake_steampipe.sh"}

	var rows []struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	if err := c.Query("select name, namespace from kubernetes_service_account", &rows); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 || rows[0].Name != "web-app" || rows[0].Namespace != "prod" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestQuery_EmptyRows(t *testing.T) {
	c := &Client{Binary: "testdata/fake_steampipe.sh"}
	var rows []struct{ Name string }
	// Any table not special-cased in fake_steampipe.sh falls through
	// to its `*)` catch-all, which returns the empty-but-well-formed
	// envelope this test is pinning down -- deliberately querying a
	// nonexistent table name here so this test doesn't silently start
	// asserting on a real fixture's row count if that fixture ever
	// grows rows (as kubernetes_cluster_role did to cover the
	// bootstrap-signer auto-vivify case).
	if err := c.Query("select name from kubernetes_nonexistent_table_for_test", &rows); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(rows))
	}
}
