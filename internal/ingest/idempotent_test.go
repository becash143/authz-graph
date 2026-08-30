// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"testing"

	"github.com/becash143/authz-graph/internal/graph"
	"github.com/becash143/authz-graph/internal/steampipe"
)

// TestReingest_IsIdempotent targets the exact bug found against a real
// cluster: running ingest-k8s (or ingest-aws) a second time against a
// graph that already has that source's data used to double every edge,
// because merging just appended without ever removing what a previous
// ingest of the same source had written. A `why` query would then
// return the same access path 2x, 3x, or Nx depending on how many
// times ingestion had been re-run -- confirmed against real output
// before this test (and graph.RemoveNodesBySource) existed.
func TestReingest_IsIdempotent(t *testing.T) {
	client := &steampipe.Client{Binary: "../steampipe/testdata/fake_steampipe.sh"}

	g := graph.New()

	ingestOnce := func() {
		awsResult, err := AWSIAM(client)
		if err != nil {
			t.Fatalf("AWSIAM: %v", err)
		}
		g.RemoveNodesBySource("aws")
		if err := awsResult.MergeInto(g); err != nil {
			t.Fatalf("MergeInto (aws): %v", err)
		}

		k8sResult, err := KubernetesRBAC(client)
		if err != nil {
			t.Fatalf("KubernetesRBAC: %v", err)
		}
		g.RemoveNodesBySource("kubernetes")
		if err := k8sResult.MergeInto(g); err != nil {
			t.Fatalf("MergeInto (k8s): %v", err)
		}
	}

	ingestOnce()
	nodeCountAfterFirst := len(g.Nodes)
	edgeCountAfterFirst := len(g.AllEdges())

	pathsAfterFirst, err := graph.WhyAccess(g, "aws:iam:user/alice", "s3:GetObject", "arn:aws:s3:::prod-data-bucket/report.csv")
	if err != nil {
		t.Fatalf("WhyAccess after first ingest: %v", err)
	}

	// Re-ingest the SAME fixture data three more times -- this is
	// exactly what a user does re-running ingest-k8s while iterating,
	// or on a cron schedule.
	ingestOnce()
	ingestOnce()
	ingestOnce()

	if got := len(g.Nodes); got != nodeCountAfterFirst {
		t.Errorf("node count changed after re-ingesting identical data 3 more times: got %d, want %d (re-ingestion must replace, not accumulate)", got, nodeCountAfterFirst)
	}
	if got := len(g.AllEdges()); got != edgeCountAfterFirst {
		t.Errorf("edge count changed after re-ingesting identical data 3 more times: got %d, want %d (re-ingestion must replace, not accumulate)", got, edgeCountAfterFirst)
	}

	pathsAfterRepeat, err := graph.WhyAccess(g, "aws:iam:user/alice", "s3:GetObject", "arn:aws:s3:::prod-data-bucket/report.csv")
	if err != nil {
		t.Fatalf("WhyAccess after repeated ingest: %v", err)
	}
	if len(pathsAfterRepeat) != len(pathsAfterFirst) {
		t.Errorf("WhyAccess returned %d path(s) after repeated ingestion, want %d (same as after a single ingest) -- this is the exact duplicate-path bug found against a real cluster", len(pathsAfterRepeat), len(pathsAfterFirst))
	}
}
