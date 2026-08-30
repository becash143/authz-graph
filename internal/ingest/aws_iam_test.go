// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"testing"

	"github.com/becash143/authz-graph/internal/graph"
	"github.com/becash143/authz-graph/internal/steampipe"
)

func TestAWSIAM_AgainstFakeSteampipe(t *testing.T) {
	client := &steampipe.Client{Binary: "../steampipe/testdata/fake_steampipe.sh"}
	result, err := AWSIAM(client)
	if err != nil {
		t.Fatalf("AWSIAM: %v", err)
	}

	g := graph.New()
	if err := result.MergeInto(g); err != nil {
		t.Fatalf("MergeInto: %v", err)
	}

	// alice is a member of engineers; engineers has S3ReadOnly attached
	// directly (grants s3:GetObject on prod-data-bucket/*) -- a clean
	// 2-hop case (member_of, then grants). deploy-role's
	// cloudformation:* grant is only reachable via can_assume (tested
	// below), kept isolated from this policy on purpose so each test
	// demonstrates one mechanism.
	paths, err := graph.WhyAccess(g, "aws:iam:user/alice", "s3:GetObject", "arn:aws:s3:::prod-data-bucket/report.csv")
	if err != nil {
		t.Fatalf("WhyAccess: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path for alice's S3 access via engineers group, got %d: %+v", len(paths), paths)
	}

	paths, err = graph.WhyAccess(g, "aws:iam:user/alice", "cloudformation:CreateStack", "arn:aws:cloudformation:us-east-1:111111111111:stack/x")
	if err != nil {
		t.Fatalf("WhyAccess: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path for alice's CloudFormation access via the assumed deploy-role, got %d: %+v", len(paths), paths)
	}
	if len(paths[0].Hops) != 3 {
		t.Fatalf("expected member_of -> can_assume -> grants (3 hops), got %d", len(paths[0].Hops))
	}
}
