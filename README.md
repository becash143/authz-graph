# authz-graph

[![build-and-test](https://github.com/becash143/authz-graph/actions/workflows/ci.yml/badge.svg)](https://github.com/becash143/authz-graph/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/becash143/authz-graph.svg)](https://pkg.go.dev/github.com/becash143/authz-graph)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

**Answer "why does this access exist?" across AWS IAM and Kubernetes RBAC — as one explained chain, not a flat permissions dump.**

Most IAM/RBAC tooling shows you *what* a principal can do, listed flat.
It rarely shows you *how* — that `alice` can create a CloudFormation
stack not because she has a direct policy, but because she's in the
`engineers` group, which can assume `deploy-role`, which has a policy
granting `cloudformation:*`. That three-hop chain is invisible to a
flat permissions report. `authz-graph` walks it and shows it to you.

```
$ authz-graph why --principal aws:iam:user/alice \
    --action cloudformation:CreateStack \
    --resource arn:aws:cloudformation:us-east-1:111111111111:stack/x

1 path(s) found:

Path 1:
aws:iam:user/alice (aws_iam_user)
  --[member_of via IAM group membership]--> aws:iam:group/engineers (aws_iam_group)
  --[can_assume via arn:aws:iam::111111111111:role/deploy-role trust policy]--> aws:iam:role/deploy-role (aws_iam_role)
  --[grants: Allow]--> cloudformation:* on * (via arn:aws:iam::111111111111:policy/DeployPolicy)
```

## Install

```
go install github.com/becash143/authz-graph/cmd/authz-graph@latest
```

Or download a prebuilt binary from the [Releases page](https://github.com/becash143/authz-graph/releases)
(Linux/macOS/Windows, amd64/arm64). Or build from source:

```
git clone https://github.com/becash143/authz-graph.git
cd authz-graph
go build -o authz-graph ./cmd/authz-graph
```

## Why this shape

- **Steampipe does the hard part (talking to AWS/K8s) for us.** This
  repo never imports an AWS SDK or a Kubernetes client library — it
  shells out to `steampipe query ... --output json`. `internal/steampipe`
  is the entire integration surface, which means adding a new data
  source is an ingester, not a new client library to maintain.
- **One canonical graph, not per-source-system special cases.**
  `internal/graph` defines a small set of edge kinds — `member_of`,
  `can_assume`, `bound_by` (identity/membership hops, carry no
  permission data) and `grants` (the only edge kind with an actual
  action/resource/effect) — that both `internal/ingest/aws_iam.go` and
  `internal/ingest/kubernetes_rbac.go` write into identically. Adding a
  third source (Vault, GitHub Actions — see Roadmap) means writing one
  more ingester against this same shape, not redesigning the graph.
- **Multi-hop by construction.** `graph.WhyAccess` walks identity edges
  recursively before checking grants, so a multi-hop chain like the one
  above comes back as one explained path, not something a flat
  permissions dump would ever surface.
- **Dependency-free, on purpose.** The graph store (`internal/store`,
  plain JSON on disk) and the CLI (stdlib `flag` only) are both
  trivially swappable later — Postgres with recursive CTEs, or a real
  graph database, without touching `internal/graph`'s traversal logic
  at all.

## Status: early / Phase 0

This is a working prototype, not a hardened product. Here's an honest
breakdown of what's solid and what isn't yet:

**Validated:**
- AWS IAM ingestion and traversal — tested against the fake-Steampipe
  fixtures below, and the underlying `aws_iam_policy_statement` table
  (which flattens policy documents into one row per statement) is
  mature, documented Steampipe functionality.
- The graph traversal engine itself (`internal/graph`) — unit-tested
  independently of Steampipe against hand-built graphs, including
  cycle handling for trust-policy loops.

**Not yet validated against a real cluster — needs your help:**
- The exact Kubernetes plugin column names in
  `internal/ingest/kubernetes_rbac.go` (`kubernetes_role`,
  `kubernetes_role_binding`, etc.) mirror the underlying K8s API object
  shape closely, but haven't been confirmed against a live Steampipe
  Kubernetes plugin install. Run `steampipe query "select * from
  kubernetes_role limit 1"` against your own cluster and open an issue
  if the columns don't match.

**Explicitly out of scope for now (not silently dropped — surfaced):**
- Cross-account AWS trust relationships (a role trusting a principal in
  a *different* AWS account). Anything unresolved lands in
  `UnresolvedPrincipals` and is printed by the CLI.
- Kubernetes RoleBinding/ClusterRoleBinding subjects of kind `User` or
  `Group` (as opposed to `ServiceAccount`) — these come from an
  external OIDC/auth provider with no backing Kubernetes object to
  ingest a node for. Also surfaced via `UnresolvedPrincipals`, not
  dropped.

## Try it (no AWS account or cluster needed)

`internal/steampipe/testdata/fake_steampipe.sh` stands in for the real
`steampipe` binary and returns fixed fixtures: `alice` → `engineers`
group → S3 read access directly, and → assumed `deploy-role` →
CloudFormation access; a `web-app` ServiceAccount → `pod-reader` Role
via a RoleBinding.

```
go build -o authz-graph ./cmd/authz-graph

FAKE=internal/steampipe/testdata/fake_steampipe.sh

./authz-graph ingest-aws --steampipe-bin "$FAKE"
./authz-graph ingest-k8s --steampipe-bin "$FAKE"
./authz-graph list
./authz-graph why --principal aws:iam:user/alice --action s3:GetObject --resource arn:aws:s3:::prod-data-bucket/report.csv
./authz-graph why --principal aws:iam:user/alice --action cloudformation:CreateStack --resource arn:aws:cloudformation:us-east-1:111111111111:stack/x
./authz-graph effective --principal aws:iam:user/alice
```

## Try it against a real environment

Drop `--steampipe-bin` (defaults to `steampipe` on your `$PATH`), and
make sure `steampipe plugin install aws` / `steampipe plugin install
kubernetes` are configured with real connections first. Verify each
plugin works standalone (`steampipe query "select * from aws_iam_user"`)
before filing an issue against this tool.

## Testing

```
go test ./...
```

`internal/graph` has traversal unit tests against a hand-built graph
(no Steampipe needed) — this is the more important test suite, since
the traversal logic is the actual intellectual content of the product.
`internal/ingest` has tests against the fake Steampipe binary above,
verifying the full ingest → normalize → graph pipeline for both AWS and
Kubernetes.

## Roadmap

- Vault, GitHub Actions, and Terraform Cloud ingesters (same `Result`
  shape, same `MergeInto` pattern as AWS/K8s — additive, not a redesign)
- Blast-radius simulation (forward traversal + before/after reachability
  diff — `graph.EffectivePrincipals` plus a reverse-direction walk from
  a changed node gets most of the way there)
- Drift/change detection and a CI/CD dangerous-change gate
- Persistence beyond a single JSON file, and a UI beyond this CLI

## Contributing

Issues and PRs welcome, especially:
- Real-world Kubernetes plugin column verification (see Status above)
- Additional escalation-path coverage in the AWS IAM ingester
- New ingesters following the existing `Result`/`MergeInto` pattern

## Security

This tool reads and displays security-sensitive authorization
structure. See [SECURITY.md](./SECURITY.md) for the vulnerability
reporting policy and a few scope notes worth knowing before you audit
it.

## License

See [LICENSE](./LICENSE) — Apache 2.0. This project shells out to the
`steampipe` binary as a subprocess and does not embed or link against
it. Steampipe itself is licensed separately (AGPL 3.0 as of this
writing, confirmed against [turbot/steampipe](https://github.com/turbot/steampipe)'s
own LICENSE file) — that distinction is what keeps this project's
Apache 2.0 license from being pulled into Steampipe's copyleft terms;
if you fork this to link against Steampipe's Go packages directly
instead of shelling out to the CLI, re-check that reasoning, since it
no longer holds.
