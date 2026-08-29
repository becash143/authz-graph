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

## Commands

| Command | What it answers |
|---|---|
| `ingest-aws` / `ingest-k8s` | Pull AWS IAM / Kubernetes RBAC via steampipe, merge into the graph file |
| `why --principal --action --resource` | Every path by which a principal can do a specific thing |
| `grants --principal [--full]` | Everything a principal can do, deduped to one line per distinct grant (pass `--full` for every individual path, same output as `why` with wildcards) |
| `effective --principal` | Every identity reachable from a principal via membership/assume/binding — **not** what those identities can do, just what they *are* |
| `list [--kind]` | Every node in the graph, optionally filtered by kind |

`effective` and `grants` answer different questions and are easy to
conflate: `effective` walks identity edges only (who/what this
principal *is*, transitively), `grants`/`why` walk into the actual
permission edges (what it can *do*). Use `effective` to see the blast
radius of group/role membership itself; use `grants` to see the
resulting permissions.

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
breakdown of what's solid and what isn't yet.

**Validated against real environments** (not just the fake-Steampipe
fixtures below):
- **AWS IAM ingestion and traversal** — tested against a real
  multi-role AWS account (dozens of IAM roles, service-linked roles,
  and users/groups). This surfaced and fixed real Steampipe-shape
  bugs along the way: `aws_iam_user.groups`/`aws_iam_group.users`
  return full AWS API objects, not bare name strings; there is no
  `aws_iam_policy_statement` table at all — statements come from
  `aws_iam_policy.policy_std`, flattened client-side; and there are
  no `aws_iam_user_policy`/`aws_iam_group_policy`/
  `aws_iam_role_policy` tables either — inline policies are a
  JSONB `inline_policies_std` column directly on `aws_iam_user`/
  `aws_iam_group`/`aws_iam_role` themselves (`[{PolicyName,
  PolicyDocument: {Statement: [...]}}]`), also flattened client-side.
  All three are handled in `internal/ingest/aws_iam.go`, so `why`/
  `effective` now account for both managed and inline policies.
- **Kubernetes RBAC ingestion and traversal** — tested against a real
  production EKS cluster (250+ nodes, 4,000+ edges from RoleBindings/
  ClusterRoleBindings alone). This also surfaced and fixed real
  Steampipe-shape bugs: `kubernetes_role_binding`/
  `kubernetes_cluster_role_binding` have no `role_ref` column at all
  (`RoleRef` is flattened into `role_name`/`role_api_group`/
  `role_kind`); and binding subjects — both `ServiceAccount`s not
  returned by `kubernetes_service_account` (RBAC-visibility gaps are
  common on EKS) and `User`/`Group` subjects (built-in EKS identities
  like `eks:fargate-scheduler`, or external OIDC principals) — are now
  auto-vivified into queryable nodes rather than crashing the ingest
  or silently making `why`/`effective` unable to answer for them.
- The graph traversal engine itself (`internal/graph`) — unit-tested
  independently of Steampipe against hand-built graphs, including
  cycle handling for trust-policy loops.

**Known gaps — surfaced via `UnresolvedPrincipals`, not silently
dropped, but genuinely out of scope for now:**
- **AWS permission boundaries and SCPs** aren't modeled — a grant this
  tool reports may still be blocked by an org-level SCP or a
  permission boundary at the account.
- **Cross-account AWS trust relationships** (a role trusting a
  principal in a *different* AWS account, including bare `:root`
  trust) aren't resolved to a node — the target account's IAM isn't
  ingested, so there's nothing to link to. Landed in
  `UnresolvedPrincipals` instead.
- **The AWS graph and the Kubernetes graph are not yet linked.** IRSA
  (IAM Roles for Service Accounts) means a K8s ServiceAccount can
  assume a real AWS role via that role's trust policy, but today
  that's two separate facts in two separate ingests — `why`/
  `effective` won't walk a k8s ServiceAccount into AWS IAM
  permissions in one path. Worth watching for if you're auditing a
  workload's *total* blast radius, not just its Kubernetes RBAC.
- **Auto-vivified K8s User/Group/ServiceAccount nodes are inferred,
  not independently confirmed.** They're created purely from a
  binding's `subjects` list — there's no corresponding "does this
  identity actually still exist / authenticate successfully" check.
  This is the safer direction to err in for a security tool (a
  binding to a since-deleted or since-renamed identity still shows up
  as a potential path rather than silently vanishing), but don't treat
  every node in the graph as confirmed-live.

## Try it (no AWS account or cluster needed)

`internal/steampipe/testdata/fake_steampipe.sh` stands in for the real
`steampipe` binary and returns fixed fixtures: `alice` → `engineers`
group → S3 read access directly, and → assumed `deploy-role` →
CloudFormation access, plus a direct inline-policy grant on her own
user; a `web-app` ServiceAccount → `pod-reader` Role via a
RoleBinding.

```
go build -o authz-graph ./cmd/authz-graph

FAKE=internal/steampipe/testdata/fake_steampipe.sh

./authz-graph ingest-aws --steampipe-bin "$FAKE"
./authz-graph ingest-k8s --steampipe-bin "$FAKE"
./authz-graph list
./authz-graph why --principal aws:iam:user/alice --action s3:GetObject --resource arn:aws:s3:::prod-data-bucket/report.csv
./authz-graph why --principal aws:iam:user/alice --action cloudformation:CreateStack --resource arn:aws:cloudformation:us-east-1:111111111111:stack/x
./authz-graph grants --principal aws:iam:user/alice
./authz-graph effective --principal aws:iam:user/alice
```

## Try it against a real environment

Drop `--steampipe-bin` (defaults to `steampipe` on your `$PATH`), and
make sure `steampipe plugin install aws` / `steampipe plugin install
kubernetes` are configured with real connections first. Verify each
plugin works standalone (`steampipe query "select * from aws_iam_user"`)
before filing an issue against this tool.

## Troubleshooting

**"unknown principal" from `why`/`grants`/`effective`, for a principal
you know exists.** The CLI now prints a hint for this, but the short
version: your graph file is almost certainly stale relative to the
binary. Re-run `ingest-aws`/`ingest-k8s` against the same `--graph`
path and retry.

**A rebuild doesn't seem to have fixed something.** If you're building
from a separate clone/fork rather than a fresh checkout, confirm the
fix you expect is actually in the source you're compiling before
assuming a re-ingest will help:

```
grep -n "knownExternalPrincipals" internal/ingest/kubernetes_rbac.go
```

If that returns nothing, your local Kubernetes ingester predates the
User/Group auto-vivify support (see Status above) — sync your copy
before re-ingesting. This specific check is worth calling out because
it's easy to get fooled by: the ingest CLI's `"... couldn't be fully
resolved"` output text is **identical** whether your binary auto-
vivifies those nodes or just drops them, since the message was written
before the auto-vivify fix and reused verbatim after — so seeing that
list print does not by itself confirm the fix is active. The only
reliable check is grepping the source (above) or trying a `why`/
`grants` query against one of the listed principals and seeing whether
it resolves.

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
- AWS permission-boundary and SCP awareness — the largest known
  coverage gap right now (see Status above)
- Linking the AWS and Kubernetes graphs via IRSA trust relationships
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
