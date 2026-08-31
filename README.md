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

## Status: tested against a real EKS cluster, still early

This has now been run against a real cluster (not just the fake
fixtures below) and one real, load-bearing bug was found and fixed as
a direct result -- documented here rather than glossed over:

**Fixed after real-cluster testing:**
- **Duplicate edges on re-ingestion.** Running `ingest-k8s` (or
  `ingest-aws`) a second time against an existing graph file used to
  *add* a second copy of every node/edge on top of the first, rather
  than replacing them -- confirmed against a real cluster, where the
  same RoleBinding->ClusterRole->grant chain came back 2-4x in a `why`
  result. Fixed: both ingest commands now call
  `graph.RemoveNodesBySource` to clear that source's previous data
  before merging in a fresh ingest, making re-ingestion idempotent.
  Covered by `internal/ingest/idempotent_test.go`, which re-ingests
  the same fixture four times and asserts the node/edge count and a
  `why` result never change after the first ingest.
- **`kubernetes_role_binding`/`kubernetes_cluster_role_binding`'s real
  schema** has no single `role_ref` column -- it's flattened into
  `role_name`, `role_kind`, `role_api_group` as separate scalar
  columns. Confirmed against `table_kubernetes_role_binding.go` in
  [turbot/steampipe-plugin-kubernetes](https://github.com/turbot/steampipe-plugin-kubernetes),
  not just a live query.
- **AWS's `aws_iam_policy_statement` table doesn't exist.** The real
  table is `aws_iam_policy`, whose `policy_std` column holds the
  normalized policy document; statements are now flattened
  client-side in `internal/ingest/aws_iam.go` instead.
- **`aws_iam_user.groups` / `aws_iam_group.users`** are arrays of full
  AWS API objects, not plain name strings -- fixed to decode the
  object and pull `GroupName`/`UserName` out of it.
- **Kubernetes `User`/`Group` RoleBinding subjects** (built-in system
  identities like `system:kube-scheduler`, `system:masters`, or
  external OIDC principals) are now auto-vivified into real graph
  nodes instead of only being logged as unresolved -- these are often
  the *most* security-relevant principals to be able to run `why`
  against (they're how `cluster-admin` actually gets granted). Each
  such node carries a `Provenance` note making clear it was inferred
  from a binding reference, not directly observed as a distinct
  object, and still gets listed in the ingest command's
  inferred/unverified summary.

**Still not fully hardened:**
- Cross-account AWS trust relationships (a role trusting a principal
  in a *different* AWS account) remain out of scope -- surfaced via
  `UnresolvedPrincipals`, not silently dropped.
- Only tested against one real EKS cluster so far. AKS/GKE/kubeadm
  clusters may expose the Kubernetes plugin's columns slightly
  differently -- if `ingest-k8s` errors on a column name, that's a real
  bug report, not user error.
- No persistent database backend or multi-user/multi-tenant support --
  this is a single-operator local tool with a single JSON graph file,
  by design (see "Why this shape" above), not a hosted product.
- No live-reload in `serve` (restart to pick up a fresh ingest) and no
  built-in TLS termination -- if you do run this beyond loopback (see
  the Web UI section's `--allow-remote` flow), put a real TLS-terminating
  reverse proxy in front of it; `serve`'s own token check is
  authentication, not encryption-in-transit.

**Fixed in the production-hardening pass** (previously real gaps,
listed here rather than quietly dropped from history):
- `serve` used to default to binding every network interface
  (`:8080`, which Go's `net/http` treats as "all interfaces," not
  "localhost") with zero authentication. Now defaults to
  `127.0.0.1:8080`, and refuses to bind anywhere else without an
  explicit `--allow-remote` + `--token`.
- The web UI's graph library loaded from a public CDN at runtime --
  now vendored and embedded in the binary, so `serve` has no network
  dependency at all.
- Bare `http.ListenAndServe` with no timeouts and no graceful shutdown
  -- now has read/write/idle timeouts and shuts down cleanly on
  Ctrl-C/SIGTERM.
- `internal/api` had zero test coverage -- now covers every handler
  plus the token-auth middleware (`internal/api/server_test.go`).
- The graph visualization itself used a force-directed layout
  (`cose`), which is the wrong tool for what is fundamentally a DAG --
  see the Web UI section for the switch to a hierarchical (dagre)
  layout, degree-based node sizing, Allow/Deny edge coloring, and
  hover tooltips replacing permanently-on edge labels.

## Web UI

`authz-graph serve` starts a local web UI + JSON API over an already-ingested
graph file -- a single self-contained binary, no separate frontend
build or deploy step, and **no network dependency at all**: Cytoscape.js
and the dagre layout engine are vendored and embedded into the binary
via Go's `embed` package (previously loaded from a CDN -- removed, see
below), so this works fully air-gapped.

```
go build -o authz-graph ./cmd/authz-graph
./authz-graph ingest-aws && ./authz-graph ingest-k8s   # or against the fake fixture, see below
./authz-graph serve
# open http://localhost:8080
```

It gives you: a principal/action/resource search with a live-filtering
dropdown, a "why" query rendered as both text and an interactive
graph, an "effective principal set" view, a "list all grants" view, and
a full-graph explorer -- with zoom/fit/re-layout controls and a
type-to-filter search over whatever's currently drawn.

**Graph rendering:** uses a hierarchical (dagre) layout instead of a
force-directed one -- this graph is fundamentally a DAG (principal ->
group/role -> policy/binding -> grant), and a layered layout makes that
chain immediately readable in a way force-directed layouts don't. Node
size reflects degree (a ClusterRole bound by 40 things visually reads
as more central than a leaf ServiceAccount). Grant edges are colored by
Effect -- green for Allow, red for Deny -- so a Deny is something you
*see*, not something you have to go looking for. Edge labels are hidden
by default (with dozens of edges on screen, always-on labels overlap
into noise) and shown instead as a hover tooltip, along with node
detail (kind, full ID).

**Auth and network exposure:** `serve` binds to `127.0.0.1` only by
default -- this tool visualizes your account/cluster's complete
authorization graph, and that has no business being reachable from
anywhere but the machine you're running it on unless you explicitly
say otherwise:

```
# loopback only, no token needed (the default, and the common case)
./authz-graph serve

# deliberately expose beyond loopback -- requires acknowledging it
./authz-graph serve --addr 0.0.0.0:8080 --allow-remote --token "$(openssl rand -hex 16)"
```

Passing a non-loopback `--addr` without both `--allow-remote` and
`--token` refuses to start, with an explanation of why, rather than
silently binding to every interface with zero authentication (the
previous default). The token check applies to `/api/*` only (the
static UI shell itself reveals nothing) and accepts either an
`Authorization: Bearer <token>` header or a `?token=` query param (the
latter purely for pasting a URL into a browser -- the header is the
correct mechanism if you're scripting against it).

**Other hardening:** the HTTP server now has real read/write/idle
timeouts (a bare `http.ListenAndServe` has none, which is a real
Slowloris-class risk) and shuts down gracefully on Ctrl-C/SIGTERM
instead of dropping in-flight connections.

No live-reload yet -- `serve` loads the graph file once at startup, so
re-run `ingest-aws`/`ingest-k8s` and restart `serve` to pick up fresh
data. Fine for the current CLI-first workflow; worth revisiting if the
UI becomes the primary way this gets used.

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
