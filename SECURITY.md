# Security Policy

`authz-graph` reads and displays authorization structure (IAM policies,
Kubernetes RBAC) that is itself security-sensitive, so please report
vulnerabilities responsibly rather than opening a public issue.

## Reporting a vulnerability

Please use [GitHub's private vulnerability reporting](../../security/advisories/new)
for this repository rather than filing a public issue, so any real
finding isn't disclosed before a fix is available.

If private reporting isn't available to you for some reason, open an
issue asking for a private contact channel without describing the
vulnerability itself.

## Scope notes for reviewers

A few things worth knowing up front, since they shape what a real
finding here looks like:

- This tool only ever reads authorization data (IAM/RBAC) via
  `steampipe query` subprocess calls -- it does not itself hold cloud
  credentials, mint tokens, or make any mutating API call. The graph
  file it writes to disk (`authz-graph.json` by default) is not a
  secret store, but it does describe your account/cluster's
  authorization topology, and is written with `0600` permissions on
  that basis -- treat it as sensitive.
- SQL passed to `steampipe query` is currently 100% static (hardcoded
  in `internal/ingest/*.go`), never built from user-supplied input --
  if a future contribution parametrizes a query by CLI-supplied value,
  that's the moment SQL-injection-into-Steampipe becomes a real
  question worth a careful look, not before.
- This project shells out to the `steampipe` binary as a subprocess
  and does not embed, statically link, or dynamically link against it
  -- see the License section of the README for why that distinction
  matters given Steampipe's own AGPL-3.0 licensing.
