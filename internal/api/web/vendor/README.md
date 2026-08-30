Vendored third-party assets, embedded into the `authz-graph` binary via
`internal/api/server.go`'s `//go:embed web`.

- `cytoscape.min.js` — Cytoscape.js 3.30.2, MIT licensed (see
  `cytoscape.LICENSE.txt`). Vendored rather than loaded from a CDN so
  `authz-graph serve` works in air-gapped environments and has no
  runtime supply-chain dependency for a security tool. To update:
  `npm pack cytoscape@<version>`, extract `dist/cytoscape.min.js` and
  `LICENSE` from the resulting tarball, replace both files here, and
  bump the version referenced in `internal/api/web/index.html`.
