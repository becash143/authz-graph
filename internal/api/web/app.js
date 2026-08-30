// authz-graph web UI. No build step, no framework -- plain fetch() +
// Cytoscape.js (loaded via CDN in index.html), consistent with the
// rest of this project's "no more dependencies than the thing
// genuinely needs" stance. This file is embedded straight into the Go
// binary (see internal/api/server.go's //go:embed) so `authz-graph
// serve` is a single self-contained executable.

const NODE_COLORS = {
  aws_iam_user: "#2E6E9E",
  aws_iam_group: "#5B8FB9",
  aws_iam_role: "#1F3A5F",
  k8s_service_account: "#1E7B34",
  k8s_role: "#4FA65F",
  k8s_cluster_role: "#0B5122",
  k8s_user: "#B7791F",
  k8s_group: "#C9962F",
  resource: "#777777",
};

const EDGE_STYLE = {
  member_of: { color: "#999", style: "dashed" },
  can_assume: { color: "#B7791F", style: "dashed" },
  bound_by: { color: "#4FA65F", style: "dashed" },
  grants: { color: "#1E7B34", style: "solid" },
};

let cy = null;

function initCytoscape() {
  cy = cytoscape({
    container: document.getElementById("cy"),
    style: [
      {
        selector: "node",
        style: {
          "background-color": (n) => NODE_COLORS[n.data("kind")] || "#999",
          label: "data(label)",
          "font-size": 9,
          color: "#222",
          "text-valign": "bottom",
          "text-margin-y": 4,
          width: 22,
          height: 22,
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": (e) => (EDGE_STYLE[e.data("kind")] || {}).color || "#ccc",
          "line-style": (e) => (EDGE_STYLE[e.data("kind")] || {}).style || "solid",
          "target-arrow-shape": "triangle",
          "target-arrow-color": (e) => (EDGE_STYLE[e.data("kind")] || {}).color || "#ccc",
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": 8,
          "text-rotation": "autorotate",
          color: "#555",
        },
      },
      {
        selector: "node.faded",
        style: { opacity: 0.12 },
      },
      {
        selector: "edge.faded",
        style: { opacity: 0.06 },
      },
      {
        selector: "node.matched",
        style: { "border-width": 3, "border-color": "#000" },
      },
    ],
    layout: { name: "cose", animate: false },
  });
}

function renderElements(nodes, edges) {
  cy.elements().remove();
  const els = [];
  const seen = new Set();
  for (const n of nodes) {
    if (seen.has(n.id)) continue;
    seen.add(n.id);
    els.push({ data: { id: n.id, label: n.name || n.id, kind: n.kind } });
  }
  for (const e of edges) {
    els.push({
      data: {
        id: `${e.from}->${e.to}->${e.kind}->${e.action || ""}`,
        source: e.from,
        target: e.to,
        kind: e.kind,
        label: e.kind === "grants" ? e.action : e.kind,
      },
    });
  }
  cy.add(els);
  cy.layout({ name: "cose", animate: false }).run();
  cy.fit(undefined, 40);

  // A fresh render replaces the element set entirely -- any filter
  // applied against the previous set no longer means anything, so
  // clear it rather than leave stale fading applied to new elements
  // (or worse, a filter silently applying to elements it was never
  // run against).
  const filterInput = document.getElementById("node-filter-input");
  if (filterInput.value) {
    filterInput.value = "";
  }
  applyNodeFilter("");
}

// Live "type to filter" over whatever's currently rendered: matches
// are outlined, everything else (including edges) fades except the
// matched nodes' immediate neighborhood, so you can still see what a
// match connects to rather than seeing it in isolation -- useful the
// moment a graph has more than a screenful of nodes, which the full
// graph view and a wide `why` result (e.g. a heavily-privileged
// ClusterRoleBinding) both routinely do.
function applyNodeFilter(query) {
  if (!cy) return;
  const q = query.trim().toLowerCase();
  const countEl = document.getElementById("filter-count");

  if (!q) {
    cy.elements().removeClass("faded").removeClass("matched");
    countEl.textContent = "";
    return;
  }

  const matched = cy.nodes().filter(
    (n) => n.data("id").toLowerCase().includes(q) || (n.data("label") || "").toLowerCase().includes(q)
  );
  const neighborhood = matched.union(matched.closedNeighborhood());

  cy.elements().addClass("faded");
  neighborhood.removeClass("faded");
  cy.nodes().removeClass("matched");
  matched.addClass("matched");

  countEl.textContent = `${matched.length} node match(es)`;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  const body = await res.json();
  if (!res.ok) throw new Error(body.error || `request failed: ${res.status}`);
  return body;
}

async function loadPrincipalList() {
  const principals = await fetchJSON("/api/principals");
  const datalist = document.getElementById("principal-list");
  datalist.innerHTML = "";
  for (const p of principals) {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.label = `${p.id} (${p.kind})`;
    datalist.appendChild(opt);
  }
  document.getElementById("node-count").textContent = `${principals.length} principals loaded`;
}

// Populates a plain-string datalist (Action/Resource) from an API
// endpoint returning a JSON array of strings -- shared by both since
// they're the same shape, unlike loadPrincipalList's richer objects.
async function loadStringDatalist(endpoint, datalistID) {
  const values = await fetchJSON(endpoint);
  const datalist = document.getElementById(datalistID);
  datalist.innerHTML = "";
  for (const v of values) {
    const opt = document.createElement("option");
    opt.value = v;
    datalist.appendChild(opt);
  }
  return values.length;
}

function renderResultsError(msg) {
  document.getElementById("results").innerHTML = `<div class="error">${escapeHTML(msg)}</div>`;
}

function escapeHTML(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

// Converts WhyAccess's []Path (each a []Hop) into node/edge lists for
// the graph view, synthesizing a "resource" node for the final grants
// hop's target -- a grants Edge's real target is a resource pattern
// string (e.g. "arn:aws:s3:::bucket/*"), not a graph node ID, so there
// is no backing Node for it the way there is for every identity hop.
function pathsToElements(paths) {
  const nodes = [];
  const edges = [];
  for (const path of paths) {
    for (const hop of path.Hops) {
      if (hop.Edge.Kind === "grants") {
        const resourceID = "resource:" + hop.Edge.Resource;
        nodes.push({ id: hop.From.ID, name: hop.From.Name || hop.From.ID, kind: hop.From.Kind });
        nodes.push({ id: resourceID, name: hop.Edge.Resource, kind: "resource" });
        edges.push({ from: hop.Edge.From, to: resourceID, kind: "grants", action: hop.Edge.Action });
      } else {
        nodes.push({ id: hop.From.ID, name: hop.From.Name || hop.From.ID, kind: hop.From.Kind });
        nodes.push({ id: hop.To.ID, name: hop.To.Name || hop.To.ID, kind: hop.To.Kind });
        edges.push({ from: hop.Edge.From, to: hop.Edge.To, kind: hop.Edge.Kind });
      }
    }
  }
  return { nodes, edges };
}

function renderWhyResults(paths) {
  const container = document.getElementById("results");
  if (paths.length === 0) {
    container.innerHTML = `<div class="empty">No path found.</div>`;
    return;
  }
  container.innerHTML = "";
  paths.forEach((path, i) => {
    const div = document.createElement("div");
    div.className = "path";
    div.innerHTML = `<strong>Path ${i + 1}</strong>` + path.Hops.map((hop) => {
      if (hop.Edge.Kind === "grants") {
        return `<div class="hop">&rarr; <strong>${escapeHTML(hop.Edge.Effect)}</strong> ${escapeHTML(hop.Edge.Action)} on ${escapeHTML(hop.Edge.Resource)} <span class="muted">(via ${escapeHTML(hop.Edge.GrantedVia)})</span></div>`;
      }
      return `<div class="hop">&rarr; ${escapeHTML(hop.Edge.Kind)} &rarr; ${escapeHTML(hop.To.ID)} <span class="muted">(${escapeHTML(hop.Edge.GrantedVia)})</span></div>`;
    }).join("");
    div.addEventListener("click", () => {
      const { nodes, edges } = pathsToElements([path]);
      renderElements(nodes, edges);
    });
    container.appendChild(div);
  });

  const { nodes, edges } = pathsToElements(paths);
  renderElements(nodes, edges);
}

async function runWhy() {
  const principal = document.getElementById("principal-input").value.trim();
  const action = document.getElementById("action-input").value.trim();
  const resource = document.getElementById("resource-input").value.trim();
  if (!principal || !action || !resource) {
    renderResultsError("principal, action, and resource are all required");
    return;
  }
  try {
    const body = await fetchJSON(`/api/why?principal=${encodeURIComponent(principal)}&action=${encodeURIComponent(action)}&resource=${encodeURIComponent(resource)}`);
    renderWhyResults(body.paths || []);
  } catch (e) {
    renderResultsError(e.message);
  }
}

async function runEffective() {
  const principal = document.getElementById("effective-principal-input").value.trim();
  if (!principal) {
    renderResultsError("principal is required");
    return;
  }
  try {
    const body = await fetchJSON(`/api/effective?principal=${encodeURIComponent(principal)}`);
    const nodes = body.nodes || [];
    document.getElementById("results").innerHTML =
      `<div class="path"><strong>${nodes.length} reachable node(s)</strong>` +
      nodes.map((n) => `<div class="hop">${escapeHTML(n.ID)} <span class="muted">(${escapeHTML(n.Kind)})</span></div>`).join("") +
      `</div>`;
    const mapped = nodes.map((n) => ({ id: n.ID, name: n.Name || n.ID, kind: n.Kind }));
    const edges = [];
    for (let i = 0; i < mapped.length - 1; i++) {
      edges.push({ from: mapped[i].id, to: mapped[i + 1].id, kind: "member_of" });
    }
    renderElements(mapped, []); // edges omitted here -- effective-set order isn't a real path, only the reachable node set matters
  } catch (e) {
    renderResultsError(e.message);
  }
}

async function runFullGraph() {
  try {
    const body = await fetchJSON("/api/graph");
    const nodes = (body.nodes || []).map((n) => ({ id: n.ID, name: n.Name || n.ID, kind: n.Kind }));
    const edges = (body.edges || [])
      .filter((e) => e.Kind !== "grants") // grants edges' target is a resource pattern, not a node -- omit from the full-graph identity view to avoid thousands of synthetic resource nodes; use "Why" for grant-level detail on a specific principal
      .map((e) => ({ from: e.From, to: e.To, kind: e.Kind }));
    document.getElementById("results").innerHTML = `<div class="muted">Showing ${nodes.length} nodes and ${edges.length} identity/membership edges (grants edges omitted here -- use "Why" for grant-level detail).</div>`;
    renderElements(nodes, edges);
  } catch (e) {
    renderResultsError(e.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initCytoscape();
  loadPrincipalList().catch((e) => renderResultsError(e.message));
  loadStringDatalist("/api/actions", "action-list").catch((e) => renderResultsError(e.message));
  loadStringDatalist("/api/resources", "resource-list").catch((e) => renderResultsError(e.message));
  document.getElementById("why-btn").addEventListener("click", runWhy);
  document.getElementById("effective-btn").addEventListener("click", runEffective);
  document.getElementById("full-graph-btn").addEventListener("click", runFullGraph);
  document.getElementById("node-filter-input").addEventListener("input", (e) => applyNodeFilter(e.target.value));

  // Every field below is backed by a <datalist>: clicking into one that
  // already has a value just drops the cursor into the existing text
  // (native input behavior), so typing inserts characters into it
  // instead of replacing it -- you'd have to manually clear the field
  // first to pick something else. Selecting all existing text on focus
  // means the first keystroke immediately overwrites it instead,
  // matching how a normal "pick a different option" interaction should
  // feel.
  for (const id of ["principal-input", "effective-principal-input", "action-input", "resource-input"]) {
    document.getElementById(id).addEventListener("focus", (e) => e.target.select());
  }
});
