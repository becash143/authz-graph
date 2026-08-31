// authz-graph web UI. No build step, no framework -- plain fetch() +
// Cytoscape.js + the cytoscape-dagre layout extension, all vendored
// locally (see internal/api/server.go's //go:embed) so `authz-graph
// serve` stays a single self-contained executable with no CDN/runtime
// network dependency -- this matters for exactly the kind of
// air-gapped/security-conscious environment a tool that visualizes an
// entire authorization graph is likely to run in.
cytoscape.use(cytoscapeDagre);

const NODE_COLORS = {
  aws_iam_user: "#2E6E9E",
  aws_iam_group: "#5B8FB9",
  aws_iam_role: "#1F3A5F",
  k8s_service_account: "#1E7B34",
  k8s_role: "#4FA65F",
  k8s_cluster_role: "#0B5122",
  k8s_user: "#B7791F",
  k8s_group: "#C9962F",
  resource: "#6b7280",
};

const KIND_LABELS = {
  aws_iam_user: "AWS IAM user",
  aws_iam_group: "AWS IAM group",
  aws_iam_role: "AWS IAM role",
  k8s_service_account: "Kubernetes ServiceAccount",
  k8s_role: "Kubernetes Role",
  k8s_cluster_role: "Kubernetes ClusterRole",
  k8s_user: "Kubernetes User (inferred)",
  k8s_group: "Kubernetes Group (inferred)",
  resource: "Resource (grant target)",
};

// Grant edges are colored by Effect (Allow=green, Deny=red) rather than
// a flat "grants" color -- an explicit Deny is a meaningfully different,
// security-relevant thing to see in this graph, not a styling detail.
// Identity/membership edges (member_of/can_assume/bound_by) all render
// the same dashed gray -- the distinction that matters visually is
// "this is how you get somewhere" vs. "this is what you're actually
// allowed to do once you're there," not which specific identity
// mechanism applies.
function edgeColor(data) {
  if (data.kind === "grants") return data.effect === "Deny" ? "#B42318" : "#1E7B34";
  return "#94a3b8";
}
function edgeLineStyle(data) {
  return data.kind === "grants" ? "solid" : "dashed";
}
function edgeWidth(data) {
  return data.kind === "grants" ? 2 : 1.2;
}

let cy = null;
const tooltip = () => document.getElementById("graph-tooltip");

function initCytoscape() {
  cy = cytoscape({
    container: document.getElementById("cy"),
    minZoom: 0.05,
    maxZoom: 4,
    style: [
      {
        selector: "node",
        style: {
          "background-color": (n) => NODE_COLORS[n.data("kind")] || "#999",
          shape: (n) => (n.data("kind") === "resource" ? "round-rectangle" : "ellipse"),
          // Node size reflects degree (how many edges touch it) --
          // a ClusterRole bound by 40 things should visually read as
          // more central than a leaf ServiceAccount, which a uniform
          // fixed size (the previous behavior) can't convey at all.
          width: (n) => Math.min(52, 20 + Math.sqrt(n.degree()) * 6),
          height: (n) => Math.min(52, 20 + Math.sqrt(n.degree()) * 6),
          label: "data(label)",
          "font-size": 10.5,
          "font-family": "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif",
          color: "#1a2433",
          "text-valign": "bottom",
          "text-margin-y": 5,
          "text-wrap": "wrap",
          "text-max-width": "120px",
          "text-background-color": "#ffffff",
          "text-background-opacity": 0.85,
          "text-background-shape": "roundrectangle",
          "text-background-padding": "2px",
          "border-width": 1.5,
          "border-color": "#ffffff",
        },
      },
      {
        selector: "edge",
        style: {
          width: (e) => edgeWidth(e.data()),
          "line-color": (e) => edgeColor(e.data()),
          "line-style": (e) => edgeLineStyle(e.data()),
          "target-arrow-shape": "triangle",
          "target-arrow-color": (e) => edgeColor(e.data()),
          "arrow-scale": 0.9,
          "curve-style": "bezier",
          opacity: 0.85,
          // No permanent edge labels -- with more than a couple dozen
          // edges on screen at once (routine for a real cluster's
          // grants), always-on labels overlap into an unreadable mess.
          // Full detail (kind/effect/action/resource/granted-via) is a
          // hover away -- see the graph-tooltip wiring below -- and the
          // left-hand results panel already shows the same detail as
          // structured text for the current query.
        },
      },
      { selector: "node.faded", style: { opacity: 0.12 } },
      { selector: "edge.faded", style: { opacity: 0.05 } },
      { selector: "node.matched", style: { "border-width": 3, "border-color": "#111827" } },
    ],
    layout: dagreLayoutOptions(),
  });

  wireGraphInteractions();
  wireToolbar();
  updateEmptyState();
}

// dagre (a hierarchical/layered layout) is a much better fit for this
// graph than the previous default (`cose`, force-directed) -- almost
// everything here is fundamentally a DAG (principal -> group/role ->
// policy/binding -> grant), and a layered top-down/left-right layout
// makes that chain structure immediately legible. Force-directed
// layouts are the right tool for graphs without inherent direction;
// this graph has direction built into every edge kind.
function dagreLayoutOptions() {
  return {
    name: "dagre",
    rankDir: "LR",
    nodeSep: 32,
    rankSep: 90,
    edgeSep: 8,
    animate: false,
  };
}

function wireGraphInteractions() {
  const tt = tooltip();

  function showTooltip(evt, html) {
    tt.innerHTML = html;
    tt.hidden = false;
    positionTooltip(evt);
  }
  function positionTooltip(evt) {
    const oe = evt.originalEvent;
    if (!oe) return;
    const pad = 16;
    // Keep the tooltip on-screen near the right/bottom edges rather
    // than letting it run off the viewport.
    const maxLeft = window.innerWidth - 380;
    const maxTop = window.innerHeight - 100;
    tt.style.left = Math.min(oe.clientX + pad, maxLeft) + "px";
    tt.style.top = Math.min(oe.clientY + pad, maxTop) + "px";
  }
  function hideTooltip() {
    tt.hidden = true;
  }

  cy.on("mouseover", "node", (evt) => showTooltip(evt, nodeTooltipHTML(evt.target.data())));
  cy.on("mousemove", "node", positionTooltip);
  cy.on("mouseout", "node", hideTooltip);

  cy.on("mouseover", "edge", (evt) => showTooltip(evt, edgeTooltipHTML(evt.target.data())));
  cy.on("mousemove", "edge", positionTooltip);
  cy.on("mouseout", "edge", hideTooltip);

  cy.on("pan zoom", hideTooltip); // don't leave a stale tooltip floating while the view moves
}

function nodeTooltipHTML(data) {
  const kindLabel = KIND_LABELS[data.kind] || data.kind;
  return `<div class="tt-title">${escapeHTML(data.label)}</div>` +
    `<div class="tt-row"><b>Kind:</b> ${escapeHTML(kindLabel)}</div>` +
    (data.label !== data.id ? `<div class="tt-row"><b>ID:</b> ${escapeHTML(data.id)}</div>` : "");
}

function edgeTooltipHTML(data) {
  if (data.kind === "grants") {
    return `<div class="tt-title">${escapeHTML(data.effect || "Allow")} &middot; ${escapeHTML(data.action || "")}</div>` +
      `<div class="tt-row"><b>Resource:</b> ${escapeHTML(data.resource || "")}</div>` +
      (data.grantedVia ? `<div class="tt-row"><b>Via:</b> ${escapeHTML(data.grantedVia)}</div>` : "");
  }
  return `<div class="tt-title">${escapeHTML(data.kind)}</div>` +
    (data.grantedVia ? `<div class="tt-row"><b>Via:</b> ${escapeHTML(data.grantedVia)}</div>` : "");
}

function wireToolbar() {
  document.getElementById("zoom-in-btn").addEventListener("click", () => zoomBy(1.25));
  document.getElementById("zoom-out-btn").addEventListener("click", () => zoomBy(0.8));
  document.getElementById("fit-btn").addEventListener("click", () => cy.fit(undefined, 40));
  document.getElementById("relayout-btn").addEventListener("click", () => {
    cy.layout(dagreLayoutOptions()).run();
    cy.fit(undefined, 40);
  });
}

function zoomBy(factor) {
  cy.zoom({
    level: cy.zoom() * factor,
    renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
  });
}

function updateEmptyState() {
  const el = document.getElementById("graph-empty-state");
  el.classList.toggle("hidden", cy.elements().length > 0);
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
        effect: e.effect,
        action: e.action,
        resource: e.resource,
        grantedVia: e.grantedVia,
      },
    });
  }
  cy.add(els);
  cy.layout(dagreLayoutOptions()).run();
  cy.fit(undefined, 40);
  updateEmptyState();

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
  document.getElementById("node-count").textContent = `${principals.length} principals loaded`;
  return principals.map((p) => ({ value: p.id, label: `${p.id} (${p.kind})` }));
}

// Loads a plain-string list (Action/Resource) from an API endpoint
// returning a JSON array of strings, in the {value, label} shape
// setupCombobox expects.
async function loadStringOptions(endpoint) {
  const values = await fetchJSON(endpoint);
  return values.map((v) => ({ value: v }));
}

// Replaces the native <input list>+<datalist> pattern this UI used to
// use for Principal/Action/Resource. Native datalist only shows options
// that PREFIX-match the field's CURRENT value -- so the moment a field
// already has text in it that isn't a prefix of anything (which is
// most of the time, once you've picked or typed something), the
// dropdown has nothing to show at all until you clear the field back
// to empty. That's fine for a handful of options; it's unusable once
// Action/Resource routinely run into the hundreds, which real AWS
// accounts do (see handleActions/handleResources in
// internal/api/server.go -- these are real distinct values pulled from
// the ingested graph's own grants edges, not a short curated list).
//
// This dropdown instead always shows every current SUBSTRING match
// against whatever's typed, capped at COMBOBOX_MAX_VISIBLE for render
// performance, with a "+N more, keep typing" hint past the cap.
const COMBOBOX_MAX_VISIBLE = 200;

function setupCombobox(inputId, menuId) {
  const input = document.getElementById(inputId);
  const menu = document.getElementById(menuId);
  let options = []; // full list, set once data loads
  let visible = []; // currently rendered/filtered subset, for keyboard nav + selection-by-index

  function render(filterText) {
    const q = filterText.trim().toLowerCase();
    visible = q
      ? options.filter((o) => o.value.toLowerCase().includes(q) || (o.label || "").toLowerCase().includes(q))
      : options;

    menu.innerHTML = "";

    if (options.length === 0) {
      const empty = document.createElement("div");
      empty.className = "combobox-empty";
      empty.textContent = "No values ingested yet -- run ingest-aws/ingest-k8s first";
      menu.appendChild(empty);
      menu.hidden = false;
      return;
    }
    if (visible.length === 0) {
      const empty = document.createElement("div");
      empty.className = "combobox-empty";
      empty.textContent = "No matches -- press Enter to use this value as free text anyway";
      menu.appendChild(empty);
      menu.hidden = false;
      return;
    }

    const shown = visible.slice(0, COMBOBOX_MAX_VISIBLE);
    shown.forEach((opt) => {
      const el = document.createElement("div");
      el.className = "combobox-option";
      el.textContent = opt.label || opt.value;
      el.title = opt.label || opt.value;
      // mousedown (not click) fires BEFORE the input's blur event, so
      // the value is set before the blur handler would otherwise hide
      // the menu out from under the click.
      el.addEventListener("mousedown", (e) => {
        e.preventDefault();
        selectOption(opt.value);
      });
      menu.appendChild(el);
    });
    if (visible.length > shown.length) {
      const hint = document.createElement("div");
      hint.className = "combobox-hint";
      hint.textContent = `+${visible.length - shown.length} more -- keep typing to narrow`;
      menu.appendChild(hint);
    }
    menu.hidden = false;
  }

  function selectOption(value) {
    input.value = value;
    menu.hidden = true;
    input.focus();
  }

  function setActive(idx) {
    const opts = menu.querySelectorAll(".combobox-option");
    opts.forEach((o) => o.classList.remove("active"));
    if (idx >= 0 && idx < opts.length) {
      opts[idx].classList.add("active");
      opts[idx].scrollIntoView({ block: "nearest" });
    }
    return idx;
  }

  let activeIndex = -1;

  input.addEventListener("focus", () => render(input.value));
  input.addEventListener("input", () => {
    render(input.value);
    activeIndex = -1;
  });
  input.addEventListener("keydown", (e) => {
    const opts = menu.querySelectorAll(".combobox-option");
    if (menu.hidden || opts.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      activeIndex = setActive(Math.min(activeIndex + 1, opts.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      activeIndex = setActive(Math.max(activeIndex - 1, 0));
    } else if (e.key === "Enter" && activeIndex >= 0) {
      e.preventDefault();
      selectOption(visible[activeIndex].value);
    } else if (e.key === "Escape") {
      menu.hidden = true;
    }
  });
  document.addEventListener("mousedown", (e) => {
    if (e.target !== input && !menu.contains(e.target)) {
      menu.hidden = true;
    }
  });

  return {
    setOptions(newOptions) {
      options = newOptions;
    },
  };
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
        edges.push({
          from: hop.Edge.From,
          to: resourceID,
          kind: "grants",
          action: hop.Edge.Action,
          effect: hop.Edge.Effect,
          resource: hop.Edge.Resource,
          grantedVia: hop.Edge.GrantedVia,
        });
      } else {
        nodes.push({ id: hop.From.ID, name: hop.From.Name || hop.From.ID, kind: hop.From.Kind });
        nodes.push({ id: hop.To.ID, name: hop.To.Name || hop.To.ID, kind: hop.To.Kind });
        edges.push({ from: hop.Edge.From, to: hop.Edge.To, kind: hop.Edge.Kind, grantedVia: hop.Edge.GrantedVia });
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
    // Real edges from the graph connecting this reachable set (see
    // handleEffective in internal/api/server.go) -- not synthesized,
    // so the drawing shows exactly why each node is reachable, not
    // just a disconnected cloud of nodes that happen to be related.
    const edges = (body.edges || []).map((e) => ({ from: e.From, to: e.To, kind: e.Kind, grantedVia: e.GrantedVia }));
    renderElements(mapped, edges);
  } catch (e) {
    renderResultsError(e.message);
  }
}

// Renders AllGrants' output: every actual permission reachable from a
// principal, without needing to already know a specific action/resource
// to ask WhyAccess about -- this is usually the starting point, with
// "Why" as the follow-up once you've spotted something here worth
// tracing back to its root cause.
async function runGrants() {
  const principal = document.getElementById("grants-principal-input").value.trim();
  if (!principal) {
    renderResultsError("principal is required");
    return;
  }
  try {
    const body = await fetchJSON(`/api/grants?principal=${encodeURIComponent(principal)}`);
    const grants = body.grants || [];
    if (grants.length === 0) {
      document.getElementById("results").innerHTML = `<div class="empty">No grants found for ${escapeHTML(principal)} (or anything it can reach via membership/assume/binding).</div>`;
      renderElements([], []);
      return;
    }
    document.getElementById("results").innerHTML =
      `<div class="path"><strong>${grants.length} grant(s)</strong>` +
      grants.map((g) => {
        const via = g.HeldBy.ID !== principal ? ` <span class="muted">(via ${escapeHTML(g.HeldBy.ID)}, ${escapeHTML(g.HeldBy.Kind)})</span>` : "";
        return `<div class="hop"><strong>${escapeHTML(g.Edge.Effect)}</strong> ${escapeHTML(g.Edge.Action)} on ${escapeHTML(g.Edge.Resource)}${via} <span class="muted">(via ${escapeHTML(g.Edge.GrantedVia)})</span></div>`;
      }).join("") +
      `</div>`;

    const nodes = [];
    const edges = [];
    for (const g of grants) {
      const resourceID = "resource:" + g.Edge.Resource;
      nodes.push({ id: g.HeldBy.ID, name: g.HeldBy.Name || g.HeldBy.ID, kind: g.HeldBy.Kind });
      nodes.push({ id: resourceID, name: g.Edge.Resource, kind: "resource" });
      edges.push({
        from: g.HeldBy.ID,
        to: resourceID,
        kind: "grants",
        action: g.Edge.Action,
        effect: g.Edge.Effect,
        resource: g.Edge.Resource,
        grantedVia: g.Edge.GrantedVia,
      });
    }
    renderElements(nodes, edges);
  } catch (e) {
    renderResultsError(e.message);
  }
}

async function runFullGraph() {
  try {
    const body = await fetchJSON("/api/graph");
    const nodes = (body.nodes || []).map((n) => ({ id: n.ID, name: n.Name || n.ID, kind: n.Kind }));
    const edges = (body.edges || [])
      .filter((e) => e.Kind !== "grants") // grants edges' target is a resource pattern, not a node -- omit from the full-graph identity view to avoid thousands of synthetic resource nodes; use "Why"/"List all grants" for grant-level detail on a specific principal
      .map((e) => ({ from: e.From, to: e.To, kind: e.Kind, grantedVia: e.GrantedVia }));
    document.getElementById("results").innerHTML = `<div class="muted">Showing ${nodes.length} nodes and ${edges.length} identity/membership edges (grants edges omitted here -- use "Why" or "List all grants" for grant-level detail).</div>`;
    renderElements(nodes, edges);
  } catch (e) {
    renderResultsError(e.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initCytoscape();

  const principalCombo = setupCombobox("principal-input", "principal-menu");
  const effectivePrincipalCombo = setupCombobox("effective-principal-input", "effective-principal-menu");
  const grantsPrincipalCombo = setupCombobox("grants-principal-input", "grants-principal-menu");
  const actionCombo = setupCombobox("action-input", "action-menu");
  const resourceCombo = setupCombobox("resource-input", "resource-menu");

  // Principal, Effective-principal, and Grants-principal all share the
  // same underlying option list (every node in the graph).
  loadPrincipalList()
    .then((opts) => {
      principalCombo.setOptions(opts);
      effectivePrincipalCombo.setOptions(opts);
      grantsPrincipalCombo.setOptions(opts);
    })
    .catch((e) => renderResultsError(e.message));
  loadStringOptions("/api/actions").then((opts) => actionCombo.setOptions(opts)).catch((e) => renderResultsError(e.message));
  loadStringOptions("/api/resources").then((opts) => resourceCombo.setOptions(opts)).catch((e) => renderResultsError(e.message));

  document.getElementById("why-btn").addEventListener("click", runWhy);
  document.getElementById("effective-btn").addEventListener("click", runEffective);
  document.getElementById("grants-btn").addEventListener("click", runGrants);
  document.getElementById("full-graph-btn").addEventListener("click", runFullGraph);
  document.getElementById("node-filter-input").addEventListener("input", (e) => applyNodeFilter(e.target.value));
});
