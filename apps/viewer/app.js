import { readLocalFile, resolveView, pathLabel } from "./model.mjs";

/** DOM construction only. Untrusted JSON is always assigned as textContent. */
export function initViewer(doc) {
  const elements = {
    before: doc.getElementById("before-file"), after: doc.getElementById("after-file"),
    diff: doc.getElementById("diff-file"), clear: doc.getElementById("clear"),
    overview: doc.getElementById("overview"), grid: doc.getElementById("tree-grid"),
    changes: doc.getElementById("changes"), status: doc.getElementById("status"),
    error: doc.getElementById("error")
  };
  const state = {before: null, after: null, diff: null};
  const el = (tag, className, content) => {
    const node = doc.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = String(content);
    return node;
  };
  function error(message) {
    elements.error.hidden = !message;
    elements.error.textContent = message || "";
  }
  function treeNode(node) {
    const details = el("details", node.status);
    const summary = el("summary", null, `${node.contract}.${node.method}`);
    summary.setAttribute("aria-label", `${node.status} ${node.kind} ${node.contract}.${node.method}; ${node.children.length} nested calls`);
    details.append(summary, el("div", "node-details", `${node.kind} · args SHA-256 ${node.argumentsSha256.slice(0, 16)}…`));
    for (const child of node.children) details.append(treeNode(child));
    return details;
  }
  function treePanel(title, entries) {
    const panel = el("section", "tree-panel");
    panel.append(el("h3", null, title));
    if (!entries.length) { panel.append(el("p", "muted", "No authorization entries in this snapshot.")); return panel; }
    entries.forEach((entry, index) => {
      const block = el("div", "entry"), meta = el("div", "entry-meta");
      meta.append(el("strong", null, `Entry ${index + 1} · ${entry.authorizer}`),
        el("span", null, `Credential: ${entry.credential}`));
      if (entry.delegates.length) meta.append(el("span", null, `Delegates: ${entry.delegates.join(", ")}`));
      if (entry.delegateTree.length) {
        const label = el("span", null, "Delegate signer hierarchy:");
        function signerList(signers) {
          const list = el("ul", "delegate-list");
          for (const signer of signers) {
            const item = el("li", null, signer.address);
            if (signer.children.length) item.append(signerList(signer.children));
            list.append(item);
          }
          return list;
        }
        meta.append(label, signerList(entry.delegateTree));
      }
      block.append(meta, treeNode(entry.root));
      panel.append(block);
    });
    return panel;
  }
  function changePanel(title, deltas, className) {
    const panel = el("section", "diff-panel");
    panel.append(el("h3", null, `${title} (${deltas.length})`));
    if (!deltas.length) panel.append(el("p", "muted", "None"));
    for (const change of deltas) {
      const row = el("div", `change-row ${className}`);
      row.append(el("b", null, `×${change.count} ${pathLabel(change.path)}`));
      let authorizer = change.authorizer;
      try { const identity = JSON.parse(change.authorizer); if (Array.isArray(identity)) authorizer = String(identity[1]); }
      catch { /* Keep original encoded metadata as inert text. */ }
      row.append(el("small", null, `Authorizer: ${authorizer}`));
      panel.append(row);
    }
    return panel;
  }
  function render() {
    elements.overview.replaceChildren(); elements.grid.replaceChildren(); elements.changes.replaceChildren();
    if (!state.before && !state.after && !state.diff) {
      elements.status.textContent = "Awaiting local JSON reports";
      elements.overview.append(el("p", "empty", "Import a snapshot or comparison JSON file to begin."));
      return;
    }
    const view = resolveView(state.before, state.after, state.diff);
    const report = view.comparison;
    const metrics = el("div", "metrics");
    const values = [
      [state.before?.authorizationCount ?? report?.beforeCount ?? "—", "Before authorizations"],
      [state.after?.authorizationCount ?? report?.afterCount ?? "—", "After authorizations"],
      [report ? report.changes.length : "—", "Changed scope paths"]
    ];
    for (const [value, label] of values) {
      const item = el("div", "metric");
      item.append(el("span", "metric-value", value), el("span", "metric-label", label));
      metrics.append(item);
    }
    elements.overview.append(metrics);
    if (state.before) elements.grid.append(treePanel("Before · authorization tree", view.before));
    if (state.after) elements.grid.append(treePanel("After · authorization tree", view.after));
    if (report) {
      const groups = el("div", "diff-groups");
      groups.append(changePanel("Added scope", view.additions, "added"), changePanel("Removed scope", view.removals, "removed"));
      elements.changes.append(groups);
      elements.status.textContent = report.changed ? "Changed scope · review required" : "No scope change detected · not a safety assessment";
    } else elements.status.textContent = "Snapshot loaded · add another snapshot to compare";
  }
  for (const [slot, expected] of [["before", "snapshot"], ["after", "snapshot"], ["diff", "comparison"]]) {
    const input = elements[slot];
    input.addEventListener("change", async () => {
      const file = input.files?.[0];
      if (!file) return;
      try {
        const value = await readLocalFile(file, expected);
        const previous = state[slot]; state[slot] = value;
        try { resolveView(state.before, state.after, state.diff); }
        catch (cause) { state[slot] = previous; throw cause; }
        doc.getElementById(`${slot}-status`).textContent = `${file.name} · loaded locally`;
        error(""); render();
      } catch (cause) {
        error(cause instanceof Error ? cause.message : "Could not load local report.");
        input.value = "";
      }
    });
  }
  elements.clear.addEventListener("click", () => {
    state.before = null; state.after = null; state.diff = null;
    for (const slot of ["before", "after", "diff"]) {
      elements[slot].value = "";
      doc.getElementById(`${slot}-status`).textContent = "No file selected";
    }
    error(""); render();
  });
  render();
  return { state, render };
}
if (typeof document !== "undefined") initViewer(document);
