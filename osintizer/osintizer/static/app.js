/* OSINTizer dashboard — vanilla JS, no external dependencies. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const PIVOTS = { emails: "email", users: "username", domains: "domain", subdomains: "domain", ips: "ip", urls: "url" };

const state = {
  meta: null,
  cases: [],
  caseId: null,
  findings: [],
  runs: [],
  collapsed: new Set(),
  activeCats: new Set(),
  openNotes: new Set(),
  selectedRun: null,
  lastSeen: 0,
  pollTimer: null,
  knownRunStatus: new Map(),
  targetType: "",
};

// ------------------------------------------------------------------ storage
const store = {
  get(k, d) { try { const v = localStorage.getItem("osintizer:" + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("osintizer:" + k, JSON.stringify(v)); } catch { /* private mode */ } },
};

// ---------------------------------------------------------------------- api
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (init.method !== "GET") init.headers["X-OSINTizer"] = "1";
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, init);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function toast(msg, kind = "") {
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), kind === "err" ? 7000 : 4000);
}

function ago(ts) {
  if (!ts) return "";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return new Date(ts * 1000).toLocaleDateString();
}

function catLabel(id) { return (state.meta.categories.find((c) => c.id === id) || { label: id }).label; }

// --------------------------------------------------------------------- tabs
function showTab(name) {
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".tabpanel").forEach((p) => (p.hidden = p.id !== "tab-" + name));
  store.set("tab", name);
  if (name === "findings") markSeenSoon();
}

// -------------------------------------------------------------------- cases
async function loadCases(selectId) {
  state.cases = await api("/api/cases");
  const sel = $("#caseSelect");
  sel.innerHTML = state.cases.map((c) => `<option value="${c.id}">${esc(c.name)}${c.target ? " — " + esc(c.target) : ""}</option>`).join("");
  const has = state.cases.length > 0;
  $("#welcome").hidden = has;
  $(".tabs").hidden = !has;
  $$(".tabpanel").forEach((p) => { if (!has) p.hidden = true; });
  $("#caseSelect").disabled = !has;
  $("#exportBtn").disabled = !has;
  if (!has) { state.caseId = null; return; }
  const want = selectId ?? state.caseId ?? store.get("case", null);
  state.caseId = state.cases.some((c) => c.id === want) ? want : state.cases[0].id;
  sel.value = state.caseId;
  await openCase();
}

async function openCase() {
  store.set("case", state.caseId);
  state.lastSeen = store.get("seen:" + state.caseId, 0);
  state.activeCats = new Set(store.get("filters:" + state.caseId, []));
  state.selectedRun = null;
  $("#console").hidden = true;
  const c = currentCase();
  const f = $("#caseForm");
  f.elements.name.value = c.name; f.elements.target.value = c.target; f.elements.scope.value = c.scope.replace(/,/g, ", "); f.elements.notes.value = c.notes;
  if (!$("#targetInput").value || $("#targetInput").dataset.auto === "1") {
    $("#targetInput").value = c.target || "";
    $("#targetInput").dataset.auto = "1";
    onTarget();
  }
  showTab(store.get("tab", "findings"));
  await Promise.all([loadFindings(), loadRuns()]);
}

function currentCase() { return state.cases.find((c) => c.id === state.caseId); }

async function createCase(form) {
  const body = { name: form.elements.name.value, target: form.elements.target.value, scope: form.elements.scope.value };
  const c = await api("/api/cases", { method: "POST", body });
  toast(`Case "${c.name}" created`, "good");
  store.set("tab", "collectors");
  $("#targetInput").value = c.target || "";
  $("#targetInput").dataset.auto = "1";
  await loadCases(c.id);
}

// ----------------------------------------------------------------- findings
async function loadFindings() {
  if (!state.caseId) return;
  state.findings = await api(`/api/cases/${state.caseId}/findings`);
  renderFindings();
}

function filteredFindings() {
  const q = $("#search").value.trim().toLowerCase();
  const st = $("#statusFilter").value;
  const starOnly = $("#starOnly").checked;
  const oos = $("#showOos").checked;
  return state.findings.filter((f) => {
    if (!oos && !f.in_scope) return false;
    if (starOnly && !f.starred) return false;
    if (st && f.status !== st) return false;
    if (q) {
      const hay = `${f.value} ${f.detail} ${f.notes} ${f.sources.join(" ")} ${f.status}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderFindings() {
  const list = filteredFindings();
  const visibleTotal = state.findings.filter((f) => f.in_scope || $("#showOos").checked).length;
  $("#findCount").textContent = visibleTotal;
  const oosN = state.findings.filter((f) => !f.in_scope).length;
  $("#oosCount").textContent = oosN ? `(${oosN})` : "";

  const byCat = {};
  for (const f of list) (byCat[f.category] ||= []).push(f);

  // filter chips: click to show only those groups (multi-select); "All" clears
  const active = state.activeCats;
  $("#chips").innerHTML = `<button class="chip ${active.size ? "" : "on"}" data-filter="">
      <span>All</span><span class="n">${list.length}</span></button>` +
    state.meta.categories.map((c) => {
      const items = byCat[c.id] || [];
      const fresh = items.filter((f) => f.first_seen > state.lastSeen).length;
      return `<button class="chip ${items.length ? "" : "zero"} ${active.has(c.id) ? "on" : ""}" data-filter="${c.id}">
        <span>${esc(c.label)}</span><span class="n">${items.length}</span>${fresh && state.lastSeen ? `<span class="new">+${fresh}</span>` : ""}
      </button>`;
    }).join("");

  const groups = state.meta.categories.filter((c) => byCat[c.id]?.length && (!active.size || active.has(c.id)));
  $("#emptyFindings").hidden = state.findings.length > 0;
  $("#groups").innerHTML = groups.map((c) => groupHTML(c, byCat[c.id])).join("") ||
    (state.findings.length ? `<div class="empty"><p>No findings match the current filters.</p></div>` : "");
}

function groupHTML(cat, items) {
  const collapsed = state.collapsed.has(cat.id);
  const pivot = PIVOTS[cat.id];
  const statuses = state.meta.statuses;
  const rows = items.map((f) => {
    const fresh = state.lastSeen && f.first_seen > state.lastSeen;
    const cls = [f.in_scope ? "" : "oos", f.status === "false-positive" ? "fp" : "", fresh ? "fresh" : ""].join(" ");
    const notesOpen = state.openNotes.has(f.id);
    return `<tr class="${cls}" data-id="${f.id}">
      <td><button class="star ${f.starred ? "on" : ""}" data-act="star" title="Mark as key finding">★</button></td>
      <td><div class="val" data-act="copy" title="Click to copy">${esc(f.value)}</div>${f.in_scope ? "" : '<span class="tag-oos">out of scope</span>'}
        ${f.notes && !notesOpen ? `<div class="note-preview">✎ ${esc(f.notes.slice(0, 140))}</div>` : ""}</td>
      <td class="det">${esc(f.detail)}</td>
      <td>${f.sources.map((s) => `<span class="src">${esc(s)}</span>`).join("")}${f.hits > 1 ? `<span class="src" title="times seen">×${f.hits}</span>` : ""}</td>
      <td><select data-act="status">${statuses.map((s) => `<option ${s === f.status ? "selected" : ""}>${s}</option>`).join("")}</select></td>
      <td class="acts">
        ${pivot ? `<button class="iconbtn" data-act="pivot" data-type="${pivot}" title="Use as a collector target">▸ pivot</button>` : ""}
        <button class="iconbtn" data-act="notes" title="Notes">✎</button>
        <button class="iconbtn" data-act="del" title="Delete">✕</button>
      </td>
    </tr>${notesOpen ? `<tr class="notes-row" data-id="${f.id}"><td></td><td colspan="5">
      <textarea rows="3" data-act="notes-edit" placeholder="Notes for this finding…">${esc(f.notes)}</textarea></td></tr>` : ""}`;
  }).join("");
  return `<section class="group ${collapsed ? "collapsed" : ""}" id="grp-${cat.id}" data-cat="${cat.id}">
    <div class="group-head" data-act="toggle">
      <span class="ico">${esc(cat.icon)}</span>
      <h3>${esc(cat.label)}</h3>
      <span class="count">${items.length}</span>
      <span class="spacer"></span>
      <button class="iconbtn" data-act="copy-group" title="Copy all values in this group">Copy all</button>
      <span class="chev">▾</span>
    </div>
    <div class="group-body"><table>
      <colgroup><col style="width:34px"><col style="width:36%"><col><col style="width:15%"><col style="width:140px"><col style="width:150px"></colgroup>
      <thead><tr><th></th><th>Value</th><th>Detail</th><th>Found by</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </section>`;
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); }
  catch {
    const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); ta.remove(); toast("Copied");
  }
}

async function onFindingsClick(e) {
  const el = e.target.closest("[data-act]");
  if (!el) return;
  const act = el.dataset.act;
  const group = el.closest(".group");
  const row = el.closest("tr[data-id]");
  const id = row && +row.dataset.id;
  const f = id && state.findings.find((x) => x.id === id);

  if (act === "toggle" && !e.target.closest(".iconbtn")) {
    const cat = group.dataset.cat;
    state.collapsed.has(cat) ? state.collapsed.delete(cat) : state.collapsed.add(cat);
    group.classList.toggle("collapsed");
    return;
  }
  if (act === "copy-group") {
    e.stopPropagation();
    const vals = filteredFindings().filter((x) => x.category === group.dataset.cat).map((x) => x.value);
    return copy(vals.join("\n"));
  }
  if (!f) return;
  if (act === "copy") return copy(f.value);
  if (act === "star") {
    f.starred = f.starred ? 0 : 1;
    el.classList.toggle("on", !!f.starred);
    await api(`/api/findings/${id}`, { method: "PATCH", body: { starred: f.starred } });
  }
  if (act === "notes") {
    state.openNotes.has(id) ? state.openNotes.delete(id) : state.openNotes.add(id);
    renderFindings();
    const ta = $(`tr.notes-row[data-id="${id}"] textarea`);
    if (ta) ta.focus();
  }
  if (act === "del") {
    if (!confirm(`Delete "${f.value}"?`)) return;
    await api(`/api/findings/${id}`, { method: "DELETE" });
    state.findings = state.findings.filter((x) => x.id !== id);
    renderFindings();
  }
  if (act === "pivot") {
    $("#targetInput").value = f.value;
    $("#targetInput").dataset.auto = "0";
    onTarget();
    showTab("collectors");
    $("#targetInput").focus();
  }
}

async function onFindingsChange(e) {
  const el = e.target;
  const row = el.closest("tr[data-id]");
  if (!row) return;
  const id = +row.dataset.id;
  const f = state.findings.find((x) => x.id === id);
  if (el.dataset.act === "status") {
    f.status = el.value;
    await api(`/api/findings/${id}`, { method: "PATCH", body: { status: f.status } });
    row.classList.toggle("fp", f.status === "false-positive");
  }
  if (el.dataset.act === "notes-edit") {
    f.notes = el.value;
    await api(`/api/findings/${id}`, { method: "PATCH", body: { notes: f.notes } });
    toast("Note saved");
  }
}

let seenTimer = null;
function markSeenSoon() {
  clearTimeout(seenTimer);
  // Highlights stay for a moment after you look, then clear next time you come back.
  seenTimer = setTimeout(() => {
    const newest = Math.max(0, ...state.findings.map((f) => f.first_seen || 0));
    if (state.caseId && newest) store.set("seen:" + state.caseId, newest);
  }, 4000);
}

// --------------------------------------------------------------- collectors
async function onTarget() {
  const t = $("#targetInput").value.trim();
  let info = { type: "", collectors: [] };
  if (t) { try { info = await api(`/api/detect?target=${encodeURIComponent(t)}`); } catch { /* ignore */ } }
  state.targetType = info.type;
  const badge = $("#targetType");
  badge.textContent = info.type || (t ? "unknown" : "—");
  badge.classList.toggle("ok", !!info.type);
  renderCollectors();
}

function runnable() {
  return state.meta.collectors.filter((c) => c.installed && c.inputs.includes(state.targetType) && !c.active);
}

function renderCollectors() {
  const args = store.get("args", {});
  const t = state.targetType;
  const allowActive = $("#allowActive").checked;
  $("#collectorGrid").innerHTML = state.meta.collectors.map((c) => {
    const match = t && c.inputs.includes(t);
    return `<div class="card ${match ? "match" : t ? "dim" : ""}" data-col="${c.id}">
      <h4>${esc(c.name)}</h4>
      <div class="badges">
        ${c.inputs.map((i) => `<span class="b">${i}</span>`).join("")}
        ${c.active ? '<span class="b active" title="Interacts with the target directly">active</span>' : '<span class="b">passive</span>'}
        ${c.installed ? '<span class="b ok">ready</span>' : '<span class="b miss">not installed</span>'}
      </div>
      <p>${esc(c.description)}</p>
      ${c.installed ? `<details><summary>Arguments</summary><input data-args="${c.id}" value="${esc(args[c.id] ?? c.args)}" spellcheck="false"></details>`
                    : `<code>${esc(c.install)}</code>`}
      <div class="row"><span></span><button class="btn ${match ? "primary" : ""} sm" data-run="${c.id}" ${match && c.installed && (!c.active || allowActive) ? "" : "disabled"} title="${c.active && !allowActive ? "Turn on 'Allow active collectors' to use this" : ""}">Run</button></div>
    </div>`;
  }).join("");
  const n = runnable().length;
  $("#runAllBtn").textContent = `Run all passive (${n})`;
  $("#runAllBtn").disabled = n === 0;
}

function collectArgs(ids) {
  const saved = store.get("args", {});
  const out = {};
  for (const id of ids) {
    const input = $(`[data-args="${id}"]`);
    if (input) { out[id] = input.value; saved[id] = input.value; }
  }
  store.set("args", saved);
  return out;
}

async function startRuns(ids) {
  const target = $("#targetInput").value.trim();
  try {
    const res = await api(`/api/cases/${state.caseId}/runs`, { method: "POST", body: { target, collectors: ids, args: collectArgs(ids), allow_active: $("#allowActive").checked } });
    res.errors.forEach((e) => toast(`${e.collector}: ${e.error}`, "err"));
    if (res.started.length) toast(`Queued ${res.started.length} collector${res.started.length > 1 ? "s" : ""} on ${target} — they run one at a time`);
    await loadRuns();
    if (res.started.length === 1) selectRun(res.started[0]);
  } catch (err) { toast(err.message, "err"); }
}

// --------------------------------------------------------------------- runs
async function loadRuns() {
  if (!state.caseId) return;
  state.runs = await api(`/api/cases/${state.caseId}/runs`);
  let finishedSomething = false;
  for (const r of state.runs) {
    const prev = state.knownRunStatus.get(r.id);
    if (prev && (prev === "running" || prev === "queued") && r.status !== prev) {
      finishedSomething = true;
      if (r.status === "done") toast(`${r.collector} finished on ${r.target}: +${r.findings_new} new finding${r.findings_new === 1 ? "" : "s"}`, "good");
      else toast(`${r.collector} ${r.status}${r.error ? ": " + r.error : ""}`, "err");
    }
    state.knownRunStatus.set(r.id, r.status);
  }
  renderRuns();
  if (finishedSomething) await loadFindings();
  const live = state.runs.filter((r) => r.status === "running" || r.status === "queued").length;
  $("#liveCount").hidden = !live;
  $("#liveCount").textContent = live;
  schedulePoll(live > 0);
  if (state.selectedRun) refreshConsole();
}

function schedulePoll(active) {
  clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(loadRuns, active ? 1500 : 8000);
}

function renderRuns() {
  const total = state.runs.reduce((a, r) => a + (r.findings_new || 0), 0);
  $("#runsSummary").textContent = state.runs.length ? `${state.runs.length} runs · ${total} findings` : "";
  $("#runList").innerHTML = state.runs.length ? state.runs.map((r) => `
    <li data-run="${r.id}" class="${state.selectedRun === r.id ? "sel" : ""}">
      <span class="st ${r.status}" title="${r.status}"></span>
      <span class="rc">${esc(r.collector)}</span>
      <span class="rn">${r.status === "done" ? "+" + r.findings_new : esc(r.status)}</span>
      <span class="rt">${esc(r.target || r.command)} · ${ago(r.started)}</span>
    </li>`).join("") : `<li class="muted" style="display:block;cursor:default">No runs yet. Enter a target and run a collector.</li>`;
}

async function selectRun(id) {
  state.selectedRun = id;
  renderRuns();
  $("#console").hidden = false;
  await refreshConsole(true);
}

async function refreshConsole(scroll) {
  const id = state.selectedRun;
  if (!id) return;
  let r;
  try { r = await api(`/api/runs/${id}`); } catch { $("#console").hidden = true; return; }
  const pre = $("#consoleOut");
  const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
  $("#consoleTitle").textContent = `#${r.id} ${r.collector} — ${r.status}${r.status === "done" ? ` (+${r.findings_new} new, ${r.findings_seen} already known)` : ""}`;
  $("#consoleCmd").textContent = r.command;
  pre.textContent = (r.output || "") + (r.error ? `\n[error] ${r.error}` : "") || "(no output yet)";
  $("#consoleCancel").hidden = !(r.status === "running" || r.status === "queued");
  if (scroll || atBottom) pre.scrollTop = pre.scrollHeight;
}

// -------------------------------------------------------------------- paste
async function onPaste(e) {
  e.preventDefault();
  const f = e.target;
  try {
    const res = await api(`/api/cases/${state.caseId}/ingest`, {
      method: "POST", body: { text: f.elements.text.value, tool: f.elements.tool.value, label: f.elements.label.value, target: f.elements.target.value },
    });
    toast(`Extracted: +${res.new} new, ${res.seen} already known`, "good");
    f.elements.text.value = "";
    await Promise.all([loadFindings(), loadRuns()]);
  } catch (err) { toast(err.message, "err"); }
}

// ------------------------------------------------------------------- export
function doExport(fmt) {
  if (!state.caseId) return;
  const q = fmt === "md-all" ? "format=md&all=1" : `format=${fmt}`;
  const a = document.createElement("a");
  a.href = `/api/cases/${state.caseId}/export?${q}`;
  a.download = "";
  document.body.appendChild(a); a.click(); a.remove();
}

async function importCase(file) {
  try {
    const data = JSON.parse(await file.text());
    const c = await api("/api/cases/import", { method: "POST", body: data });
    toast(`Imported "${c.name}"`, "good");
    await loadCases(c.id);
  } catch (err) { toast("Import failed: " + err.message, "err"); }
}

// --------------------------------------------------------------------- init
async function init() {
  state.meta = await api("/api/meta");
  $("#statusFilter").insertAdjacentHTML("beforeend", state.meta.statuses.map((s) => `<option>${s}</option>`).join(""));
  $("#addCategory").innerHTML = state.meta.categories.map((c) => `<option value="${c.id}">${esc(c.label)}</option>`).join("");
  $("#pasteTool").insertAdjacentHTML("beforeend", state.meta.collectors.filter((c) => !c.builtin)
    .map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join("") + '<option value="paste">Other / plain text</option>');
  $("#dbPath").textContent = "Database: " + state.meta.db;
  $("#allowActive").checked = false; // always off when the page loads

  // tabs & header
  $$(".tab").forEach((t) => t.addEventListener("click", () => showTab(t.dataset.tab)));
  document.addEventListener("click", (e) => {
    const g = e.target.closest("[data-goto]");
    if (g) { e.preventDefault(); showTab(g.dataset.goto); }
    if (!e.target.closest(".menu")) $("#exportMenu").hidden = true;
  });
  $("#caseSelect").addEventListener("change", (e) => { state.caseId = +e.target.value; $("#targetInput").dataset.auto = "1"; openCase(); });
  $("#newCaseBtn").addEventListener("click", () => { $("#newCaseForm").reset(); $("#newCaseDialog").showModal(); });
  $("#newCaseDialog").addEventListener("close", async () => {
    if ($("#newCaseDialog").returnValue !== "ok") return;
    try { await createCase($("#newCaseForm")); } catch (err) { toast(err.message, "err"); }
  });
  $("#welcomeForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try { await createCase(e.target); } catch (err) { toast(err.message, "err"); }
  });
  $("#exportBtn").addEventListener("click", () => ($("#exportMenu").hidden = !$("#exportMenu").hidden));
  $("#exportMenu").addEventListener("click", (e) => {
    const a = e.target.closest("a");
    if (!a) return;
    $("#exportMenu").hidden = true;
    if (a.id === "importCaseLink") return $("#importFile").click();
    doExport(a.dataset.fmt);
  });
  $("#importFile").addEventListener("change", (e) => { if (e.target.files[0]) importCase(e.target.files[0]); e.target.value = ""; });

  // findings
  $("#groups").addEventListener("click", onFindingsClick);
  $("#groups").addEventListener("change", onFindingsChange);
  ["#search", "#statusFilter", "#starOnly", "#showOos"].forEach((s) => $(s).addEventListener("input", renderFindings));
  $("#chips").addEventListener("click", (e) => {
    const c = e.target.closest("[data-filter]");
    if (!c) return;
    const id = c.dataset.filter;
    if (!id) state.activeCats.clear();
    else if (state.activeCats.has(id)) state.activeCats.delete(id);
    else { state.activeCats.add(id); state.collapsed.delete(id); }
    store.set("filters:" + state.caseId, [...state.activeCats]);
    renderFindings();
  });
  $("#collapseAll").addEventListener("click", () => {
    const all = state.meta.categories.map((c) => c.id);
    const anyOpen = all.some((id) => !state.collapsed.has(id));
    state.collapsed = new Set(anyOpen ? all : []);
    $("#collapseAll").textContent = anyOpen ? "Expand all" : "Collapse all";
    renderFindings();
  });
  $("#addFindingBtn").addEventListener("click", () => { $("#addFindingForm").hidden = false; $("#addFindingForm").elements.value.focus(); });
  $("#cancelAdd").addEventListener("click", () => ($("#addFindingForm").hidden = true));
  $("#addFindingForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await api(`/api/cases/${state.caseId}/findings`, { method: "POST", body: { category: f.elements.category.value, value: f.elements.value.value, detail: f.elements.detail.value } });
      f.elements.value.value = ""; f.elements.detail.value = "";
      await Promise.all([loadFindings(), loadRuns()]);
    } catch (err) { toast(err.message, "err"); }
  });

  // collectors
  let tt;
  $("#targetInput").addEventListener("input", () => { $("#targetInput").dataset.auto = "0"; clearTimeout(tt); tt = setTimeout(onTarget, 200); });
  $("#targetInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !$("#runAllBtn").disabled) $("#runAllBtn").click(); });
  $("#allowActive").addEventListener("change", renderCollectors);
  $("#runAllBtn").addEventListener("click", () => startRuns(runnable().map((c) => c.id)));
  $("#collectorGrid").addEventListener("click", (e) => {
    const b = e.target.closest("[data-run]");
    if (!b) return;
    const col = state.meta.collectors.find((c) => c.id === b.dataset.run);
    if (col.active && !confirm(`${col.name} is ACTIVE — it sends traffic directly to the target.\nOnly continue if you're authorized to test it.`)) return;
    startRuns([b.dataset.run]);
  });
  $("#pasteForm").addEventListener("submit", onPaste);
  $("#pasteFile").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (file) $("#pasteForm").elements.text.value = await file.text();
    e.target.value = "";
  });
  $("#runList").addEventListener("click", (e) => { const li = e.target.closest("[data-run]"); if (li) selectRun(+li.dataset.run); });
  $("#consoleClose").addEventListener("click", () => { state.selectedRun = null; $("#console").hidden = true; renderRuns(); });
  $("#consoleCancel").addEventListener("click", async () => { await api(`/api/runs/${state.selectedRun}/cancel`, { method: "POST" }); loadRuns(); });
  $("#consoleDelete").addEventListener("click", async () => {
    if (!confirm("Delete this run and its raw output? Findings only it discovered (and that you haven't starred or annotated) are removed too.")) return;
    await api(`/api/runs/${state.selectedRun}`, { method: "DELETE" });
    state.selectedRun = null; $("#console").hidden = true;
    await Promise.all([loadRuns(), loadFindings()]);
  });

  // case form
  const saveCase = async (quiet) => {
    const f = $("#caseForm");
    try {
      await api(`/api/cases/${state.caseId}`, { method: "PATCH", body: { name: f.elements.name.value, target: f.elements.target.value, scope: f.elements.scope.value, notes: f.elements.notes.value } });
      $("#caseSaved").textContent = "Saved " + new Date().toLocaleTimeString();
      if (!quiet) { toast("Case saved", "good"); await loadCases(state.caseId); }
    } catch (err) { toast(err.message, "err"); }
  };
  $("#caseForm").addEventListener("submit", (e) => { e.preventDefault(); saveCase(false); });
  let nt;
  $("#caseForm").elements.notes.addEventListener("input", () => { clearTimeout(nt); nt = setTimeout(() => saveCase(true), 800); });
  $("#deleteCase").addEventListener("click", async () => {
    const c = currentCase();
    if (prompt(`This permanently deletes "${c.name}" with all runs and findings.\nType the case name to confirm:`) !== c.name) return;
    await api(`/api/cases/${c.id}`, { method: "DELETE" });
    toast("Case deleted");
    state.caseId = null;
    await loadCases();
  });

  await loadCases();
}

init().catch((err) => toast("Failed to load: " + err.message, "err"));
