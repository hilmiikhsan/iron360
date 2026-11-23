/* Iron360 SPA — vanilla JS, self-hosted (strict CSP compatible). */
"use strict";

const State = {
  token: localStorage.getItem("iron360_token") || null,
  user: null,
  targets: [],
  currentTargetId: Number(localStorage.getItem("iron360_target")) || null,
  findings: [],
  status: null,
  view: "dashboard",
  scan: null,      // active scan object
  ws: null,
  activeMode: "pentest",  // "va" or "pentest"
};

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg, type = "info") {
  const icons = { info: "ℹ", success: "✓", error: "✗", warn: "⚠" };
  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  t.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span><span>${esc(msg)}</span>`;
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add("toast-show"));
  setTimeout(() => { t.classList.remove("toast-show"); setTimeout(() => t.remove(), 300); }, 2800);
}

function showDialog(opts) {
  return new Promise((resolve) => {
    const bg = document.createElement("div");
    bg.className = "dialog-bg";
    const hasInput = opts.type === "prompt";
    const isDanger = opts.danger;
    bg.innerHTML = `
      <div class="dialog">
        <div class="dialog-icon-wrap ${isDanger ? "dialog-danger" : "dialog-normal"}">
          ${isDanger ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
            : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4m0 4h.01"/><circle cx="12" cy="12" r="10"/></svg>'}
        </div>
        <h3 class="dialog-title">${esc(opts.title || "Confirm")}</h3>
        <p class="dialog-msg">${esc(opts.message || "")}</p>
        ${hasInput ? `<input class="dialog-input" id="dlgInput" placeholder="${esc(opts.placeholder || "")}" value="${esc(opts.defaultValue || "")}" />` : ""}
        <div class="dialog-actions">
          <button class="dialog-btn dialog-cancel" id="dlgCancel">${esc(opts.cancelText || "Cancel")}</button>
          <button class="dialog-btn ${isDanger ? "dialog-btn-danger" : "dialog-btn-primary"}" id="dlgOk">${esc(opts.okText || "OK")}</button>
        </div>
      </div>`;
    document.body.appendChild(bg);
    requestAnimationFrame(() => bg.classList.add("dialog-show"));
    const inp = bg.querySelector("#dlgInput");
    if (inp) setTimeout(() => inp.focus(), 100);
    const close = (val) => {
      bg.classList.remove("dialog-show");
      setTimeout(() => bg.remove(), 250);
      resolve(val);
    };
    bg.querySelector("#dlgCancel").addEventListener("click", () => close(hasInput ? null : false));
    bg.querySelector("#dlgOk").addEventListener("click", () => close(hasInput ? (inp ? inp.value : "") : true));
    bg.addEventListener("click", (e) => { if (e.target === bg) close(hasInput ? null : false); });
    if (inp) inp.addEventListener("keydown", (e) => { if (e.key === "Enter") close(inp.value); });
    bg.addEventListener("keydown", (e) => { if (e.key === "Escape") close(hasInput ? null : false); });
  });
}

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (State.token) headers["Authorization"] = "Bearer " + State.token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401) { logout(true); throw new Error("Session expired"); }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

function logout(force) {
  if (force) {
    _doLogout();
    return;
  }
  showDialog({ title: "Logout", message: "Keluar dari Iron360? Session aktif akan diakhiri.", okText: "Logout", cancelText: "Cancel", danger: true }).then((yes) => {
    if (yes) _doLogout();
  });
}
function _doLogout() {
  if (State.token) {
    fetch("/api/auth/logout", { method: "POST", headers: { "Authorization": "Bearer " + State.token, "Content-Type": "application/json" } }).catch(() => {});
  }
  State.token = null; State.user = null;
  localStorage.removeItem("iron360_token");
  if (State.ws) { try { State.ws.close(); } catch (_) {} State.ws = null; }
  renderLogin();
}

/* ----------------------------- Login ----------------------------- */
function renderLogin() {
  document.getElementById("app").innerHTML = `
    <div class="login-wrap">
      <form class="login-card" id="loginForm">
        <div class="brand-mark"><div class="logo">I</div><h1>Iron360</h1></div>
        <div class="login-sub">VAPT AI Console &middot; RSA Offensive Security</div>
        <label class="field"><span>Username</span><input id="u" autocomplete="username" autofocus /></label>
        <label class="field"><span>Password</span><input id="p" type="password" autocomplete="current-password" /></label>
        <button class="btn" type="submit">Sign in</button>
        <div class="err" id="loginErr"></div>
      </form>
    </div>`;
  $("#loginForm").addEventListener("submit", doLogin);
}

async function doLogin(e) {
  e.preventDefault();
  const body = new URLSearchParams({ username: $("#u").value, password: $("#p").value });
  try {
    const res = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
    if (!res.ok) { $("#loginErr").textContent = (await res.json()).detail || "Login failed"; return; }
    const data = await res.json();
    State.token = data.access_token;
    State.user = { username: data.username, role: data.role };
    localStorage.setItem("iron360_token", State.token);
    await boot();
  } catch (err) { $("#loginErr").textContent = err.message; }
}

/* ----------------------------- Boot ----------------------------- */
async function boot() {
  try {
    State.user = await api("/api/auth/me");
  } catch (_) { renderLogin(); return; }
  await Promise.all([loadTargets(), loadStatus()]);
  renderShell();
  setView(State.view);
}

async function loadTargets() {
  State.targets = await api("/api/targets");
  if (!State.currentTargetId && State.targets.length) State.currentTargetId = State.targets[0].id;
}
async function loadStatus() { try { State.status = await api("/api/status"); } catch (_) {} }

function currentTarget() { return State.targets.find((t) => t.id === State.currentTargetId) || null; }

/* ----------------------------- Shell ----------------------------- */
const NAV = [
  { sep: "VAPT AI" },
  { k: "dashboard", ico: "◆", label: "Dashboard" },
  { k: "pentest", ico: "⚡", label: "AI Pentest" },
  { k: "findings", ico: "⚑", label: "Findings" },
  { k: "reports", ico: "▦", label: "Reports" },
  { sep: "Iron360 Modules" },
  { k: "domain-health", ico: "✚", label: "Domain Health" },
  { k: "threat-intel", ico: "◈", label: "Threat Intel" },
  { k: "dark-web", ico: "☍", label: "Dark Web" },
  { k: "siem-log", ico: "▥", label: "SIEM Log" },
  { sep: "Workspace" },
  { k: "targets", ico: "◎", label: "Targets & Scope" },
  { k: "knowledge", ico: "✦", label: "Knowledge Base" },
  { k: "schedules", ico: "⏱", label: "Scheduled Scans" },
  { k: "trending", ico: "▧", label: "Vuln Trending" },
  { k: "audit", ico: "▤", label: "Audit Log" },
  { k: "settings", ico: "⚙", label: "Settings" },
];

function renderShell() {
  const nav = NAV.map((n) => n.sep
    ? `<div class="nav-sep">${n.sep}</div>`
    : `<a class="nav-item" data-nav="${n.k}"><span class="ico">${n.ico}</span>${n.label}</a>`).join("");

  document.getElementById("app").innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand"><div class="logo">I</div><div><b>Iron360</b><small>OFFENSIVE CONSOLE</small></div></div>
        ${nav}
        <div class="spacer"></div>
        <div class="userbox">
          <span class="who">${esc(State.user.username)} &middot; ${esc(State.user.role)}</span>
          <button class="btn ghost sm" id="logoutBtn">Exit</button>
        </div>
      </aside>
      <div class="main">
        <div class="topbar">
          <div class="target-switch" id="targetSwitch"></div>
          <h2 id="viewTitle"></h2>
          <div class="spacer"></div>
          <span class="pill ${State.status && State.status.ai_engine === "live" ? "live" : "demo"}" id="enginePill"></span>
        </div>
        <div class="content" id="content"></div>
      </div>
    </div>
    <div class="drawer-bg" id="drawerBg"></div>
    <div class="drawer" id="drawer"></div>
    <div class="modal-bg" id="modalBg"></div>`;

  $("#logoutBtn").addEventListener("click", () => logout());
  $("#drawerBg").addEventListener("click", closeDrawer);
  document.querySelectorAll("[data-nav]").forEach((a) => a.addEventListener("click", () => setView(a.dataset.nav)));
  renderTargetSwitch();
  renderEnginePill();
}

function renderEnginePill() {
  const live = State.status && State.status.ai_engine === "live";
  const pill = $("#enginePill");
  if (!pill) return;
  pill.className = "pill " + (live ? "live" : "demo");
  pill.textContent = live ? "● AI LIVE" : "● SIMULATION";
}

/* ---------------- Target switcher (Ironcloud-style) ---------------- */
function renderTargetSwitch() {
  const t = currentTarget();
  const box = $("#targetSwitch");
  const label = t ? `<b>${esc(t.value)}</b><small>${esc(t.label)}${t.engagement ? " · " + esc(t.engagement) : ""}</small>`
                  : `<b>No target</b><small>add one to begin</small>`;
  const dotColor = t ? (t.authorized ? "var(--ok)" : "var(--warn)") : "var(--muted)";
  box.innerHTML = `
    <button class="target-btn" id="targetBtn">
      <span class="dot" style="background:${dotColor};box-shadow:0 0 8px ${dotColor}"></span>
      <span class="lbl">${label}</span>
      <span class="chev">▾</span>
    </button>
    <div class="target-menu" id="targetMenu" style="display:none"></div>`;
  $("#targetBtn").addEventListener("click", toggleTargetMenu);
}

function toggleTargetMenu() {
  const menu = $("#targetMenu");
  if (menu.style.display === "none") {
    menu.innerHTML = State.targets.map((t) => `
      <div class="opt" data-pick="${t.id}">
        <span class="dot" style="width:8px;height:8px;border-radius:50%;background:${t.authorized ? "var(--ok)" : "var(--warn)"}"></span>
        <div><b>${esc(t.value)}</b><small>${esc(t.label)}${t.engagement ? " · " + esc(t.engagement) : ""}</small></div>
        <span class="pill ${t.authorized ? "confirmed" : "needs_review"}">${t.authorized ? "authorized" : "unauthorized"}</span>
      </div>`).join("") + `
      <div class="add"><button class="btn secondary" id="addTargetQuick">+ Add target / scope</button></div>`;
    menu.style.display = "block";
    menu.querySelectorAll("[data-pick]").forEach((o) => o.addEventListener("click", () => {
      State.currentTargetId = Number(o.dataset.pick);
      localStorage.setItem("iron360_target", State.currentTargetId);
      menu.style.display = "none";
      renderTargetSwitch(); setView(State.view);
    }));
    $("#addTargetQuick").addEventListener("click", () => { menu.style.display = "none"; openTargetModal(); });
  } else { menu.style.display = "none"; }
}

/* ----------------------------- Router ----------------------------- */
const TITLES = { dashboard: "Dashboard", pentest: "AI Pentest Console", findings: "Findings", reports: "Reports", "domain-health": "Domain Health", "threat-intel": "Threat Intelligence", "dark-web": "Dark Web Crawling", "siem-log": "SIEM Log", targets: "Targets & Scope", knowledge: "Knowledge Base", schedules: "Scheduled Scans", trending: "Vulnerability Trending", audit: "Audit Log", settings: "Settings" };

function setView(view) {
  State.view = view;
  // Don't close WebSocket on navigation — let scans run in background.
  // WS is only closed when explicitly starting a new scan or switching modes.
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === view));
  $("#viewTitle").textContent = TITLES[view] || "";
  const views = {
    dashboard: viewDashboard, pentest: viewPentest, findings: viewFindings, reports: viewReports,
    "domain-health": viewDomainHealth, "threat-intel": () => viewModule("threat-intel"),
    "dark-web": () => viewModule("dark-web"), "siem-log": () => viewModule("siem-log"),
    targets: viewTargets, knowledge: viewKnowledge, schedules: viewSchedules, trending: viewTrending, audit: viewAudit, settings: viewSettings,
  };
  (views[view] || viewDashboard)();
}

/* ----------------------------- Dashboard ----------------------------- */
async function viewDashboard() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `<div class="muted">Loading…</div>`;
  const [findings, scans] = await Promise.all([
    api("/api/findings?target_id=" + t.id),
    api("/api/scans?target_id=" + t.id),
  ]);
  State.findings = findings;
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => sev[f.severity] = (sev[f.severity] || 0) + 1);
  const confirmed = findings.filter((f) => f.status === "confirmed").length;
  const needsReview = findings.filter((f) => f.status === "needs_review" || f.status === "likely").length;

  c.innerHTML = `
    <div class="grid stats">
      ${statCard("Target", t.value, t.authorized ? "authorized" : "⚠ unauthorized", t.authorized ? "var(--ok)" : "var(--warn)")}
      ${statCard("Findings", findings.length, confirmed + " confirmed", "var(--confirmed)")}
      ${statCard("Needs review", needsReview, "human validation gate", "var(--muted)")}
      ${statCard("Scans run", scans.length, "last: " + (scans[0] ? fmtTime(scans[0].started_at) : "—"), "var(--muted)")}
    </div>
    <div class="section-title"><h3>Severity breakdown</h3></div>
    <div class="card">${sevBars(sev)}</div>
    <div class="section-title"><h3>Recent scans</h3><div class="spacer"></div><button class="btn sm" id="goPentest">Start AI Pentest →</button></div>
    <div class="card">${scansTable(scans)}</div>`;
  $("#goPentest").addEventListener("click", () => setView("pentest"));
  c.querySelectorAll("[data-diff]").forEach((b) => b.addEventListener("click", () => showScanDiff(Number(b.dataset.diff))));
}

function statCard(k, v, trend, color) {
  return `<div class="card stat"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div><div class="trend" style="color:${color}">${esc(trend)}</div></div>`;
}
function sevBars(sev) {
  const total = Object.values(sev).reduce((a, b) => a + b, 0) || 1;
  return ["critical", "high", "medium", "low", "info"].map((s) => `
    <div class="row" style="margin:7px 0">
      <span class="pill ${s}" style="min-width:80px;justify-content:center">${s}</span>
      <div style="flex:1;height:8px;background:var(--bg);border-radius:6px;overflow:hidden">
        <div style="height:100%;width:${(sev[s] / total) * 100}%;background:var(--${s})"></div>
      </div>
      <b style="width:28px;text-align:right">${sev[s]}</b>
    </div>`).join("");
}
function scansTable(scans) {
  if (!scans.length) return `<div class="empty">No scans yet. Start an AI pentest to populate findings.</div>`;
  return `<table><thead><tr><th>ID</th><th>Mode</th><th>Profile</th><th>Autonomy</th><th>Status</th><th>Started</th><th>Summary</th><th></th></tr></thead><tbody>
    ${scans.map((s) => `<tr><td>#${s.id}</td><td>${s.mode.toUpperCase()}</td>
      <td><span class="tag">${esc((s.profile || "full"))}</span></td><td>${s.autonomy}</td>
      <td><span class="pill ${s.status === "done" ? "confirmed" : s.status === "failed" ? "critical" : "needs_review"}">${s.status}</span></td>
      <td class="muted">${fmtTime(s.started_at)}</td><td class="muted">${esc((s.summary || "").slice(0, 70))}</td>
      <td>${["done", "stopped"].includes(s.status) ? `<button class="btn ghost sm" data-diff="${s.id}">Compare</button>` : ""}</td></tr>`).join("")}
  </tbody></table>`;
}

async function showScanDiff(scanId) {
  const d = $("#drawer");
  d.innerHTML = `<div class="muted">Comparing scan #${scanId} with previous…</div>`;
  $("#drawerBg").classList.add("open"); d.classList.add("open");
  let diff;
  try { diff = await api(`/api/scans/${scanId}/diff`); }
  catch (e) { d.innerHTML = `<div class="empty">Diff failed: ${esc(e.message)}</div>`; return; }
  const sevPill = (f) => `<span class="pill ${f.severity}">${f.severity}</span>`;
  const list = (arr, prefix) => arr.length
    ? arr.map((f) => `<div class="row" style="margin:5px 0;gap:8px">${sevPill(f)}<b>${esc(f.title)}</b>
        ${f.cve ? `<span class="tag" style="color:var(--accent)">${esc(f.cve)}</span>` : ""}
        <small class="muted">${esc(f.affected || "")}</small>
        ${prefix === "persistent" && f.baseline_severity && f.baseline_severity !== f.severity
          ? `<small style="color:var(--warn)">was ${esc(f.baseline_severity)}</small>` : ""}</div>`).join("")
    : `<div class="muted" style="padding:4px 0">none</div>`;
  const base = diff.baseline_scan ? `scan #${diff.baseline_scan}` : "no earlier scan";
  d.innerHTML = `
    <div class="row spread"><h2 style="margin:0">Scan diff</h2><button class="btn ghost sm" id="closeDrawer">Close</button></div>
    <div class="muted">#${diff.current_scan} vs ${esc(base)}${diff.note ? " · " + esc(diff.note) : ""}</div>
    <div class="section-title"><h3 style="color:var(--critical)">🆕 New (${diff.new.length})</h3></div>${list(diff.new, "new")}
    <div class="section-title"><h3 style="color:var(--ok)">✓ Fixed / gone (${diff.fixed.length})</h3></div>${list(diff.fixed, "fixed")}
    <div class="section-title"><h3 class="muted">↻ Persistent (${diff.persistent.length})</h3></div>${list(diff.persistent, "persistent")}`;
  $("#closeDrawer").addEventListener("click", closeDrawer);
}

/* ----------------------------- Targets & Scope ----------------------------- */
async function viewTargets() {
  const c = $("#content");
  c.innerHTML = `
    <div class="section-title"><h3>Target workspaces</h3><div class="spacer"></div>
      <button class="btn sm" id="addTarget">+ Add target</button></div>
    <div class="card" id="targetsTable"></div>
    <div class="hint">Each target is an isolated workspace — one domain/IP, one focused dataset. A scan only ever runs
      against hosts inside a target's authorized scope; the executor hard-rejects anything out of scope.</div>`;
  $("#addTarget").addEventListener("click", openTargetModal);
  renderTargetsTable();
}

function renderTargetsTable() {
  const el = $("#targetsTable");
  if (!State.targets.length) { el.innerHTML = `<div class="empty">No targets yet. Add one to begin.</div>`; return; }
  el.innerHTML = `<table><thead><tr><th>Target</th><th>Engagement</th><th>Scope</th><th>Authorization</th><th></th></tr></thead><tbody>
    ${State.targets.map((t) => `<tr>
      <td><b>${esc(t.value)}</b><br><small class="muted">${esc(t.label)} · ${t.kind}</small></td>
      <td>${esc(t.engagement || "—")}</td>
      <td><small class="muted">${[t.value].concat(t.scope_extra || []).map(esc).join("<br>")}</small></td>
      <td>${t.authorized
        ? `<span class="pill confirmed">authorized</span><br><small class="muted">${esc(t.authorization_ref || "")}</small>`
        : `<span class="pill needs_review">unauthorized</span>`}
        ${t.auth_type && t.auth_type !== "none" ? `<br><span class="pill low">🔑 credentialed ${esc(t.auth_user || "")}</span>` : ""}</td>
      <td class="row">
        <button class="btn ghost sm" data-auth="${t.id}">${t.authorized ? "Revoke" : "Authorize"}</button>
        <button class="btn danger sm" data-del="${t.id}">Delete</button>
      </td></tr>`).join("")}
  </tbody></table>`;
  el.querySelectorAll("[data-auth]").forEach((b) => b.addEventListener("click", () => toggleAuth(Number(b.dataset.auth))));
  el.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", () => delTarget(Number(b.dataset.del))));
}

async function toggleAuth(id) {
  const t = State.targets.find((x) => x.id === id);
  if (!t.authorized) {
    const ref = await showDialog({ type: "prompt", title: "Authorization Reference", message: "Masukkan referensi otorisasi (SOW / PKS / NDA id) untuk menandai target in-scope.", placeholder: "SOW-2026-014", okText: "Authorize" });
    if (ref === null) return;
    await api(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify({ authorized: true, authorization_ref: ref }) });
  } else {
    await api(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify({ authorized: false }) });
  }
  await loadTargets(); renderTargetsTable(); renderTargetSwitch(); toast("Authorization updated", "success");
}
async function delTarget(id) {
  const yes = await showDialog({ title: "Delete Target", message: "Hapus target ini beserta semua scan dan findings yang terkait? Aksi ini tidak dapat dibatalkan.", okText: "Delete", cancelText: "Cancel", danger: true });
  if (!yes) return;
  await api(`/api/targets/${id}`, { method: "DELETE" });
  if (State.currentTargetId === id) State.currentTargetId = null;
  await loadTargets(); renderTargetsTable(); renderTargetSwitch(); toast("Target deleted", "success");
}

function openTargetModal() {
  const m = $("#modalBg");
  m.innerHTML = `<div class="modal"><h3>Add target workspace</h3>
    <label class="field"><span>Label</span><input id="mLabel" placeholder="Indorama Web App" /></label>
    <div class="inline-2">
      <label class="field"><span>Domain / IP</span><input id="mValue" placeholder="example.com" /></label>
      <label class="field"><span>Kind</span><select id="mKind"><option value="domain">domain</option><option value="ip">ip</option><option value="cidr">cidr</option></select></label>
    </div>
    <label class="field"><span>Engagement / client</span><input id="mEng" placeholder="Indorama Ventures" /></label>
    <label class="field"><span>Extra in-scope hosts (one per line)</span><textarea id="mScope" rows="3" placeholder="api.example.com&#10;10.0.0.0/24"></textarea></label>
    <label class="field"><span>Authorization reference (SOW/PKS/NDA) — leave blank to add as unauthorized</span><input id="mRef" placeholder="SOW-2026-014" /></label>
    <div class="section-title" style="margin:6px 0 10px"><h3 style="font-size:12px;color:var(--muted)">Credentialed VA (optional — like Nessus)</h3></div>
    <div class="inline-2">
      <label class="field"><span>SSH auth</span><select id="mAuthType"><option value="none">none</option><option value="ssh_password">password</option><option value="ssh_key">private key</option></select></label>
      <label class="field"><span>SSH port</span><input id="mAuthPort" value="22" /></label>
    </div>
    <label class="field"><span>SSH user</span><input id="mAuthUser" placeholder="root / ubuntu" /></label>
    <label class="field"><span>SSH password or private key (stored only in local DB)</span><textarea id="mAuthSecret" rows="2" placeholder="password, or paste private key"></textarea></label>
    <div class="row spread" style="margin-top:10px">
      <button class="btn ghost" id="mCancel">Cancel</button>
      <button class="btn sm" id="mSave">Create</button>
    </div>
    <div class="err" id="mErr"></div></div>`;
  m.classList.add("open");
  $("#mCancel").addEventListener("click", () => m.classList.remove("open"));
  $("#mSave").addEventListener("click", saveTarget);
}

async function saveTarget() {
  const ref = $("#mRef").value.trim();
  const body = {
    label: $("#mLabel").value.trim() || $("#mValue").value.trim(),
    value: $("#mValue").value.trim(),
    kind: $("#mKind").value,
    engagement: $("#mEng").value.trim(),
    scope_extra: $("#mScope").value.split("\n").map((s) => s.trim()).filter(Boolean),
    authorized: !!ref,
    authorization_ref: ref,
    auth_type: $("#mAuthType").value,
    auth_user: $("#mAuthUser").value.trim(),
    auth_secret: $("#mAuthSecret").value,
    auth_port: parseInt($("#mAuthPort").value, 10) || 22,
  };
  if (!body.value) { $("#mErr").textContent = "Domain/IP is required"; return; }
  try {
    const t = await api("/api/targets", { method: "POST", body: JSON.stringify(body) });
    $("#modalBg").classList.remove("open");
    State.currentTargetId = t.id;
    localStorage.setItem("iron360_target", t.id);
    await loadTargets(); renderTargetSwitch();
    if (State.view === "targets") renderTargetsTable(); else setView(State.view);
    toast("Target created", "success");
  } catch (e) { $("#mErr").textContent = e.message; }
}

/* ----------------------------- AI Pentest console ----------------------------- */
function viewPentest() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }

  // Mode selector at top
  c.innerHTML = `
    <div class="row" style="margin-bottom:12px;gap:12px;align-items:center">
      <label class="field" style="margin:0"><span style="display:none">Mode</span>
        <div class="seg" id="modeSeg"><button data-mode="va">VA scan</button><button data-mode="pentest" class="on">Pentest</button></div>
      </label>
      ${t.authorized ? "" : `<span class="pill needs_review" style="font-size:12px">Target not authorized</span>`}
    </div>
    <div id="modeContent"></div>`;

  let mode = State.activeMode || "pentest";
  $("#modeSeg").querySelectorAll("button").forEach((b) => {
    b.classList.toggle("on", b.dataset.mode === mode);
    b.addEventListener("click", () => {
      mode = b.dataset.mode;
      $("#modeSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
      renderModeContent(t, mode);
    });
  });
  renderModeContent(t, mode);
}

function renderModeContent(t, mode) {
  const mc = $("#modeContent");
  if (!mc) return;
  // Only close WS if actually switching to a different mode
  if (mode !== State.activeMode && State.ws) { try { State.ws.close(); } catch (_) {} State.ws = null; }
  _currentToolBlock = null;
  State.activeMode = mode;
  if (mode === "va") {
    renderVAMode(t, mc);
  } else {
    renderPentestMode(t, mc);
  }
}

function renderVAMode(t, mc) {
  mc.innerHTML = `
    <div class="console">
      <div class="panel">
        <div class="phead">① Reasoning / Plan</div>
        <div class="pbody" id="timeline"><div class="muted">Idle. Configure and press Start.</div></div>
      </div>
      <div class="panel">
        <div class="phead">② Live Execution <span class="muted" id="execHost">· ${esc(t.value)}</span></div>
        <div class="pbody term" id="terminal"><div class="line muted">No commands executed yet.</div></div>
      </div>
      <div class="panel controls">
        <div class="phead">③ Controls</div>
        <div class="pbody">
          <label class="field"><span>Scan profile</span>
            <select id="profileSel" class="sel">
              <option value="full" selected>Full — deepest coverage</option>
              <option value="quick">Quick — fast triage (high/critical)</option>
              <option value="web">Web — application focus</option>
              <option value="network">Network — ports + NSE</option>
              <option value="compliance">Compliance — credentialed CIS</option>
            </select>
          </label>
          <div class="row" style="margin:14px 0 6px">
            <button class="btn sm" id="startBtn">▶ Start assessment</button>
            <button class="btn ghost sm" id="stopBtn" disabled>■ Stop</button>
          </div>
          <div class="hint">VA mode scans the target domain for vulnerabilities. No subdomain enum — focused on the single target.</div>
        </div>
      </div>
    </div>`;
  $("#startBtn").addEventListener("click", () => startScan(t, "va", "auto", $("#profileSel").value));
  $("#stopBtn").addEventListener("click", stopScan);
  resumeIfRunning(t);
}

function renderPentestMode(t, mc) {
  mc.innerHTML = `
    <div class="agent-console">
      <div class="agent-stream" id="agentStream">
        <div class="agent-welcome">
          <div class="agent-welcome-title">Iron360 Pentest Agent</div>
          <div class="agent-welcome-sub">Target: <b>${esc(t.value)}</b> · Type your instructions below</div>
          <div class="agent-examples">
            <span class="agent-example" data-msg="Enumerate subdomains lalu scan vulnerability">enumerate subdomains + scan vulns</span>
            <span class="agent-example" data-msg="Run nmap full port scan with service detection">nmap full scan</span>
            <span class="agent-example" data-msg="Find SQL injection on all known endpoints">find SQLi</span>
            <span class="agent-example" data-msg="Run nuclei with critical and high severity templates">nuclei critical/high</span>
          </div>
        </div>
      </div>
      <div class="agent-input-bar" id="agentInputBar">
        <div class="agent-status-line" id="agentStatus"></div>
        <div class="agent-input-row">
          <textarea id="chatInput" placeholder="What should I do?" rows="1"></textarea>
          <button class="btn sm" id="chatSendBtn" disabled>↵</button>
          <button class="btn danger sm" id="chatStopBtn" style="display:none">■ Stop</button>
        </div>
      </div>
    </div>`;

  const input = $("#chatInput");
  const sendBtn = $("#chatSendBtn");
  const stopBtn = $("#chatStopBtn");

  // Auto-resize textarea + toggle send button
  input.addEventListener("input", () => {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 120) + "px";
    sendBtn.disabled = !input.value.trim();
  });

  // Example chips
  document.querySelectorAll(".agent-example").forEach((el) => {
    el.addEventListener("click", () => { input.value = el.dataset.msg; input.focus(); input.dispatchEvent(new Event("input")); });
  });

  async function sendMessage() {
    const msg = input.value.trim();
    if (!msg) return;
    if (!t.authorized) { toast("Target not authorized", "warn"); return; }
    input.value = ""; input.style.height = "auto";
    input.disabled = true;
    sendBtn.disabled = true;
    stopBtn.style.display = "";

    // Hide welcome on first message
    const wel = document.querySelector(".agent-welcome");
    if (wel) wel.style.display = "none";

    // Create pentest session if needed
    if (!State.scan || State.scan.status === "done" || State.scan.status === "stopped" || State.scan.status === "failed") {
      try {
        const scan = await api("/api/scans", { method: "POST", body: JSON.stringify({ target_id: t.id, mode: "pentest", autonomy: "auto", profile: "full" }) });
        State.scan = scan;
        try { localStorage.setItem(`iron360_active_scan_${t.id}`, scan.id); } catch (_) {}
        openScanStream(scan.id);
        await new Promise((r) => setTimeout(r, 300));
      } catch (e) { toast(e.message); input.disabled = false; sendBtn.disabled = !input.value.trim(); stopBtn.style.display = "none"; return; }
    }

    try {
      await api(`/api/scans/${State.scan.id}/chat`, { method: "POST", body: JSON.stringify({ message: msg }) });
    } catch (e) {
      toast(e.message);
      input.disabled = false; sendBtn.disabled = !input.value.trim();
    }
  }

  sendBtn.addEventListener("click", sendMessage);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  stopBtn.addEventListener("click", stopScan);
  resumePentestIfActive(t);
}

async function resumePentestIfActive(t) {
  let savedId;
  try { savedId = localStorage.getItem(`iron360_active_scan_${t.id}`); } catch (_) {}

  if (!savedId) {
    try {
      const scans = await api(`/api/scans?target_id=${t.id}`);
      const lastPT = scans.find((s) => s.mode === "pentest");
      if (lastPT) savedId = lastPT.id;
    } catch (_) {}
  }
  if (!savedId) return;

  try {
    const scan = await api(`/api/scans/${savedId}`);
    if (scan.mode !== "pentest") return;

    if (scan.status === "chat_active" || scan.status === "running" || scan.status === "queued") {
      State.scan = scan;
      const stopBtn = $("#chatStopBtn");
      if (stopBtn) stopBtn.style.display = "";
      const wel = document.querySelector(".agent-welcome");
      if (wel) wel.style.display = "none";
      agentAppend("system", "Reconnected to session #" + scan.id);
      openScanStream(scan.id);
    } else if (scan.status === "done" || scan.status === "stopped" || scan.status === "failed") {
      State.scan = scan;
      const wel = document.querySelector(".agent-welcome");
      if (wel) wel.style.display = "none";
      _replayPentestTimeline(scan);
    }
  } catch (_) {}
}

function _replayPentestTimeline(scan) {
  if (!scan.timeline || !scan.timeline.length) return;
  // During replay, limit log lines per tool to avoid DOM overload
  let logCount = 0;
  const LOG_LIMIT = 30;
  for (const e of scan.timeline) {
    switch (e.type) {
      case "note": agentAppend("system", e.text); break;
      case "chat_user": agentAppend("user", e.text); break;
      case "agent_text": agentAppend("text", e.text); break;
      case "agent_thinking_text":
        if (e.text && e.text.length > 0) agentAppend("thinking_text", e.text.length > 300 ? e.text.slice(0, 300) + "…" : e.text);
        break;
      case "agent_tool_start":
        logCount = 0;
        agentAppend("tool_start", "", { tool: e.tool, host: e.host });
        break;
      case "exec":
        if (logCount > LOG_LIMIT && _currentToolBlock) {
          agentAppend("tool_line", `… ${logCount - LOG_LIMIT} more lines (collapsed)`);
        }
        agentAppend("tool_done", "", { ok: e.ok, exit_code: e.exit_code, duration_s: e.duration_s, denied_reason: e.denied_reason });
        logCount = 0;
        break;
      case "log":
        logCount++;
        if (logCount <= LOG_LIMIT) agentAppend("tool_line", e.line || e.text || "");
        break;
      case "finding":
        if (e.finding) agentAppend("finding", e.finding.title, { severity: e.finding.severity, title: e.finding.title });
        break;
      case "reasoning": agentAppend("system", e.text); break;
      case "finish": agentAppend("system", e.text); break;
      case "agent_status": break;
      case "agent_thinking": break;
      case "error": agentAppend("error", e.text); break;
    }
  }
  // Scroll to bottom after replay
  const stream = $("#agentStream");
  if (stream) stream.scrollTop = stream.scrollHeight;
}

// ---- Agent stream rendering (Claude-Code style) ----
let _currentToolBlock = null;

function agentAppend(type, content, meta) {
  const stream = $("#agentStream");
  if (!stream) return null;
  const el = document.createElement("div");
  el.className = "ag-block ag-" + type;

  if (type === "user") {
    el.innerHTML = `<span class="ag-prompt">❯</span> <span class="ag-user-text">${esc(content)}</span>`;
  } else if (type === "thinking") {
    el.innerHTML = `<span class="ag-thinking-indicator">⟳ Thinking…</span>`;
    el.id = "agThinking";
  } else if (type === "thinking_text") {
    el.innerHTML = `<span class="ag-thinking-text">${esc(content).replace(/\n/g, "<br>")}</span>`;
  } else if (type === "text") {
    el.innerHTML = formatAgentMarkdown(content);
  } else if (type === "tool_start") {
    const toolName = meta?.tool || "tool";
    const uid = "agTool_" + Date.now();
    el.className = "ag-block ag-tool";
    el.innerHTML = `
      <div class="ag-tool-head" aria-expanded="false" data-toggle="${uid}">
        <span class="ag-tool-icon running">●</span>
        <span class="ag-tool-name">${esc(toolName)}</span>
        <span class="ag-tool-host">${esc(meta?.host || "")}</span>
        <span class="ag-tool-meta"><span class="ag-tool-status">running…</span><span class="ag-tool-chevron">▶</span></span>
      </div>
      <div class="ag-tool-body collapsed" id="${uid}">
        <div class="ag-tool-output"></div>
      </div>`;
    const head = el.querySelector(".ag-tool-head");
    const body = el.querySelector(".ag-tool-body");
    head.addEventListener("click", () => {
      const exp = head.getAttribute("aria-expanded") === "true";
      head.setAttribute("aria-expanded", !exp);
      body.classList.toggle("collapsed", exp);
    });
    _currentToolBlock = el.querySelector(".ag-tool-output");
  } else if (type === "tool_line") {
    if (_currentToolBlock) {
      const line = document.createElement("div");
      line.className = "ag-tool-line";
      line.textContent = content;
      _currentToolBlock.appendChild(line);
      _currentToolBlock.scrollTop = _currentToolBlock.scrollHeight;
      // Auto-expand when output starts flowing
      const body = _currentToolBlock.closest(".ag-tool-body");
      if (body && body.classList.contains("collapsed")) {
        body.classList.remove("collapsed");
        const head = body.previousElementSibling;
        if (head) head.setAttribute("aria-expanded", "true");
      }
      stream.scrollTop = stream.scrollHeight;
      return null;
    }
    return null;
  } else if (type === "tool_done") {
    if (_currentToolBlock) {
      const parent = _currentToolBlock.closest(".ag-tool");
      if (parent) {
        const icon = parent.querySelector(".ag-tool-icon");
        const statusEl = parent.querySelector(".ag-tool-status");
        if (meta?.ok) {
          if (icon) { icon.textContent = "✓"; icon.className = "ag-tool-icon ok"; }
          if (statusEl) statusEl.textContent = `exit ${meta.exit_code} · ${meta.duration_s}s`;
        } else {
          if (icon) { icon.textContent = "✗"; icon.className = "ag-tool-icon fail"; }
          if (statusEl) { statusEl.textContent = meta.denied_reason || "failed"; statusEl.style.color = "var(--critical)"; }
        }
        // Collapse successful tool output after completion
        const body = parent.querySelector(".ag-tool-body");
        const head = parent.querySelector(".ag-tool-head");
        if (body && meta?.ok) {
          body.classList.add("collapsed");
          if (head) head.setAttribute("aria-expanded", "false");
        }
      }
    }
    _currentToolBlock = null;
    stream.scrollTop = stream.scrollHeight;
    return null;
  } else if (type === "finding") {
    el.className = "ag-block ag-finding";
    el.innerHTML = `<span class="ag-finding-sev ag-sev-${esc(meta?.severity || "info")}">${esc((meta?.severity || "INFO").toUpperCase())}</span> ${esc(meta?.title || content)}`;
  } else if (type === "system") {
    el.innerHTML = `<span class="ag-system">${esc(content)}</span>`;
  } else if (type === "error") {
    el.innerHTML = `<span class="ag-error">✗ ${esc(content)}</span>`;
  }

  stream.appendChild(el);
  stream.scrollTop = stream.scrollHeight;
  return el;
}

function formatAgentMarkdown(text) {
  let s = esc(text);
  // Code blocks
  s = s.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre class="ag-codeblock"><code>$2</code></pre>');
  // Headers
  s = s.replace(/^### (.+)$/gm, '<div class="ag-h3">$1</div>');
  s = s.replace(/^## (.+)$/gm, '<div class="ag-h2">$1</div>');
  // Bold, inline code
  s = s.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>');
  s = s.replace(/`(.*?)`/g, '<code class="ag-inline-code">$1</code>');
  // Lists
  s = s.replace(/^- (.+)$/gm, '<div class="ag-li">· $1</div>');
  // Newlines
  s = s.replace(/\n/g, '<br>');
  return s;
}

async function startScan(t, mode, autonomy, profile) {
  if (!t.authorized) { toast("Target not authorized", "warn"); return; }
  if (State.scanning) { toast("Scan already running", "warn"); return; }
  $("#timeline").innerHTML = ""; $("#terminal").innerHTML = "";
  $("#startBtn").disabled = true; $("#stopBtn").disabled = false;
  State.scanning = true;
  try {
    const scan = await api("/api/scans", { method: "POST", body: JSON.stringify({ target_id: t.id, mode, autonomy, profile: profile || "full" }) });
    State.scan = scan;
    // Persist so browser refresh can reconnect.
    try { localStorage.setItem(`iron360_active_scan_${t.id}`, scan.id); } catch (_) {}
    openScanStream(scan.id);
  } catch (e) { toast(e.message); $("#startBtn").disabled = false; $("#stopBtn").disabled = true; State.scanning = false; }
}

/**
 * On page load / view switch: if the previous scan for this target is still running,
 * reconnect its WebSocket so the user doesn't lose context on a refresh.
 */
async function resumeIfRunning(t) {
  // First check localStorage for a known scan
  let savedId;
  try { savedId = localStorage.getItem(`iron360_active_scan_${t.id}`); } catch (_) {}

  // If no saved scan, try loading the most recent VA scan for this target
  if (!savedId) {
    try {
      const scans = await api(`/api/scans?target_id=${t.id}`);
      const lastVA = scans.find((s) => s.mode === "va");
      if (lastVA) savedId = lastVA.id;
    } catch (_) {}
  }
  if (!savedId) return;

  try {
    const scan = await api(`/api/scans/${savedId}`);
    if (scan.mode !== "va") return;

    if (scan.status === "running" || scan.status === "queued") {
      State.scan = scan;
      State.scanning = true;
      const sb = $("#startBtn"), stb = $("#stopBtn");
      if (sb) sb.disabled = true;
      if (stb) stb.disabled = false;
      addTimeline("note", `↩ Scan #${scan.id} still running — reconnecting stream…`);
      openScanStream(scan.id);
    } else if (scan.status === "done" || scan.status === "stopped") {
      // Completed scan — replay its timeline so user sees results
      State.scan = scan;
      State.scanning = false;
      _replayTimeline(scan);
    }
  } catch (_) {}
}

function _replayTimeline(scan) {
  if (!scan.timeline || !scan.timeline.length) return;
  for (const e of scan.timeline) {
    switch (e.type) {
      case "note": addTimeline("note", e.text); break;
      case "plan": renderPlan(e.steps || []); break;
      case "step": updateStep(e.n, e.status, e.text); break;
      case "reasoning": addTimeline("reasoning", e.text); break;
      case "log": addTerm("out", e.line || e.text || ""); break;
      case "exec":
        addTerm("cmd", "$ " + e.command);
        if (!e.ok) addTerm("denied", "✗ " + (e.denied_reason || "failed"));
        else addTerm("ok", `✓ exit ${e.exit_code} · ${e.duration_s}s`);
        break;
      case "finding":
        if (e.finding) addTimeline("finding", `${(e.finding.status || "").toUpperCase()} · ${e.finding.severity} · ${e.finding.title} (conf ${e.finding.confidence}%)`);
        break;
      case "intel": {
        const items = e.items || [];
        if (e.kind === "exploit-db") addTimeline("reasoning", `Exploit-DB: ${items.length} public exploit(s) matched`);
        else if (e.kind === "owasp") {
          const checked = items.filter((m) => m.method !== "manual only").length;
          addTimeline("reasoning", `OWASP Top 10: ${checked}/10 categories checked`);
        }
        break;
      }
      case "finish": addTimeline("finish", e.text); break;
      case "done": break;
    }
  }
}

function openScanStream(scanId) {
  if (State.ws) { try { State.ws.close(); } catch (_) {} }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/scans/${scanId}/stream?token=${encodeURIComponent(State.token)}`);
  State.ws = ws;
  ws.onmessage = (ev) => handleEvent(JSON.parse(ev.data));
  ws.onclose = () => {
    State.ws = null;
    if (State.scanning) return;
    // Remove thinking indicator on disconnect
    const th = document.getElementById("agThinking"); if (th) th.remove();
    if (State.activeMode === "pentest") {
      setAgentStatusLine("");
      _resetPentestInput();
    } else {
      const sb = $("#startBtn"); if (sb) sb.disabled = false;
      const stb = $("#stopBtn"); if (stb) stb.disabled = true;
    }
  };
  ws.onerror = () => {
    // Remove thinking indicator on error
    const th = document.getElementById("agThinking"); if (th) th.remove();
    if (State.activeMode === "pentest") {
      agentAppend("error", "Connection lost — check network or retry.");
      setAgentStatusLine("");
      _resetPentestInput();
      if (State.scan) State.scan.status = "failed";
    }
    toast("Stream error", "error");
  };
}

const STEP_ICON = { pending: "○", running: "◍", done: "✓", failed: "✗", skipped: "⊘" };

function renderPlan(steps) {
  const tl = $("#timeline"); if (!tl) return;
  const wrap = document.createElement("div");
  wrap.className = "plan";
  wrap.innerHTML = `<div class="plan-head">Plan · ${steps.length} steps</div>` +
    steps.map((s) => `<div class="pstep pending" id="pstep-${s.n}">
        <span class="pico">${STEP_ICON.pending}</span>
        <span class="ptool">${esc(s.tool)}</span>
        <span class="pdesc">${esc(s.desc)}</span>
        <span class="pmeta"></span></div>`).join("");
  tl.appendChild(wrap); tl.scrollTop = tl.scrollHeight;
}
function updateStep(n, status, text) {
  let el = $("#pstep-" + n);
  if (!el) return;
  el.className = "pstep " + status;
  const ico = el.querySelector(".pico"); if (ico) ico.textContent = STEP_ICON[status] || "○";
  if (text) { const d = el.querySelector(".pdesc"); if (d) d.textContent = text; }
}

function addTimeline(cls, text) {
  const tl = $("#timeline"); if (!tl) return;
  const icons = { reasoning: "🧠", note: "·", approval_required: "⏸", finding: "⚑", error: "✗", finish: "✓" };
  const d = document.createElement("div");
  d.className = "timeline-step " + cls;
  d.innerHTML = `<span class="ic">${icons[cls] || "›"}</span><span>${esc(text)}</span>`;
  tl.appendChild(d); tl.scrollTop = tl.scrollHeight;
}
function renderApproval(e) {
  const tl = $("#timeline"); if (!tl) return;
  const d = document.createElement("div");
  d.className = "timeline-step approval_required";
  d.id = "appr-" + e.approval_id;
  d.innerHTML = `<span class="ic">⏸</span><span>${esc(e.text)}
    <div class="row" style="margin-top:8px;gap:8px">
      <button class="btn sm" data-appr="approve">✓ Approve</button>
      <button class="btn danger sm" data-appr="deny">✗ Deny</button>
    </div></span>`;
  tl.appendChild(d); tl.scrollTop = tl.scrollHeight;
  d.querySelectorAll("[data-appr]").forEach((b) => b.addEventListener("click", async () => {
    d.querySelectorAll("[data-appr]").forEach((x) => (x.disabled = true));
    const approved = b.dataset.appr === "approve";
    try {
      await api(`/api/scans/${State.scan.id}/approve`, {
        method: "POST", body: JSON.stringify({ approval_id: e.approval_id, approved }),
      });
    } catch (err) { toast("Approval failed: " + err.message); d.querySelectorAll("[data-appr]").forEach((x) => (x.disabled = false)); }
  }));
}

function addTerm(cls, text) {
  const term = $("#terminal"); if (!term) return;
  const d = document.createElement("div");
  d.className = "line " + cls;
  d.textContent = text;
  term.appendChild(d); term.scrollTop = term.scrollHeight;
}

function handleEvent(e) {
  // --- VA mode events (timeline + terminal panels) ---
  switch (e.type) {
    case "note": addTimeline("note", e.text); agentAppend("system", e.text); break;
    case "plan": renderPlan(e.steps || []); break;
    case "step": updateStep(e.n, e.status, e.text); break;
    case "reasoning": addTimeline("reasoning", e.text); break;
    case "approval_required":
      if (e.approval_id) renderApproval(e);
      else addTimeline("approval_required", e.text);
      break;
    case "approval_resolved": {
      const box = document.getElementById("appr-" + e.approval_id);
      if (box) box.remove();
      addTimeline("approval_required", e.text);
      break;
    }
    case "log":
      addTerm("out", e.line || e.text || "");
      agentAppend("tool_line", e.line || e.text || "");
      break;
    case "exec":
      addTerm("cmd", "$ " + e.command);
      if (!e.ok) addTerm("denied", "✗ " + (e.denied_reason || "failed"));
      else addTerm("ok", `✓ exit ${e.exit_code} · ${e.duration_s}s`);
      agentAppend("tool_done", "", { ok: e.ok, exit_code: e.exit_code, duration_s: e.duration_s, denied_reason: e.denied_reason });
      break;
    case "finding":
      addTimeline("finding", `${(e.finding.status || "").toUpperCase()} · ${e.finding.severity} · ${e.finding.title} (conf ${e.finding.confidence}%)`);
      agentAppend("finding", e.finding.title, { severity: e.finding.severity, title: e.finding.title });
      break;
    case "intel": {
      const items = e.items || [];
      if (e.kind === "compliance") {
        const fail = items.filter((i) => i.result === "fail").length;
        addTimeline("reasoning", `CIS compliance: ${items.length - fail}/${items.length} controls pass · ${fail} fail`);
      } else if (e.kind === "cve") {
        addTimeline("reasoning", `CVE intel: ${items.map((i) => i.cve).join(", ")}`);
      } else if (e.kind === "exploit-db") {
        addTimeline("reasoning", `Exploit-DB: ${items.length} public exploit(s) matched`);
      } else if (e.kind === "owasp") {
        const checked = items.filter((m) => m.method !== "manual only").length;
        const hits = items.filter((m) => m.findings > 0).map((m) => m.id).join(", ");
        addTimeline("reasoning", `OWASP Top 10: ${checked}/10 categories checked${hits ? " · findings in " + hits : ""}`);
      }
      break;
    }
    case "finish": addTimeline("finish", e.text); break;
    case "done":
      State.scanning = false;
      if ($("#startBtn")) $("#startBtn").disabled = false;
      if ($("#stopBtn")) $("#stopBtn").disabled = true;
      toast("Assessment complete", "success");
      break;

    // ---- Pentest agent events (Claude Code style stream) ----
    case "chat_ready":
      break;
    case "chat_user":
      agentAppend("user", e.text);
      break;
    case "agent_thinking": {
      const old = document.getElementById("agThinking");
      if (old) old.remove();
      agentAppend("thinking");
      setAgentStatusLine("thinking…");
      // Ensure Stop button is visible during thinking
      { const stopB = $("#chatStopBtn"); if (stopB) stopB.style.display = ""; }
      break;
    }
    case "agent_thinking_text": {
      const old = document.getElementById("agThinking");
      if (old) old.remove();
      if (e.text && e.text.length > 0) {
        agentAppend("thinking_text", e.text.length > 500 ? e.text.slice(0, 500) + "…" : e.text);
      }
      break;
    }
    case "agent_text":
      agentAppend("text", e.text);
      break;
    case "agent_tool_start":
      agentAppend("tool_start", "", { tool: e.tool, host: e.host });
      setAgentStatusLine(`running ${e.tool || "tool"}…`);
      { const stopB = $("#chatStopBtn"); if (stopB) stopB.style.display = ""; }
      break;
    case "agent_status":
      setAgentStatusLine(e.status);
      break;
    case "chat_turn_done": {
      setAgentStatusLine("");
      _resetPentestInput();
      break;
    }
    case "error":
      addTimeline("error", e.text);
      // Remove any thinking indicator
      { const th = document.getElementById("agThinking"); if (th) th.remove(); }
      agentAppend("error", e.text);
      setAgentStatusLine("");
      _resetPentestInput();
      // Mark scan as failed so next message creates a fresh session
      if (State.scan) State.scan.status = "failed";
      break;
  }
}

function _resetPentestInput() {
  const inp = $("#chatInput"); if (inp) { inp.disabled = false; inp.focus(); }
  const sb = $("#chatSendBtn"); if (sb) sb.disabled = !(inp && inp.value.trim());
  const stopB = $("#chatStopBtn"); if (stopB) stopB.style.display = "none";
}

function setAgentStatusLine(status) {
  const el = $("#agentStatus");
  if (el) el.textContent = status || "";
}

async function stopScan() {
  if (!State.scan) return;
  const sid = State.scan.id;

  State.scanning = false;
  if (State.activeMode === "pentest") {
    const chatStopBtn = $("#chatStopBtn"); if (chatStopBtn) chatStopBtn.style.display = "none";
    agentAppend("system", "Stopping agent…");
    setAgentStatusLine("");
  } else {
    const startBtn = $("#startBtn"); if (startBtn) startBtn.disabled = false;
    const stopBtn = $("#stopBtn"); if (stopBtn) stopBtn.disabled = true;
    addTimeline("note", "Stopping…");
  }

  // Call stop API first, then close WS
  try { await api(`/api/scans/${sid}/stop`, { method: "POST" }); } catch (_) {}
  if (State.ws) { try { State.ws.close(); } catch (_) {} State.ws = null; }

  // Re-enable inputs
  if (State.activeMode === "pentest") {
    const chatInput = $("#chatInput"); if (chatInput) chatInput.disabled = false;
    const chatSendBtn = $("#chatSendBtn"); if (chatSendBtn) chatSendBtn.disabled = false;
  }

  if (State.currentTargetId) { try { localStorage.removeItem(`iron360_active_scan_${State.currentTargetId}`); } catch (_) {} }
  State.scan = null;
  toast("Stopped");
}

/* ----------------------------- Findings ----------------------------- */
async function viewFindings() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `<div class="muted">Loading…</div>`;
  const findings = await api("/api/findings?target_id=" + t.id);
  State.findings = findings;
  if (!findings.length) { c.innerHTML = `<div class="empty">No findings yet for ${esc(t.value)}. Run an AI pentest.</div>`; return; }
  const realFindings = findings.filter((f) => f.status !== "false_positive");
  const fpFindings = findings.filter((f) => f.status === "false_positive");
  c.innerHTML = `
    <div class="row spread" style="margin-bottom:14px">
      <span class="muted">${findings.length} finding(s)${fpFindings.length ? ` · <span id="toggleFP" style="cursor:pointer;text-decoration:underline">${fpFindings.length} false positive hidden</span>` : ""}</span>
      <button class="btn danger sm" id="resetFindings">Reset all findings</button>
    </div>
    <div class="card"><table><thead><tr><th>Severity</th><th>Finding</th><th>CVSS</th><th>Status</th><th>Confidence</th><th>Sources</th><th></th></tr></thead><tbody>
    ${findings.map((f) => `<tr class="clickable ${f.status === "false_positive" ? "fp-row" : ""}" data-f="${f.id}" ${f.status === "false_positive" ? 'style="display:none"' : ""}>
      <td><span class="pill ${f.severity}">${f.severity}</span></td>
      <td><b>${esc(f.title)}</b> ${f.cve ? `<span class="tag" style="color:var(--accent)">${esc(f.cve)}</span>` : ""}${f.cwe ? ` <span class="tag">${esc(f.cwe)}</span>` : ""}<br><small class="muted">${esc(f.affected || "")}</small></td>
      <td>${f.cvss_score ? `<b style="color:${cvssColor(f.cvss_score)}">${f.cvss_score}</b>` : '<span class="muted">—</span>'}</td>
      <td><span class="pill ${f.status}">${f.status.replace("_", " ")}</span></td>
      <td>${_confLabel(f.confidence)}</td>
      <td><small class="muted">${(f.sources || []).map(esc).join(", ")}</small></td>
      <td><button class="btn danger sm del-finding" data-del="${f.id}" style="padding:3px 8px;font-size:11px">✗</button></td></tr>`).join("")}
  </tbody></table></div>`;
  c.querySelectorAll("[data-f]").forEach((r) => r.addEventListener("click", (e) => {
    if (e.target.closest(".del-finding")) return;
    openFinding(Number(r.dataset.f));
  }));
  c.querySelectorAll(".del-finding").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    deleteFinding(Number(b.dataset.del));
  }));
  $("#resetFindings").addEventListener("click", () => resetAllFindings(t.id));
  const fpToggle = $("#toggleFP");
  if (fpToggle) {
    let fpVisible = false;
    fpToggle.addEventListener("click", () => {
      fpVisible = !fpVisible;
      c.querySelectorAll(".fp-row").forEach((r) => r.style.display = fpVisible ? "" : "none");
      fpToggle.textContent = fpVisible ? `hide ${fpFindings.length} false positive` : `${fpFindings.length} false positive hidden`;
    });
  }
}

function _confLabel(pct) {
  if (pct >= 80) return `<span style="color:var(--ok)">${pct}%</span>`;
  if (pct >= 50) return `<span style="color:var(--warn)">${pct}%</span>`;
  if (pct >= 20) return `<span style="color:var(--muted)">${pct}%</span>`;
  return `<span style="color:var(--critical);opacity:0.7">${pct}% <small>unverified</small></span>`;
}

function openFinding(id) {
  const f = State.findings.find((x) => x.id === id); if (!f) return;
  const d = $("#drawer");
  d.innerHTML = `
    <div class="row spread"><span class="pill ${f.severity}">${f.severity}</span><button class="btn ghost sm" id="closeDrawer">Close</button></div>
    <h2>${esc(f.title)}</h2>
    <div class="row"><span class="pill ${f.status}">${f.status.replace("_", " ")}</span><span class="muted">confidence ${f.confidence}%</span>
      ${f.cvss_score ? `<span style="font-weight:700;color:${cvssColor(f.cvss_score)}">CVSS ${f.cvss_score}</span>` : ""}</div>
    ${f.cvss_vector ? kv("CVSS Vector", f.cvss_vector) : ""}
    ${f.cve ? `<div class="kv"><div class="k">CVE / Exploit</div><div class="v">
        <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" rel="noopener">${esc(f.cve)} (NVD)</a>
        &nbsp;·&nbsp;<a href="https://www.exploit-db.com/search?cve=${esc(f.cve)}" target="_blank" rel="noopener">Exploit-DB</a>
      </div></div>` : ""}
    ${f.cwe ? kv("CWE", f.cwe) : ""}
    ${kv("Affected", f.affected || "—")}
    <div class="kv"><div class="k">Description</div><div class="v">${fmtText(f.description || "—")}</div></div>
    <div class="kv"><div class="k">Evidence / PoC</div><div class="codeblock">${esc(f.evidence || "(none)")}</div></div>
    <div class="kv"><div class="k">Remediation</div><div class="v">${fmtText(f.remediation || "—")}</div></div>
    ${f.fix_config ? `<div class="kv"><div class="k" style="color:var(--confirmed)">Config fix (siap pakai)</div><div class="codeblock">${esc(f.fix_config)}</div></div>` : ""}
    ${f.fix_steps ? `<div class="kv"><div class="k" style="color:var(--confirmed)">Langkah apply &amp; verify</div><div class="codeblock" style="white-space:pre-wrap">${fmtText(f.fix_steps)}</div></div>` : ""}
    ${kv("Corroborating sources", (f.sources || []).join(", ") || "—")}
    ${(f.references && f.references.length) ? `<div class="kv"><div class="k">References</div><div class="v">${f.references.map(r => `<a href="${esc(r)}" target="_blank" rel="noopener" style="display:block;font-size:12px;margin:2px 0">${esc(r)}</a>`).join("")}</div></div>` : ""}
    <div class="section-title"><h3>Human validation (final gate)</h3></div>
    <div class="row">
      <button class="btn sm" data-set="confirmed">Confirm</button>
      <button class="btn ghost sm" data-set="likely">Likely</button>
      <button class="btn ghost sm" data-set="needs_review">Needs review</button>
      <button class="btn danger sm" data-set="false_positive">False positive</button>
    </div>
    <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border)">
      <button class="btn danger sm" id="drawerDelFinding">Delete this finding</button>
    </div>`;
  $("#drawerBg").classList.add("open"); d.classList.add("open");
  $("#closeDrawer").addEventListener("click", closeDrawer);
  $("#drawerDelFinding").addEventListener("click", () => deleteFinding(id));
  d.querySelectorAll("[data-set]").forEach((b) => b.addEventListener("click", () => setFindingStatus(id, b.dataset.set)));
}
function cvssColor(score) {
  if (score >= 9.0) return "#dc2626";
  if (score >= 7.0) return "#ea580c";
  if (score >= 4.0) return "#d97706";
  if (score >= 0.1) return "#2563eb";
  return "#64748b";
}
function kv(k, v) { return `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`; }
function fmtText(raw) {
  if (!raw || raw === "—") return "—";
  let s = esc(raw);
  s = s.replace(/(\d+)\)\s+/g, "\n$1) ");
  s = s.replace(/(\d+)\.\s+/g, "\n$1. ");
  s = s.replace(/;\s+/g, ";\n");
  s = s.replace(/\n{3,}/g, "\n\n");
  const lines = s.split("\n").map(l => l.trim()).filter(Boolean);
  if (lines.length <= 1) return s.trim();
  return lines.map(l => {
    if (/^\d+[\.\)]/.test(l)) return `<div style="padding:3px 0 3px 8px;border-left:2px solid var(--border-2);margin:3px 0">${l}</div>`;
    return `<div style="margin:3px 0">${l}</div>`;
  }).join("");
}
function closeDrawer() { $("#drawerBg").classList.remove("open"); $("#drawer").classList.remove("open"); }

async function setFindingStatus(id, status) {
  await api(`/api/findings/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) });
  const f = State.findings.find((x) => x.id === id); if (f) f.status = status;
  closeDrawer(); viewFindings(); toast("Verdict: " + status.replace("_", " "), "success");
}

async function deleteFinding(id) {
  const f = State.findings.find((x) => x.id === id);
  const yes = await showDialog({ title: "Delete Finding", message: `Hapus finding "${f ? f.title : "#" + id}" ? Aksi ini tidak dapat dibatalkan.`, okText: "Delete", danger: true });
  if (!yes) return;
  await api(`/api/findings/${id}`, { method: "DELETE" });
  closeDrawer(); viewFindings(); toast("Finding deleted", "success");
}

async function resetAllFindings(targetId) {
  const yes = await showDialog({ title: "Reset All Findings", message: `Hapus SEMUA findings untuk target ini? Semua data temuan, evidence, dan status akan dihapus permanen.`, okText: "Reset All", danger: true });
  if (!yes) return;
  await api(`/api/findings?target_id=${targetId}`, { method: "DELETE" });
  viewFindings(); toast("All findings reset", "success");
}

/* ----------------------------- Knowledge ----------------------------- */
async function viewKnowledge() {
  const c = $("#content");
  c.innerHTML = `<div class="muted">Loading knowledge base…</div>`;
  const { references, corpus } = await api("/api/knowledge");
  const corpusLine = corpus && corpus.indexed
    ? `<span class="pill confirmed">RAG corpus: ${corpus.chunks.toLocaleString()} chunks</span> <span class="muted">sources: ${(corpus.sources || []).join(", ")}</span>`
    : `<span class="pill needs_review">RAG corpus not ingested on this host</span>`;
  c.innerHTML = `
    <div class="hint">References feed the AI as retrieval context (RAG) + methodology playbooks — not model retraining.
      During an assessment the AI searches this corpus for real payloads/techniques and uses them.</div>
    <div class="card" style="margin-top:12px">
      <div class="row spread"><div>${corpusLine}</div></div>
      <div class="row" style="margin-top:10px">
        <input id="kbq" placeholder="Search corpus payloads/techniques… e.g. SQL injection WAF bypass" style="flex:1" />
        <button class="btn sm" id="kbsearch">Search</button>
      </div>
      <div id="kbresults" style="margin-top:12px"></div>
    </div>
    <div class="section-title"><h3>Reference registry (${references.length})</h3></div>
    <div class="ref-grid">
      ${references.map((r) => `<div class="ref"><div class="cat">${esc(r.category)}</div><b>${esc(r.name)}</b>
        <p>${esc(r.note)}</p><div class="tagline">${(r.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</div></div>`).join("")}
    </div>`;
  const doSearch = async () => {
    const q = $("#kbq").value.trim(); if (!q) return;
    $("#kbresults").innerHTML = `<div class="muted">Searching…</div>`;
    try {
      const { hits } = await api("/api/knowledge/search?q=" + encodeURIComponent(q));
      $("#kbresults").innerHTML = hits.length
        ? hits.map((h) => `<div class="card" style="margin:8px 0"><div class="row spread"><b>${esc(h.heading)}</b><span class="tag">${esc(h.path)}</span></div><div class="codeblock" style="margin-top:8px">${esc(h.text.slice(0, 700))}</div></div>`).join("")
        : `<div class="muted">No matches.</div>`;
    } catch (e) { $("#kbresults").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  };
  $("#kbsearch").addEventListener("click", doSearch);
  $("#kbq").addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });
}

/* ----------------------------- Audit ----------------------------- */
async function viewAudit() {
  const c = $("#content");
  c.innerHTML = `<div class="muted">Loading…</div>`;
  const rows = await api("/api/audit?limit=300");
  c.innerHTML = `<div class="card"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>Outcome</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="muted">${fmtTime(r.at)}</td><td>${esc(r.actor)}</td><td><b>${esc(r.action)}</b></td>
      <td>${esc(r.target_value || "—")}</td><td><small class="muted">${esc((r.detail || "").slice(0, 80))}</small></td>
      <td><span class="pill ${r.outcome === "ok" ? "confirmed" : r.outcome === "denied" ? "critical" : "needs_review"}">${r.outcome}</span></td></tr>`).join("")}
  </tbody></table></div>`;
}

/* ----------------------------- Scheduled Scans ----------------------------- */
async function viewSchedules() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `<div class="muted">Loading…</div>`;
  const schedules = await api("/api/schedules?target_id=" + t.id);
  c.innerHTML = `
    <div class="row spread" style="margin-bottom:14px">
      <span class="muted">${schedules.length} schedule(s) for ${esc(t.value)}</span>
      <button class="btn sm" id="addSchedule">+ Add Schedule</button>
    </div>
    ${schedules.length ? `<div class="card"><table><thead><tr><th>Cron</th><th>Profile</th><th>Status</th><th>Last Run</th><th>Next Run</th><th></th></tr></thead><tbody>
    ${schedules.map((s) => `<tr>
      <td><code>${esc(s.cron_expr)}</code></td>
      <td>${esc(s.profile)}</td>
      <td><span class="pill ${s.enabled ? "confirmed" : "needs_review"}">${s.enabled ? "Active" : "Paused"}</span></td>
      <td class="muted">${s.last_run ? fmtTime(s.last_run) : "—"}</td>
      <td class="muted">${s.next_run ? fmtTime(s.next_run) : "—"}</td>
      <td>
        <button class="btn ghost sm toggle-sched" data-sid="${s.id}" data-en="${s.enabled ? 0 : 1}">${s.enabled ? "Pause" : "Resume"}</button>
        <button class="btn danger sm del-sched" data-sid="${s.id}" style="margin-left:4px">Delete</button>
      </td></tr>`).join("")}
    </tbody></table></div>` : `<div class="empty">No scheduled scans. Click "Add Schedule" to set up recurring VA scans.</div>`}
    <div class="hint" style="margin-top:14px">Cron format: minute hour day month weekday. Example: <code>0 2 * * 1</code> = setiap Senin jam 2 pagi.</div>`;
  $("#addSchedule").addEventListener("click", () => addScheduleDialog(t));
  c.querySelectorAll(".toggle-sched").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/schedules/${b.dataset.sid}`, { method: "PATCH", body: JSON.stringify({ enabled: b.dataset.en === "1" }) });
    viewSchedules();
  }));
  c.querySelectorAll(".del-sched").forEach((b) => b.addEventListener("click", async () => {
    const yes = await showDialog({ title: "Delete Schedule", message: "Hapus jadwal scan ini?", okText: "Delete", danger: true });
    if (!yes) return;
    await api(`/api/schedules/${b.dataset.sid}`, { method: "DELETE" });
    viewSchedules(); toast("Schedule deleted", "success");
  }));
}

async function addScheduleDialog(t) {
  const cron = await showDialog({ type: "prompt", title: "Add Scheduled Scan", message: "Masukkan cron expression (contoh: 0 2 * * 1 = setiap Senin jam 2 pagi):", placeholder: "0 2 * * 1", okText: "Create" });
  if (!cron) return;
  try {
    await api("/api/schedules", { method: "POST", body: JSON.stringify({ target_id: t.id, cron_expr: cron, profile: "full" }) });
    viewSchedules(); toast("Schedule created", "success");
  } catch (e) { toast(e.message, "error"); }
}

/* ----------------------------- Vulnerability Trending ----------------------------- */
async function viewTrending() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `<div class="muted">Loading trending data…</div>`;
  const data = await api(`/api/scans/trending/${t.id}`);
  if (!data.length) { c.innerHTML = `<div class="empty">No completed scans for ${esc(t.value)} yet. Run a VA scan first.</div>`; return; }
  const maxTotal = Math.max(...data.map(d => d.total), 1);
  c.innerHTML = `
    <div class="hint" style="margin-bottom:14px">Vulnerability trend across ${data.length} scan(s) for ${esc(t.value)}. Track remediation progress over time.</div>
    <div class="card">
      <table><thead><tr><th>Date</th><th>Profile</th><th>Total</th><th style="color:#dc2626">Crit</th><th style="color:#ea580c">High</th><th style="color:#d97706">Med</th><th style="color:#2563eb">Low</th><th>Info</th><th>Avg CVSS</th><th>Trend</th></tr></thead><tbody>
      ${data.map((d) => `<tr>
        <td class="muted">${fmtTime(d.date)}</td>
        <td>${esc(d.profile)}</td>
        <td><b>${d.total}</b></td>
        <td>${d.critical || "—"}</td>
        <td>${d.high || "—"}</td>
        <td>${d.medium || "—"}</td>
        <td>${d.low || "—"}</td>
        <td>${d.info || "—"}</td>
        <td>${d.avg_cvss ? `<b style="color:${cvssColor(d.avg_cvss)}">${d.avg_cvss}</b>` : "—"}</td>
        <td><div style="background:var(--border);border-radius:3px;height:14px;width:120px;overflow:hidden">
          <div style="height:100%;display:flex">
            <div style="width:${(d.critical/maxTotal*100).toFixed(1)}%;background:#dc2626"></div>
            <div style="width:${(d.high/maxTotal*100).toFixed(1)}%;background:#ea580c"></div>
            <div style="width:${(d.medium/maxTotal*100).toFixed(1)}%;background:#d97706"></div>
            <div style="width:${(d.low/maxTotal*100).toFixed(1)}%;background:#2563eb"></div>
            <div style="width:${(d.info/maxTotal*100).toFixed(1)}%;background:#64748b"></div>
          </div></div></td>
      </tr>`).join("")}
      </tbody></table>
    </div>
    ${data.length >= 2 ? `<div class="card" style="margin-top:16px;padding:16px">
      <h3 style="margin:0 0 10px">Remediation Progress</h3>
      <div class="row" style="gap:24px">
        <div><span class="muted">First scan:</span> <b>${data[0].total}</b> findings</div>
        <div><span class="muted">Latest scan:</span> <b>${data[data.length-1].total}</b> findings</div>
        <div><span class="muted">Change:</span> <b style="color:${data[data.length-1].total <= data[0].total ? "#047857" : "#dc2626"}">${data[data.length-1].total - data[0].total >= 0 ? "+" : ""}${data[data.length-1].total - data[0].total}</b></div>
      </div>
    </div>` : ""}`;
}

/* ----------------------------- Settings ----------------------------- */
function viewSettings() {
  const s = State.status || {};
  const tools = s.tools || {};
  const c = $("#content");
  c.innerHTML = `
    <div class="grid stats">
      ${statCard("AI engine", (s.ai_engine || "?").toUpperCase(), s.ai_model || "set ANTHROPIC_API_KEY for live", s.ai_engine === "live" ? "var(--ok)" : "var(--warn)")}
      ${statCard("Executor", s.executor_enabled ? "ENABLED" : "DISABLED", "live tool runs", s.executor_enabled ? "var(--ok)" : "var(--warn)")}
      ${statCard("Environment", (s.env || "?").toUpperCase(), "", "var(--muted)")}
    </div>
    <div class="section-title"><h3>Installed executor tools</h3></div>
    <div class="card"><div class="row">
      ${Object.entries(tools).map(([n, ok]) => `<span class="pill ${ok ? "confirmed" : "needs_review"}">${esc(n)} ${ok ? "✓" : "✗"}</span>`).join("")}
    </div></div>
    <div class="section-title"><h3>Change password</h3></div>
    <div class="card" style="max-width:420px">
      <label class="field"><span>Current password</span><input id="cpCur" type="password" /></label>
      <label class="field"><span>New password (min 10 chars)</span><input id="cpNew" type="password" /></label>
      <button class="btn sm" id="cpBtn">Update password</button>
      <div class="err" id="cpErr"></div>
    </div>`;
  $("#cpBtn").addEventListener("click", async () => {
    try {
      await api("/api/auth/change-password", { method: "POST", body: JSON.stringify({ current_password: $("#cpCur").value, new_password: $("#cpNew").value }) });
      $("#cpCur").value = ""; $("#cpNew").value = ""; toast("Password updated", "success");
    } catch (e) { $("#cpErr").textContent = e.message; }
  });
}

/* ----------------------------- Reports ----------------------------- */
async function viewReports() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  const reportUrl = `/report/${t.id}?token=${encodeURIComponent(State.token)}`;
  c.innerHTML = `
    <div class="section-title"><h3>VAPT report — ${esc(t.value)}</h3><div class="spacer"></div>
      <button class="btn sm" id="printReport">⎙ Print / Save PDF</button>
      <button class="btn ghost sm" id="openReport">↗ Open full report</button></div>
    <div class="hint">Laporan AI mencakup ringkasan eksekutif, rincian temuan, bukti/PoC, confidence, dan
      <b>konfigurasi perbaikan konkret</b> (siap pakai) per temuan.</div>
    <div class="card" style="margin-top:14px;padding:0;overflow:hidden">
      <iframe id="reportFrame" style="width:100%;height:70vh;border:0;background:#fff" title="report preview"></iframe>
    </div>`;
  $("#printReport").addEventListener("click", () => {
    window.open(reportUrl, "_blank");
    toast("Report dibuka di tab baru — gunakan Print / Save PDF di sana");
  });
  $("#openReport").addEventListener("click", () => {
    window.open(reportUrl, "_blank");
  });
  // Inline preview via authenticated fetch (iframe can't send Authorization header).
  try {
    const res = await fetch(`/api/targets/${t.id}/report`, { headers: { Authorization: "Bearer " + State.token } });
    let htmlStr = await res.text();
    htmlStr = htmlStr.replace('</head>', '<style>.toolbar{display:none!important}</style></head>');
    $("#reportFrame").srcdoc = htmlStr;
  } catch (e) { toast("Report preview failed: " + e.message); }
}

/* ----------------------------- Domain Health (module) ----------------------------- */
async function viewDomainHealth() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `<div class="muted">Probing ${esc(t.value)} (DNS · TLS · HTTP · Headers)…</div>`;
  try {
    const h = await api(`/api/modules/domain-health/${t.id}`);
    const gradeColor = h.score >= 85 ? "var(--ok)" : h.score >= 60 ? "var(--warn)" : "var(--critical)";
    const secHeaders = (h.http.security_headers || []);
    const shPresent = secHeaders.filter(s => s.present).length;
    const shTotal = secHeaders.length;
    const dns = h.dns || {};

    c.innerHTML = `
      <div class="grid stats">
        ${statCard("Health score", h.score + "/100", h.issues.length + " issue(s)", gradeColor)}
        ${statCard("TLS", (h.tls.protocol || "—"), h.tls.cipher || (h.tls.error ? "probe error" : ""), h.tls.ok ? "var(--ok)" : "var(--warn)")}
        ${statCard("Security headers", shTotal ? shPresent + "/" + shTotal : "—", shTotal ? (shPresent === shTotal ? "All present" : (shTotal - shPresent) + " missing") : "No data", shPresent === shTotal ? "var(--ok)" : "var(--warn)")}
        ${statCard("DNS records", (dns.resolved || []).length + " A", (dns.mx || []).length + " MX · " + (dns.ns || []).length + " NS", "var(--muted)")}
      </div>

      <div class="section-title"><h3>Security headers</h3></div>
      <div class="card">${secHeaders.length ? `<table>
        <thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Description</th></tr></thead>
        <tbody>${secHeaders.map(s => `<tr>
          <td><b>${esc(s.header)}</b></td>
          <td>${s.present ? '<span class="pill ok" style="font-size:11px">✓ Present</span>' : '<span class="pill critical" style="font-size:11px">✗ Missing</span>'}</td>
          <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;font-size:12px">${esc(s.value || "—")}</td>
          <td class="muted" style="font-size:12px">${esc(s.description || "")}</td>
        </tr>`).join("")}</tbody>
      </table>` : '<div class="muted">Could not probe security headers (target unreachable)</div>'}</div>

      <div class="section-title"><h3>DNS records</h3></div>
      <div class="card"><table>
        <tr><th>A records</th><td>${(dns.resolved || []).map(r => esc(r)).join(", ") || esc(dns.error || "—")}</td></tr>
        <tr><th>MX records</th><td>${(dns.mx || []).map(r => esc(r)).join(", ") || "—"}</td></tr>
        <tr><th>NS records</th><td>${(dns.ns || []).map(r => esc(r)).join(", ") || "—"}</td></tr>
        <tr><th>SPF</th><td>${dns.has_spf ? '<span class="pill ok" style="font-size:11px">✓ Present</span>' : '<span class="pill critical" style="font-size:11px">✗ Missing</span>'}</td></tr>
        <tr><th>DMARC</th><td>${dns.has_dmarc ? '<span class="pill ok" style="font-size:11px">✓ Present</span>' : '<span class="pill critical" style="font-size:11px">✗ Missing</span>'}</td></tr>
      </table></div>

      <div class="section-title"><h3>TLS / certificate</h3></div>
      <div class="card"><table>
        <tr><th>Protocol</th><td>${esc(h.tls.protocol || "—")}</td></tr>
        <tr><th>Cipher suite</th><td>${esc(h.tls.cipher || "—")}</td></tr>
        <tr><th>Issuer</th><td>${esc(h.tls.issuer || "—")}</td></tr>
        <tr><th>Expires</th><td>${esc(h.tls.expires || "—")}</td></tr>
        <tr><th>SAN</th><td>${(h.tls.san || []).map(s => esc(s)).join(", ") || "—"}</td></tr>
        <tr><th>Signature algorithm</th><td>${esc(h.tls.sig_alg || "—")}</td></tr>
      </table></div>

      <div class="section-title"><h3>HTTP probe (httpx)</h3></div>
      <div class="card"><div class="codeblock">${esc(h.http.raw || "—")}</div></div>

      <div class="section-title"><h3>Issues (${h.issues.length})</h3></div>
      <div class="card">${h.issues.length ? h.issues.map((i) => `<div class="row" style="margin:6px 0"><span class="pill ${i.sev}">${i.sev}</span><span>${esc(i.msg)}</span></div>`).join("") : `<div class="muted">No issues detected — looking good!</div>`}</div>`;
  } catch (e) { c.innerHTML = `<div class="empty"><h3>Domain Health</h3><p>${esc(e.message)}</p></div>`; }
}

/* ----------------------------- Planned modules ----------------------------- */
async function viewModule(name) {
  const c = $("#content");
  c.innerHTML = `<div class="muted">Loading…</div>`;
  try {
    const s = await api(`/api/modules/spec/${name}`);
    c.innerHTML = `
      <div class="card">
        <div class="row spread"><h3 style="margin:0">${esc(s.title)}</h3><span class="pill demo">${esc(s.status)} · phase 2</span></div>
        <p class="muted" style="margin-top:8px">${esc(s.summary)}</p>
      </div>
      <div class="section-title"><h3>Planned capabilities</h3></div>
      <div class="card">${s.capabilities.map((x) => `<div class="row" style="margin:5px 0"><span class="pill low">▸</span><span>${esc(x)}</span></div>`).join("")}</div>
      <div class="section-title"><h3>Requires</h3></div>
      <div class="card"><div class="row">${s.needs.map((x) => `<span class="tag">${esc(x)}</span>`).join("")}</div></div>
      <div class="hint">Sesuai arahan: fokus VAPT AI dulu. Modul ini sudah tersedia di dashboard dan siap diaktifkan di fase berikutnya.</div>`;
  } catch (e) { c.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

/* ----------------------------- helpers ----------------------------- */
function emptyNoTarget() {
  return `<div class="empty"><h3>No target selected</h3><p>Create a target workspace to begin.</p>
    <button class="btn sm" id="emptyAdd" style="margin:0 auto">+ Add target</button></div>`;
}
function bindEmpty() { const b = $("#emptyAdd"); if (b) b.addEventListener("click", openTargetModal); }
function fmtTime(iso) { if (!iso) return "—"; const d = new Date(iso); return d.toLocaleString(); }

/* ----------------------------- start ----------------------------- */
if (State.token) boot().catch(renderLogin); else renderLogin();
