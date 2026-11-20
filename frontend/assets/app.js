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
};

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2600);
}

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (State.token) headers["Authorization"] = "Bearer " + State.token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401) { logout(); throw new Error("Session expired"); }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

function logout() {
  State.token = null; State.user = null;
  localStorage.removeItem("iron360_token");
  if (State.ws) { try { State.ws.close(); } catch (_) {} }
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

  $("#logoutBtn").addEventListener("click", logout);
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
const TITLES = { dashboard: "Dashboard", pentest: "AI Pentest Console", findings: "Findings", reports: "Reports", "domain-health": "Domain Health", "threat-intel": "Threat Intelligence", "dark-web": "Dark Web Crawling", "siem-log": "SIEM Log", targets: "Targets & Scope", knowledge: "Knowledge Base", audit: "Audit Log", settings: "Settings" };

function setView(view) {
  State.view = view;
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === view));
  $("#viewTitle").textContent = TITLES[view] || "";
  const views = {
    dashboard: viewDashboard, pentest: viewPentest, findings: viewFindings, reports: viewReports,
    "domain-health": viewDomainHealth, "threat-intel": () => viewModule("threat-intel"),
    "dark-web": () => viewModule("dark-web"), "siem-log": () => viewModule("siem-log"),
    targets: viewTargets, knowledge: viewKnowledge, audit: viewAudit, settings: viewSettings,
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
  return `<table><thead><tr><th>ID</th><th>Mode</th><th>Autonomy</th><th>Status</th><th>Started</th><th>Summary</th></tr></thead><tbody>
    ${scans.map((s) => `<tr><td>#${s.id}</td><td>${s.mode.toUpperCase()}</td><td>${s.autonomy}</td>
      <td><span class="pill ${s.status === "done" ? "confirmed" : s.status === "failed" ? "critical" : "needs_review"}">${s.status}</span></td>
      <td class="muted">${fmtTime(s.started_at)}</td><td class="muted">${esc((s.summary || "").slice(0, 90))}</td></tr>`).join("")}
  </tbody></table>`;
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
    const ref = prompt("Authorization reference (SOW / PKS / NDA id) — required to mark in-scope:");
    if (ref === null) return;
    await api(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify({ authorized: true, authorization_ref: ref }) });
  } else {
    await api(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify({ authorized: false }) });
  }
  await loadTargets(); renderTargetsTable(); renderTargetSwitch(); toast("Authorization updated");
}
async function delTarget(id) {
  if (!confirm("Delete this target and all its scans/findings?")) return;
  await api(`/api/targets/${id}`, { method: "DELETE" });
  if (State.currentTargetId === id) State.currentTargetId = null;
  await loadTargets(); renderTargetsTable(); renderTargetSwitch(); toast("Target deleted");
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
    toast("Target created");
  } catch (e) { $("#mErr").textContent = e.message; }
}

/* ----------------------------- AI Pentest console ----------------------------- */
function viewPentest() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `
    <div class="console">
      <div class="panel">
        <div class="phead">① Reasoning / Plan</div>
        <div class="pbody" id="timeline"><div class="muted">Idle. Configure a run and press Start.</div></div>
      </div>
      <div class="panel">
        <div class="phead">② Live Execution <span class="muted" id="execHost">· ${esc(t.value)}</span></div>
        <div class="pbody term" id="terminal"><div class="line muted">No commands executed yet.</div></div>
      </div>
      <div class="panel controls">
        <div class="phead">③ Controls</div>
        <div class="pbody">
          <label class="field"><span>Mode</span>
            <div class="seg" id="modeSeg"><button data-mode="va">VA scan</button><button data-mode="pentest" class="on">Pentest</button></div>
          </label>
          <label class="field"><span>Autonomy</span>
            <div class="seg" id="autoSeg"><button data-auto="auto">Auto</button><button data-auto="approve" class="on">Approve intrusive</button></div>
          </label>
          <div class="row" style="margin:14px 0 6px">
            <button class="btn sm" id="startBtn">▶ Start assessment</button>
            <button class="btn ghost sm" id="stopBtn" disabled>■ Stop</button>
          </div>
          ${t.authorized ? "" : `<div class="hint" style="border-color:var(--warn);color:var(--warn)">Target is not authorized — mark it authorized in Targets &amp; Scope before scanning.</div>`}
          <div class="hint">The AI plans and decides; it never runs a shell. Every command is spawned by the executor only
            after a scope check. Out-of-scope hosts are refused automatically. In <b>Approve</b> mode, intrusive steps
            (ffuf, sqlmap) are held for your approval.</div>
        </div>
      </div>
    </div>`;

  let mode = "pentest", autonomy = "approve";
  $("#modeSeg").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    mode = b.dataset.mode; $("#modeSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
  }));
  $("#autoSeg").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    autonomy = b.dataset.auto; $("#autoSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
  }));
  $("#startBtn").addEventListener("click", () => startScan(t, mode, autonomy));
  $("#stopBtn").addEventListener("click", stopScan);
}

async function startScan(t, mode, autonomy) {
  if (!t.authorized) { toast("Target not authorized"); return; }
  $("#timeline").innerHTML = ""; $("#terminal").innerHTML = "";
  $("#startBtn").disabled = true; $("#stopBtn").disabled = false;
  try {
    const scan = await api("/api/scans", { method: "POST", body: JSON.stringify({ target_id: t.id, mode, autonomy }) });
    State.scan = scan;
    openScanStream(scan.id);
  } catch (e) { toast(e.message); $("#startBtn").disabled = false; $("#stopBtn").disabled = true; }
}

function openScanStream(scanId) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/scans/${scanId}/stream?token=${encodeURIComponent(State.token)}`);
  State.ws = ws;
  ws.onmessage = (ev) => handleEvent(JSON.parse(ev.data));
  ws.onclose = () => { $("#startBtn") && ($("#startBtn").disabled = false); $("#stopBtn") && ($("#stopBtn").disabled = true); };
  ws.onerror = () => toast("Stream error");
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
function addTerm(cls, text) {
  const term = $("#terminal"); if (!term) return;
  const d = document.createElement("div");
  d.className = "line " + cls;
  d.textContent = text;
  term.appendChild(d); term.scrollTop = term.scrollHeight;
}

function handleEvent(e) {
  switch (e.type) {
    case "note": addTimeline("note", e.text); break;
    case "plan": renderPlan(e.steps || []); break;
    case "step": updateStep(e.n, e.status, e.text); break;
    case "reasoning": addTimeline("reasoning", e.text); break;
    case "approval_required": addTimeline("approval_required", e.text); break;
    case "exec":
      addTerm("cmd", "$ " + e.command);
      if (!e.ok) addTerm("denied", "✗ " + (e.denied_reason || "failed"));
      else {
        addTerm("out", (e.output || "(no output)").slice(0, 4000));
        addTerm("ok", `✓ exit ${e.exit_code} · ${e.duration_s}s`);
      }
      break;
    case "finding":
      addTimeline("finding", `${(e.finding.status || "").toUpperCase()} · ${e.finding.severity} · ${e.finding.title} (conf ${e.finding.confidence}%)`);
      break;
    case "finish": addTimeline("finish", e.text); break;
    case "done":
      $("#startBtn") && ($("#startBtn").disabled = false); $("#stopBtn") && ($("#stopBtn").disabled = true);
      toast("Assessment complete");
      break;
    case "error": addTimeline("error", e.text); break;
  }
}

async function stopScan() {
  if (!State.scan) return;
  // Respond instantly: flip buttons + close the stream before the API round-trip.
  $("#startBtn").disabled = false; $("#stopBtn").disabled = true;
  addTimeline("note", "Stopping… killing running tool.");
  const sid = State.scan.id;
  if (State.ws) { try { State.ws.close(); } catch (_) {} State.ws = null; }
  try { await api(`/api/scans/${sid}/stop`, { method: "POST" }); } catch (_) {}
  toast("Assessment stopped");
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
  c.innerHTML = `<div class="card"><table><thead><tr><th>Severity</th><th>Finding</th><th>Status</th><th>Confidence</th><th>Sources</th></tr></thead><tbody>
    ${findings.map((f) => `<tr class="clickable" data-f="${f.id}">
      <td><span class="pill ${f.severity}">${f.severity}</span></td>
      <td><b>${esc(f.title)}</b> ${f.cve ? `<span class="tag" style="color:var(--accent)">${esc(f.cve)}</span>` : ""}<br><small class="muted">${esc(f.affected || "")}</small></td>
      <td><span class="pill ${f.status}">${f.status.replace("_", " ")}</span></td>
      <td>${f.confidence}%</td>
      <td><small class="muted">${(f.sources || []).map(esc).join(", ")}</small></td></tr>`).join("")}
  </tbody></table></div>`;
  c.querySelectorAll("[data-f]").forEach((r) => r.addEventListener("click", () => openFinding(Number(r.dataset.f))));
}

function openFinding(id) {
  const f = State.findings.find((x) => x.id === id); if (!f) return;
  const d = $("#drawer");
  d.innerHTML = `
    <div class="row spread"><span class="pill ${f.severity}">${f.severity}</span><button class="btn ghost sm" id="closeDrawer">Close</button></div>
    <h2>${esc(f.title)}</h2>
    <div class="row"><span class="pill ${f.status}">${f.status.replace("_", " ")}</span><span class="muted">confidence ${f.confidence}%</span></div>
    ${f.cve ? `<div class="kv"><div class="k">CVE / Exploit</div><div class="v">
        <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" rel="noopener">${esc(f.cve)} (NVD)</a>
        &nbsp;·&nbsp;<a href="https://www.exploit-db.com/search?cve=${esc(f.cve)}" target="_blank" rel="noopener">Exploit-DB</a>
      </div></div>` : ""}
    ${kv("Affected", f.affected || "—")}
    ${kv("Description", esc(f.description || "—"))}
    <div class="kv"><div class="k">Evidence / PoC</div><div class="codeblock">${esc(f.evidence || "(none)")}</div></div>
    ${kv("Remediation", esc(f.remediation || "—"))}
    ${f.fix_config ? `<div class="kv"><div class="k" style="color:var(--confirmed)">Config fix (siap pakai)</div><div class="codeblock">${esc(f.fix_config)}</div></div>` : ""}
    ${f.fix_steps ? `<div class="kv"><div class="k" style="color:var(--confirmed)">Langkah apply &amp; verify</div><div class="codeblock">${esc(f.fix_steps)}</div></div>` : ""}
    ${kv("Corroborating sources", (f.sources || []).join(", ") || "—")}
    <div class="section-title"><h3>Human validation (final gate)</h3></div>
    <div class="row">
      <button class="btn sm" data-set="confirmed">Confirm</button>
      <button class="btn ghost sm" data-set="likely">Likely</button>
      <button class="btn ghost sm" data-set="needs_review">Needs review</button>
      <button class="btn danger sm" data-set="false_positive">False positive</button>
    </div>`;
  $("#drawerBg").classList.add("open"); d.classList.add("open");
  $("#closeDrawer").addEventListener("click", closeDrawer);
  d.querySelectorAll("[data-set]").forEach((b) => b.addEventListener("click", () => setFindingStatus(id, b.dataset.set)));
}
function kv(k, v) { return `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`; }
function closeDrawer() { $("#drawerBg").classList.remove("open"); $("#drawer").classList.remove("open"); }

async function setFindingStatus(id, status) {
  await api(`/api/findings/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) });
  const f = State.findings.find((x) => x.id === id); if (f) f.status = status;
  closeDrawer(); viewFindings(); toast("Verdict: " + status.replace("_", " "));
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
      $("#cpCur").value = ""; $("#cpNew").value = ""; toast("Password updated");
    } catch (e) { $("#cpErr").textContent = e.message; }
  });
}

/* ----------------------------- Reports ----------------------------- */
async function viewReports() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `
    <div class="section-title"><h3>VAPT report — ${esc(t.value)}</h3><div class="spacer"></div>
      <button class="btn sm" id="openReport">⎙ Open full report (print / PDF)</button></div>
    <div class="hint">Laporan AI mencakup ringkasan eksekutif, rincian temuan, bukti/PoC, confidence, dan
      <b>konfigurasi perbaikan konkret</b> (siap pakai) per temuan. Buka laporan lalu "Print / Save PDF".</div>
    <div class="card" style="margin-top:14px;padding:0;overflow:hidden">
      <iframe id="reportFrame" style="width:100%;height:70vh;border:0;background:#fff" title="report preview"></iframe>
    </div>`;
  $("#openReport").addEventListener("click", () => {
    window.open(`/report/${t.id}?token=${encodeURIComponent(State.token)}`, "_blank");
  });
  // Inline preview via authenticated fetch (iframe can't send Authorization header).
  try {
    const res = await fetch(`/api/targets/${t.id}/report`, { headers: { Authorization: "Bearer " + State.token } });
    const htmlStr = await res.text();
    $("#reportFrame").srcdoc = htmlStr;
  } catch (e) { toast("Report preview failed: " + e.message); }
}

/* ----------------------------- Domain Health (module) ----------------------------- */
async function viewDomainHealth() {
  const t = currentTarget();
  const c = $("#content");
  if (!t) { c.innerHTML = emptyNoTarget(); bindEmpty(); return; }
  c.innerHTML = `<div class="muted">Probing ${esc(t.value)} (DNS · TLS · HTTP)…</div>`;
  try {
    const h = await api(`/api/modules/domain-health/${t.id}`);
    const gradeColor = h.score >= 85 ? "var(--ok)" : h.score >= 60 ? "var(--warn)" : "var(--critical)";
    c.innerHTML = `
      <div class="grid stats">
        ${statCard("Health score", h.score + "/100", h.issues.length + " issue(s)", gradeColor)}
        ${statCard("TLS", (h.tls.protocol || "—"), h.tls.cipher || (h.tls.error ? "probe error" : ""), h.tls.protocol && h.tls.protocol >= "TLSv1.2" ? "var(--ok)" : "var(--warn)")}
        ${statCard("DNS A-records", (h.dns.resolved || []).length, (h.dns.resolved || []).join(", ") || h.dns.error || "—", "var(--muted)")}
      </div>
      <div class="section-title"><h3>TLS / certificate</h3></div>
      <div class="card"><table>
        <tr><th>Protocol</th><td>${esc(h.tls.protocol || "—")}</td></tr>
        <tr><th>Cipher</th><td>${esc(h.tls.cipher || "—")}</td></tr>
        <tr><th>Issuer</th><td>${esc(h.tls.issuer || "—")}</td></tr>
        <tr><th>Expires</th><td>${esc(h.tls.expires || "—")}</td></tr>
      </table></div>
      <div class="section-title"><h3>HTTP probe (httpx)</h3></div>
      <div class="card"><div class="codeblock">${esc(h.http.raw || "—")}</div></div>
      <div class="section-title"><h3>Issues</h3></div>
      <div class="card">${h.issues.length ? h.issues.map((i) => `<div class="row" style="margin:6px 0"><span class="pill ${i.sev}">${i.sev}</span><span>${esc(i.msg)}</span></div>`).join("") : `<div class="muted">No issues detected.</div>`}</div>`;
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
