const $ = (s) => document.querySelector(s);
const order = { FOUND: 0, UNCERTAIN: 1, UNVERIFIABLE: 2, ERROR: 3, NOT_FOUND: 4 };
let es = null;
let liveScanFinished = false;
let authState = { required: false, authenticated: true, csrf_token: null, user: null };
const rawFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const method = (init.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && authState.csrf_token) {
    const headers = new Headers(init.headers || {});
    headers.set("X-CSRF-Token", authState.csrf_token);
    init = { ...init, headers };
  }
  const response = await rawFetch(input, init);
  if (response.status === 401) showLogin();
  return response;
};

function showLogin(message = "") {
  $("#auth-gate").hidden = false;
  document.body.classList.add("auth-locked");
  $("#login-status").textContent = message;
}

function hideLogin() {
  $("#auth-gate").hidden = true;
  document.body.classList.remove("auth-locked");
}

function applyRole() {
  const role = (authState.user || {}).role || "admin";
  document.querySelectorAll("[data-role='admin']").forEach(el => el.hidden = role !== "admin");
  document.querySelectorAll("[data-role='review']").forEach(el => el.hidden = !["admin", "reviewer"].includes(role));
  document.querySelectorAll("[data-role='scan']").forEach(el => el.hidden = role === "reviewer");
  const liveScanAvailable = role !== "reviewer" && authState.live_scans_enabled !== false;
  $("#go").hidden = !liveScanAvailable;
  $("#save").classList.toggle("primary-action", !liveScanAvailable);
  $("#save").classList.toggle("secondary-action", liveScanAvailable);
  if (authState.required && authState.user) {
    $("#account").hidden = false;
    const accountName = authState.user.display_name || authState.user.username;
    $("#account-name").textContent = `${accountName} · ${role}`;
    $("#account .account-avatar").textContent = accountName.slice(0, 1).toUpperCase();
  } else {
    $("#account").hidden = true;
  }
  document.querySelectorAll(".nav-curtain").forEach((curtain) => {
    curtain.hidden = ![...curtain.querySelectorAll("button[data-tab]")]
      .some((button) => !button.hidden);
  });
  const active = document.querySelector("#tabs button.active");
  if (active && active.hidden) {
    const fallback = [...document.querySelectorAll("#tabs button")].find(button => !button.hidden);
    if (fallback) fallback.click();
  }
}

async function bootstrapAuth() {
  const response = await rawFetch("/api/auth/status", { headers: { "Accept": "application/json" } });
  authState = await response.json();
  applyRole();
  if (authState.required && !authState.authenticated) showLogin(); else hideLogin();
}

// --- tab switching ---------------------------------------------------------
function loadTabData(tab) {
  if (tab === "investigations") { loadTargets(); loadRuns(); }
  if (tab === "review") loadReview();
  if (tab === "timeline") loadChanges();
  if (tab === "sources") loadSources();
  if (tab === "insights") { loadInsights(); loadRuleCatalogue(); loadCalibration(); }
  if (tab === "reasoning") loadReasoning();
  if (tab === "confidence") loadAnalytics();
  if (tab === "keys") { loadKeys(); loadModules(); }
  if (tab === "governance") loadGovernance();
  if (tab === "administration") { loadExpansion(); loadUsers(); }
}

function activateTab(button, updateHash = true) {
  if (!button || button.hidden) return;
  const curtain = button.closest(".nav-curtain");
  if (curtain) curtain.open = true;
  document.querySelectorAll("#tabs button").forEach((item) => {
    const selected = item === button;
    item.classList.toggle("active", selected);
    if (selected) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `panel-${button.dataset.tab}`);
  });
  const title = button.dataset.title || button.textContent.trim();
  $("#page-title").textContent = title;
  $("#page-context").textContent = button.dataset.context || "Workspace";
  document.title = `${title} - Specter`;
  if (updateHash) history.replaceState(null, "", `#${button.dataset.tab}`);
  loadTabData(button.dataset.tab);
}

document.querySelectorAll(".nav-curtain").forEach((curtain) => {
  curtain.addEventListener("toggle", () => {
    if (!curtain.open) return;
    document.querySelectorAll(".nav-curtain").forEach((other) => {
      if (other !== curtain) other.open = false;
    });
  });
});

document.querySelectorAll("#tabs button").forEach((button) => {
  button.addEventListener("click", () => activateTab(button));
});

window.addEventListener("hashchange", () => {
  const tab = location.hash.slice(1);
  activateTab(document.querySelector(`#tabs button[data-tab="${CSS.escape(tab)}"]`), false);
});

function setScanStage(stage, { focus = false } = {}) {
  const selectedButton = document.querySelector(`[data-scan-view="${stage}"]`);
  if (!selectedButton) return;
  document.querySelectorAll("[data-scan-view]").forEach((button) => {
    const selected = button === selectedButton;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  document.querySelectorAll("[data-scan-stage]").forEach((panel) => {
    const selected = panel.dataset.scanStage === stage;
    panel.hidden = !selected;
    panel.classList.toggle("active", selected);
  });
  if (stage === "activity") {
    requestAnimationFrame(() => {
      sizeLiveCanvas();
      scheduleLiveGraph();
    });
  }
  if (focus) selectedButton.focus();
}

document.querySelectorAll("[data-scan-view]").forEach((button) => {
  button.addEventListener("click", () => setScanStage(button.dataset.scanView));
  button.addEventListener("keydown", (event) => {
    const tabs = [...document.querySelectorAll("[data-scan-view]")];
    const current = tabs.indexOf(button);
    let next = current;
    if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;
    event.preventDefault();
    setScanStage(tabs[next].dataset.scanView, { focus: true });
  });
});
setScanStage("start");

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const response = await rawFetch("/api/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: form.get("username"), password: form.get("password") }),
  });
  const data = await response.json();
  if (!response.ok) { showLogin(data.error || "Sign-in failed"); return; }
  await bootstrapAuth();
  event.currentTarget.reset();
});

$("#logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  });
  authState = { required: true, authenticated: false, csrf_token: null, user: null };
  showLogin();
});

function formParams() {
  const data = new FormData($("#q"));
  const params = new URLSearchParams();
  const obj = {};
  for (const [k, v] of data.entries()) if (v.trim()) { params.set(k, v.trim()); obj[k] = v.trim(); }
  return { params, obj };
}

const identityFields = ["name", "username", "email", "phone", "url", "domain", "ip_address"];
const identityLabels = {
  name: "name", username: "username", email: "email", phone: "phone",
  url: "profile", domain: "domain", ip_address: "IP address",
};

function currentIdentityClues() {
  const data = new FormData($("#q"));
  return identityFields
    .map((name) => [name, String(data.get(name) || "").trim()])
    .filter(([, value]) => value);
}

function updateClueSummary() {
  const root = $("#intake-preview");
  const clues = currentIdentityClues();
  root.dataset.kind = clues.length > 1 ? "multiple" : clues.length ? "explicit" : "";
  if (!clues.length) {
    root.innerHTML = "<strong>No clues added</strong><span>Add any details you already know.</span>";
    return;
  }
  const labels = clues.map(([name]) => identityLabels[name]);
  root.innerHTML = `<strong>${clues.length} ${clues.length === 1 ? "clue" : "clues"} for one subject</strong>`
    + `<span>${esc(labels.join(" · "))}</span>`;
}

document.querySelectorAll("#q [name]").forEach((input) => {
  input.addEventListener("input", updateClueSummary);
});
updateClueSummary();

function renderIntake(intake) {
  const root = $("#intake-preview");
  if (!intake) {
    updateClueSummary();
    return;
  }
  const fields = Object.entries(intake.query_fields || {})
    .filter(([name, value]) => identityFields.includes(name) && value);
  if (fields.length) {
    const labels = fields.map(([name]) => identityLabels[name]);
    root.dataset.kind = fields.length > 1 ? "multiple" : "explicit";
    root.innerHTML = `<strong>${fields.length} ${fields.length === 1 ? "clue" : "clues"} linked for research</strong>`
      + `<span>${esc(labels.join(" · "))}</span>`;
    return;
  }
  const kind = String(intake.kind || "input").replace("ip_address", "IP address");
  const derived = (intake.derived_fields || []).length
    ? ` · also derived ${intake.derived_fields.map(item => esc(String(item).replace("ip_address", "IP address"))).join(", ")}`
    : "";
  root.dataset.kind = String(intake.kind || "");
  root.innerHTML = `<strong>Interpreted as ${esc(kind)}</strong>`
    + `<span>${esc(intake.normalized || "")} · ${Math.round((intake.confidence || 0) * 100)}% classifier confidence${derived}</span>`;
}

const verdictCounts = { ALL: 0, FOUND: 0, UNCERTAIN: 0, UNVERIFIABLE: 0, ERROR: 0, NOT_FOUND: 0 };
let activeVerdictFilter = "ALL";

function setScanStatus(message, tone = "neutral") {
  const status = $("#status");
  status.textContent = message;
  status.dataset.tone = tone;
}

function desktopNotify(title, message, level = "info") {
  window.dispatchEvent(new CustomEvent("specter:notification", {
    detail: { title, message, level },
  }));
}

function updateVerdictCounts() {
  document.querySelectorAll("[data-verdict-count]").forEach((item) => {
    item.textContent = verdictCounts[item.dataset.verdictCount] || 0;
  });
  $("#scan-evidence-count").textContent = verdictCounts.ALL;
}

function applyVerdictFilter() {
  $("#results").querySelectorAll("tbody tr").forEach((row) => {
    row.hidden = activeVerdictFilter !== "ALL" && row.dataset.verdict !== activeVerdictFilter;
  });
}

function selectVerdictFilter(filter) {
  activeVerdictFilter = filter;
  document.querySelectorAll("[data-verdict-filter]").forEach((button) => {
    const selected = button.dataset.verdictFilter === filter;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  applyVerdictFilter();
}

function resetResults() {
  $("#results").querySelector("tbody").innerHTML = "";
  $("#summary").innerHTML = "";
  $("#profile").innerHTML = "";
  $("#profile").hidden = true;
  Object.keys(verdictCounts).forEach((key) => { verdictCounts[key] = 0; });
  updateVerdictCounts();
  selectVerdictFilter("ALL");
  $("#results").hidden = true;
  $("#results-empty").hidden = false;
  $("#live-reasoning").hidden = true;
  $("#live-reasoning").innerHTML = "";
  resetLiveGraph();
}

document.querySelectorAll("[data-verdict-filter]").forEach((button) => {
  button.addEventListener("click", () => selectVerdictFilter(button.dataset.verdictFilter));
});

// --- live SSE search -------------------------------------------------------
$("#q").addEventListener("submit", (e) => {
  e.preventDefault();
  if (es) es.close();
  const { params } = formParams();
  if ([...params].length === 0) { setScanStatus("Add at least one identity clue.", "error"); return; }
  resetResults();
  beginResearchRoom();
  setScanStage("activity");
  $("#go").disabled = true;
  setScanStatus("Researching…", "busy");
  setLiveGraphStatus("Streaming", "busy");
  liveScanFinished = false;
  let hits = 0;
  es = new EventSource("/api/search?" + params.toString());
  es.onmessage = (msg) => {
    let ev;
    try { ev = JSON.parse(msg.data); }
    catch (_) {
      liveScanFinished = true;
      setScanStatus("The live stream returned invalid data.", "error");
      failLiveGraph("Invalid stream data");
      desktopNotify("Investigation failed", "The live stream returned invalid data.", "error");
      $("#go").disabled = false;
      es.close();
      return;
    }
    if (ev.type === "activity") { ingestLiveActivity(ev.activity); }
    else if (ev.type === "intake") { renderIntake(ev.intake); }
    else if (ev.type === "finding") {
      addRow(ev.finding);
      if (ev.finding.verdict === "FOUND")
        setScanStatus(`Researching… ${++hits} confirmed`, "busy");
    } else if (ev.type === "summary") { renderSummary(ev.summary); }
    else if (ev.type === "reasoning") { renderReasoning(ev.reasoning, "#live-reasoning"); }
    else if (ev.type === "done") {
      liveScanFinished = true;
      setScanStatus(`Done — ${ev.hits}/${ev.total} confirmed.`, "success");
      finishLiveGraph();
      setScanStage("evidence");
      desktopNotify("Investigation complete", `${ev.hits}/${ev.total} findings confirmed.`);
      $("#go").disabled = false;
      es.close();
    } else if (ev.type === "error") {
      liveScanFinished = true;
      setScanStatus("Error: " + ev.message, "error");
      failLiveGraph(ev.message);
      desktopNotify("Investigation failed", ev.message, "error");
      $("#go").disabled = false;
      es.close();
    }
  };
  es.onerror = () => {
    if (liveScanFinished) return;
    liveScanFinished = true;
    setScanStatus("Live scan disconnected.", "error");
    failLiveGraph("Stream disconnected");
    desktopNotify("Investigation interrupted", "The live scan disconnected.", "warning");
    $("#go").disabled = false;
    es.close();
  };
});

// --- persisted scan --------------------------------------------------------
async function loadJobActivity(jobId, trace) {
  let hasMore = true;
  while (hasMore) {
    const response = await fetch(`/api/jobs/${jobId}/activity?after=${trace.cursor}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || data.error || "Job activity unavailable");
    if (trace.attempt !== null && data.attempts !== trace.attempt) {
      trace.attempt = data.attempts;
      trace.cursor = 0;
      resetLiveGraph();
      continue;
    }
    for (const activity of data.activities || []) ingestLiveActivity(activity);
    trace.cursor = data.cursor || trace.cursor;
    hasMore = Boolean(data.has_more);
  }
}

async function waitForJob(jobId) {
  const trace = { cursor: 0, attempt: null };
  for (;;) {
    const response = await fetch(`/api/jobs/${jobId}`);
    const job = await response.json();
    if (!response.ok) throw new Error(job.detail || job.error || "Job status unavailable");
    if (trace.attempt !== job.attempts) {
      if (trace.attempt !== null) resetLiveGraph();
      trace.attempt = job.attempts;
      trace.cursor = 0;
    }
    await loadJobActivity(jobId, trace);
    if (job.status === "done") { finishLiveGraph(); return job; }
    if (job.status === "error") {
      failLiveGraph(job.error || "Scan failed");
      throw new Error(job.error || "Scan failed");
    }
    setLiveGraphStatus(job.status === "leased" ? `Attempt ${job.attempts}` : "Queued", "busy");
    setScanStatus(`Queued scan #${jobId} · attempt ${job.attempts || 0}`, "busy");
    await new Promise(resolve => setTimeout(resolve, 500));
  }
}

$("#save").addEventListener("click", async () => {
  if (!$("#q").reportValidity()) return;
  const { obj } = formParams();
  if (Object.keys(obj).length === 0) { setScanStatus("Add at least one identity clue.", "error"); return; }
  liveScanFinished = true;
  if (es) es.close();
  resetResults();
  beginResearchRoom();
  setScanStage("activity");
  const button = $("#save");
  button.disabled = true;
  try {
    setScanStatus("Running and saving…", "busy");
    setLiveGraphStatus("Running", "busy");
    const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });
    const d = await r.json();
    if (!r.ok) {
      const message = d.detail || d.error || "Scan could not start.";
      setScanStatus(message, "error");
      desktopNotify("Investigation failed", message, "error");
      return;
    }
    if (r.status === 202) {
      renderIntake(d.intake);
      setScanStatus(`Queued scan #${d.job_id}`, "busy");
      const job = await waitForJob(d.job_id);
      const hits = (job.stats || {}).hits || 0;
      setScanStatus(`Saved run #${job.run_id}: ${hits} confirmed.`, "success");
      desktopNotify("Investigation saved", `Run #${job.run_id}: ${hits} findings confirmed.`);
      renderProfile((job.stats || {}).profile);
      renderReasoning((job.stats || {}).reasoning, "#live-reasoning");
      setScanStage("evidence");
      return;
    }
    renderIntake(d.intake);
    setScanStatus(`Saved run #${d.run_id}: ${d.hits} confirmed, ${d.summary.identities} identities, ${d.changes.length} change(s).`, "success");
    desktopNotify("Investigation saved", `Run #${d.run_id}: ${d.hits} findings confirmed.`);
    for (const activity of d.activity || []) ingestLiveActivity(activity);
    finishLiveGraph();
    renderSummary(d.summary);
    renderReasoning(d.reasoning, "#live-reasoning");
    setScanStage("evidence");
  } catch (error) {
    setScanStatus(`Scan failed: ${error.message}`, "error");
    failLiveGraph(error.message);
    desktopNotify("Investigation failed", error.message, "error");
  } finally {
    button.disabled = false;
  }
});

function breakdownHtml(bd) {
  if (!bd || !bd.contributions) return "";
  const sign = (d) => (d >= 0 ? "+" : "") + d.toFixed(2);
  const rows = bd.contributions
    .map((c) => `<span class="bd-row">${sign(c.delta)} <b>${esc(c.term)}</b> — ${esc(c.reason)}</span>`).join("");
  let shadow = "";
  if (bd.shadow_total != null && bd.shadow_total !== bd.total)
    shadow = `<span class="bd-shadow">independence-adjusted: ${bd.shadow_total.toFixed(2)}`
      + (bd.shadow_note ? ` — ${esc(bd.shadow_note)}` : "") + `</span>`;
  return `<details class="why"><summary>why ${bd.total.toFixed(2)}</summary>`
    + `<div class="bd"><span class="bd-row">base ${bd.base.toFixed(2)}</span>${rows}`
    + `<span class="bd-row bd-total">= ${bd.total.toFixed(2)}</span>${shadow}</div></details>`;
}

function traceHtml(t) {
  if (!t) return "";
  const kv = [];
  if (t.site_rule) kv.push(`rule: ${esc(t.site_rule.name)} (${esc(t.site_rule.error_type)})`);
  if (t.request) kv.push(`request: HTTP ${t.request.status} → ${esc(t.request.final_url || "")}`
    + (t.request.elapsed_ms ? ` (${t.request.elapsed_ms}ms)` : ""));
  kv.push("baseline: " + (t.baseline ? `HTTP ${t.baseline.status}, fp ${esc((t.baseline.fingerprint || "").slice(0, 8))}` : "none"));
  if (t.thresholds) kv.push(`thresholds: FOUND≥${t.thresholds.found_confidence}, UNCERTAIN≥${t.thresholds.uncertain_confidence}`);
  kv.push(`dataset ${esc((t.dataset_sha256 || "").slice(0, 8))} · tool ${esc(t.tool_version)}`
    + (t.deterministic ? " · deterministic" : ""));
  return `<details class="why trace"><summary>trace</summary><div class="bd">`
    + kv.map((x) => `<span class="bd-row">${x}</span>`).join("") + `</div></details>`;
}

function addRow(f) {
  const tr = document.createElement("tr");
  tr.className = f.verdict;
  tr.dataset.verdict = f.verdict;
  const url = safeHttpUrl(f.url);
  const label = url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(f.label)}</a>` : esc(f.label);
  const reasons = (f.reasons || []).map(esc).join("<br>") + breakdownHtml(f.breakdown) + traceHtml(f.trace);
  tr.innerHTML = `<td><span class="v ${f.verdict}">${f.verdict}</span></td><td>${f.confidence.toFixed(2)}</td>
    <td>${esc(f.source)}</td><td>${label}</td><td class="reasons">${reasons}</td>`;
  const tbody = $("#results").querySelector("tbody");
  const rows = [...tbody.children];
  const idx = rows.findIndex((row) => order[row.className] > order[f.verdict]);
  if (idx === -1) tbody.appendChild(tr); else tbody.insertBefore(tr, rows[idx]);
  verdictCounts.ALL += 1;
  if (Object.hasOwn(verdictCounts, f.verdict)) verdictCounts[f.verdict] += 1;
  updateVerdictCounts();
  $("#results").hidden = false;
  $("#results-empty").hidden = true;
  applyVerdictFilter();
}

function renderSummary(s) {
  renderProfile(s && s.profile);
  if (!s || !s.clusters || !s.clusters.length) { $("#summary").innerHTML = ""; return; }
  let html = `<h2>Identities (${s.identities})</h2>`;
  for (const c of s.clusters) {
    const sig = Object.entries(c.signals || {}).map(([k, v]) => `${k}: ${[].concat(v).join(", ")}`).join(" · ") || "—";
    const flags = (c.flags && c.flags.length) ? `<span class="flag">${esc(c.flags.join(", "))}</span>` : "";
    const co = c.corroboration;
    let corro = "";
    if (co) {
      const title = co.redundant && co.redundant.length ? ` title="redundant: ${esc(co.redundant.join(", "))}"` : "";
      const inflated = co.inflation > 1 ? ` · ${co.inflation}× inflated` : "";
      const cls = co.label === "corroborated" ? "corro-ok" : "corro-weak";
      corro = `<span class="corro ${cls}"${title}>${co.label} · ${co.independent_classes} indep.${inflated}</span>`;
    }
    html += `<div class="cluster"><b>#${c.id} ${esc(c.label||"")}</b> · score ${c.score} · ${c.found} found / ${c.uncertain} uncertain ${flags} ${corro}<br><small>${esc(sig)}</small></div>`;
  }
  $("#summary").innerHTML = html;
}

function profileValue(value) {
  if (Array.isArray(value)) return value.map(item => String(item)).join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value == null ? "" : value);
}

function renderProfile(profile) {
  const root = $("#profile");
  if (!profile) {
    root.hidden = true;
    root.innerHTML = "";
    return;
  }
  const status = ["corroborated", "partial", "unresolved"].includes(profile.status)
    ? profile.status : "unresolved";
  const coverage = (profile.coverage || []).map(item => {
    const state = ["confirmed", "inconclusive", "checked", "not_searched"].includes(item.state)
      ? item.state : "not_searched";
    const detail = item.checks
      ? `${item.confirmed || 0} confirmed · ${item.candidates || 0} candidate · ${item.checks} checks`
      : "Not reached from this starting point";
    return `<div class="coverage-item ${state}"><strong>${esc(item.label)}</strong>`
      + `<span>${esc(detail)}</span></div>`;
  }).join("");
  const identifiers = (profile.identifiers || []).map(item => {
    const standing = ["confirmed", "provided", "candidate"].includes(item.standing)
      ? item.standing : "candidate";
    return `<div class="profile-fact"><span>${esc(String(item.type).replaceAll("_", " "))}</span>`
      + `<b>${esc(profileValue(item.value))}</b><span class="fact-standing ${standing}">${standing}</span></div>`;
  }).join("");
  const accounts = (profile.accounts || []).map(item => {
    const standing = item.standing === "confirmed" ? "confirmed" : "candidate";
    const url = safeHttpUrl(item.url);
    const value = url
      ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(item.label)}</a>`
      : `<b>${esc(item.label)}</b>`;
    return `<div class="profile-account"><span>${esc(item.source)}</span>${value}`
      + `<span class="fact-standing ${standing}">${standing}</span></div>`;
  }).join("");
  const detailRows = Object.entries(profile.details || {}).flatMap(([group, rows]) =>
    (rows || []).map(item => `<div class="profile-fact"><span>${esc(String(item.name).replaceAll("_", " "))}</span>`
      + `<b>${esc(profileValue(item.value))}</b><span class="fact-standing">${esc(group)}</span></div>`)
  ).join("");
  const gaps = (profile.gaps || []).map(item => `<li>${esc(item)}</li>`).join("");
  root.hidden = false;
  root.innerHTML = `<div class="profile-head"><div><span class="profile-status ${status}">${esc(status)}</span>`
    + `<h2>${esc(profile.title || "Profile synthesis")}</h2><p>${esc(profile.assessment)}</p></div>`
    + `<div class="profile-confidence"><strong>${Math.round((profile.confidence || 0) * 100)}%</strong>`
    + `<span>evidence confidence</span></div></div>`
    + `<div class="profile-coverage">${coverage}</div>`
    + `<div class="profile-columns"><section class="profile-section"><h3>Identifiers</h3>`
    + `<div class="profile-list">${identifiers || "<span class='tag'>No identifiers established.</span>"}</div></section>`
    + `<section class="profile-section"><h3>Public accounts</h3><div class="profile-list">`
    + `${accounts || "<span class='tag'>No account confirmed.</span>"}</div></section></div>`
    + (detailRows ? `<section class="profile-section"><h3>Established details</h3><div class="profile-list">${detailRows}</div></section>` : "")
    + `<section class="profile-section"><h3>Unresolved gaps</h3><ul class="profile-gaps">`
    + `${gaps || "<li>No material gap was recorded.</li>"}</ul></section>`
    + `<p class="profile-note">${esc(profile.completeness_note || "")}</p>`;
}

function renderReasoning(report, target = "#reasoning-view") {
  const root = $(target);
  if (!root) return;
  if (!report) {
    root.hidden = false;
    root.innerHTML = `<div class="empty-state compact-empty"><strong>No reasoning recorded</strong>`
      + `<span>This run predates investigation planning.</span></div>`;
    return;
  }
  const state = report.evidence_state || {};
  const verdicts = state.verdicts || {};
  const actions = (report.next_actions || []).map((action) => {
    const priority = ["critical", "high", "medium", "low"].includes(action.priority)
      ? action.priority : "medium";
    const execution = ["automatic", "manual", "approval"].includes(action.execution)
      ? action.execution : "manual";
    const actionStatus = ["ready", "needs_review", "blocked"].includes(action.status)
      ? action.status.replace("_", " ") : "needs review";
    const requires = (action.requires || []).length
      ? `<div class="action-requires"><span>Requires</span>${(action.requires || []).map(item => `<b>${esc(item)}</b>`).join("")}</div>`
      : "";
    const inputs = (action.inputs || []).length
      ? `<details class="why"><summary>inputs</summary><div class="bd">${action.inputs.map(item => `<span class="bd-row">${esc(item)}</span>`).join("")}</div></details>`
      : "";
    return `<article class="reasoning-action priority-${priority}">`
      + `<div class="action-heading"><span class="priority-label">${esc(priority)}</span>`
      + `<span class="execution-label">${esc(execution)}</span><span class="action-status">${esc(actionStatus)}</span></div>`
      + `<h4>${esc(action.title)}</h4><p>${esc(action.rationale)}</p>`
      + `<span class="action-confidence">${Math.round((action.confidence || 0) * 100)}% confidence</span>`
      + requires + inputs + `</article>`;
  }).join("");
  const uncertainties = (report.uncertainties || []).length
    ? `<section class="reasoning-notes"><h4>Uncertainty</h4><ul>${report.uncertainties.map(item => `<li>${esc(item)}</li>`).join("")}</ul></section>`
    : `<section class="reasoning-notes"><h4>Uncertainty</h4><p>No material uncertainty was identified.</p></section>`;
  const guardrails = (report.guardrails || []).map(item => `<li>${esc(item)}</li>`).join("");
  const decisions = (report.decisions || []).map((decision) => {
    const prioritized = (decision.prioritized || []).map(item =>
      `<span class="bd-row"><b>${esc(item.module)}</b> on ${esc(item.artifact)} · ${esc(item.score)}</span>`
    ).join("");
    return `<div class="decision-wave"><b>Wave ${esc(decision.wave)}</b>`
      + `<span>${esc(decision.objective)} · ${esc(decision.candidate_dispatches)} candidates · ${esc(decision.remaining_requests)} requests remaining</span>`
      + prioritized + `</div>`;
  }).join("");
  root.hidden = false;
  root.innerHTML = `<div class="reasoning-overview"><div><span class="eyebrow">Current objective</span>`
    + `<h3>${esc(report.objective)}</h3><p>${esc(report.assessment)}</p></div>`
    + `<div class="reasoning-confidence"><strong>${Math.round((report.confidence || 0) * 100)}%</strong><span>assessment confidence</span></div></div>`
    + `<div class="reasoning-metrics"><span><b>${esc(state.findings || 0)}</b> findings</span>`
    + `<span><b>${esc(verdicts.FOUND || 0)}</b> confirmed</span><span><b>${esc(state.artifacts || 0)}</b> artifacts</span>`
    + `<span><b>${esc(state.independent_classes || 0)}</b> evidence classes</span></div>`
    + uncertainties + `<div class="reasoning-section-heading"><h4>Next actions</h4><span>${actions ? (report.next_actions || []).length : 0} proposed</span></div>`
    + `<div class="reasoning-actions">${actions}</div>`
    + `<details class="reasoning-trace"><summary>Decision trace and guardrails</summary>`
    + `<div class="decision-waves">${decisions || "<span class='tag'>No traversal waves recorded.</span>"}</div>`
    + `<ul>${guardrails}</ul></details>`;
}

// --- dashboard loaders -----------------------------------------------------
async function table(target, url, cols, mapRow) {
  const rows = await (await fetch(url)).json();
  if (!rows.length) { $(target).innerHTML = "<p class='tag'>No data yet.</p>"; return; }
  let h = "<table><thead><tr>" + cols.map((c) => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
  h += rows.map((r) => "<tr>" + mapRow(r).map((c) => `<td>${c}</td>`).join("") + "</tr>").join("");
  $(target).innerHTML = h + "</tbody></table>";
}

const loadTargets = () => table("#targets", "/api/targets", ["id", "label", "watch", "query"],
  (t) => [t.id, esc(t.label||""), t.watchlist ? "✓" : "", esc(JSON.stringify(t.query))]);

const loadRuns = () => table("#runs", "/api/runs", ["run", "target", "status", "stats", "provenance"],
  (r) => [r.id, r.target_id, r.status, esc(JSON.stringify(r.stats)), provenanceHtml(r.provenance)]);

function provenanceHtml(p) {
  if (!p) return "<span class='tag'>—</span>";
  const e = p.engine || {};
  const t = p.thresholds || {};
  const rows = [
    `tool ${esc(p.tool_version)} · py ${esc(p.python)}${p.deterministic ? " · deterministic" : ""}`,
    `dataset sha ${esc((p.sites_dataset_sha256 || "").slice(0, 12))}`,
    `engine: scope ${esc(e.scope_mode)} · depth ${e.max_depth} · ${e.passive_only ? "passive" : "active"}`
      + ` · independence ${e.confidence_independence ? "on" : "shadow"}`,
    `thresholds: FOUND≥${t.found_confidence} · merge ${t.er_merge_threshold}`,
  ];
  return `<details class="why"><summary>stamp</summary><div class="bd">`
    + rows.map((x) => `<span class="bd-row">${x}</span>`).join("") + `</div></details>`;
}

const loadChanges = () => table("#changes", "/api/changes", ["when","kind","source","label","detail"],
  (c) => [c.created_at.replace("T"," ").slice(0,16), badge(c.kind), esc(c.source||""), esc(c.label||""), esc(JSON.stringify(c.detail))]);

const loadSources = () => table("#sources", "/api/sources",
  ["source","interaction","data sent","reliability","runtime","canary"],
  (s) => {
    const c = s.contract || {};
    const check = s.latest_check
      ? `${badge(s.latest_check.status)}<br><small>${esc(s.latest_check.created_at.slice(0,10))}</small>`
      : `<span class="tag">not run</span>`;
    return [esc(s.name), esc(c.interaction||""), esc((c.data_sent||[]).join(", ")||"none"),
            bar(s.reliability), `${s.successes} ok / ${s.failures} fail · ${badge(s.breaker_state)}`, check];
  });

async function loadReview() {
  let run = $("#review-run").value.trim();
  if (!run) {
    const runs = await (await fetch("/api/runs")).json();
    if (!runs.length) { $("#review-status").textContent = "No saved runs yet."; return; }
    run = runs[0].id;
    $("#review-run").value = run;
  }
  const response = await fetch(`/api/runs/${run}/observations`);
  const data = await response.json();
  if (!response.ok) { $("#review-status").textContent = data.error || "Unable to load run."; return; }
  $("#review-status").textContent = `run #${run}: ${data.observations.length} observations`;
  if (!data.observations.length) {
    $("#review-observations").innerHTML = "<p class='tag'>No observations in this run.</p>";
    return;
  }
  let html = "<table><thead><tr><th>automated</th><th>source</th><th>evidence</th><th>review</th></tr></thead><tbody>";
  for (const o of data.observations) {
    const current = o.review ? `<span class="review-${esc(o.review.decision)}">${esc(o.review.decision)}</span>` : "unreviewed";
    html += `<tr><td><span class="v ${o.verdict}">${o.verdict}</span><br>${(+o.confidence).toFixed(2)}</td>`
      + `<td>${esc(o.source)}</td><td><b>${esc(o.label)}</b><br><small class="tag">${esc((o.reasons||[]).join(" · "))}</small></td>`
      + `<td><div class="review-current">${current}</div><input class="review-note" data-observation="${o.id}" maxlength="4000" placeholder="review note" value="${esc((o.review||{}).note||"")}" />`
      + `<div class="review-actions" data-observation="${o.id}"><button data-decision="accepted">Accept</button><button data-decision="rejected" class="danger">Reject</button><button data-decision="unresolved" class="secondary">Unresolved</button></div></td></tr>`;
  }
  $("#review-observations").innerHTML = html + "</tbody></table>";
  document.querySelectorAll(".review-actions button").forEach((button) => {
    button.addEventListener("click", () => saveReview(button));
  });
}

async function saveReview(button) {
  const observation = button.parentElement.dataset.observation;
  const note = document.querySelector(`.review-note[data-observation="${observation}"]`).value;
  const response = await fetch(`/api/observations/${observation}/review`, {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({decision:button.dataset.decision, note, reviewer:"local"}),
  });
  const data = await response.json();
  $("#review-status").textContent = response.ok ? `Recorded review #${data.id}.` : `Error: ${data.error||response.status}`;
  if (response.ok) loadReview();
}

$("#review-load").addEventListener("click", loadReview);

async function loadGovernance() {
  const [targets, audit] = await Promise.all([
    fetch("/api/targets").then(r=>r.json()), fetch("/api/audit").then(r=>r.json()),
  ]);
  if (!targets.length) $("#governance-targets").innerHTML = "<p class='tag'>No targets stored.</p>";
  else {
    let html = "<table><thead><tr><th>target</th><th>export</th><th>delete</th></tr></thead><tbody>";
    for (const t of targets) html += `<tr><td>#${t.id} ${esc(t.label||"")}</td>`
      + `<td><button class="secondary export-target" data-target="${t.id}">Redacted JSON</button></td>`
      + `<td><button class="danger purge-target" data-target="${t.id}" data-label="${esc(t.label||t.id)}">Delete</button></td></tr>`;
    $("#governance-targets").innerHTML = html + "</tbody></table>";
    document.querySelectorAll(".export-target").forEach((button) => button.addEventListener("click", () => exportTarget(button)));
    document.querySelectorAll(".purge-target").forEach((button) => button.addEventListener("click", () => deleteTarget(button)));
  }
  if (!audit.length) $("#audit-events").innerHTML = "<p class='tag'>No governance actions yet.</p>";
  else {
    $("#audit-events").innerHTML = "<table><thead><tr><th>when</th><th>action</th><th>actor</th><th>object</th><th>detail</th></tr></thead><tbody>"
      + audit.map(e=>`<tr><td>${esc(e.created_at.replace("T"," ").slice(0,19))}</td><td>${esc(e.action)}</td><td>${esc(e.actor)}</td><td>${esc(e.object_type)} #${e.object_id==null?"":e.object_id}</td><td><small>${esc(JSON.stringify(e.detail))}</small></td></tr>`).join("") + "</tbody></table>";
  }
}

async function exportTarget(button) {
  const target = button.dataset.target;
  const response = await fetch(`/api/targets/${target}/export`, {
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({redacted:true, actor:"local"}),
  });
  const data = await response.json();
  if (!response.ok) { $("#retention-status").textContent = `Error: ${data.error||response.status}`; return; }
  const blob = new Blob([JSON.stringify(data, null, 2) + "\n"], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = `target-${target}-redacted.json`; link.click();
  URL.revokeObjectURL(url);
}

async function deleteTarget(button) {
  if (!window.confirm(`Permanently delete target ${button.dataset.label} and all investigation data?`)) return;
  const response = await fetch(`/api/targets/${button.dataset.target}`, {
    method:"DELETE", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({confirm:true, actor:"local"}),
  });
  const data = await response.json();
  $("#retention-status").textContent = response.ok ? `Deleted target #${button.dataset.target}.` : `Error: ${data.error||response.status}`;
  loadGovernance();
}

async function runRetention(apply) {
  const days = Number($("#retention-days").value);
  if (!Number.isInteger(days) || days < 1) { $("#retention-status").textContent = "Enter a positive number of days."; return; }
  if (apply && !window.confirm(`Delete all targets inactive for more than ${days} days?`)) return;
  const response = await fetch("/api/retention", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({days, dry_run:!apply, actor:"local"}),
  });
  const data = await response.json();
  $("#retention-status").textContent = `${apply?"Deleted":"Would delete"} ${data.target_ids.length} target(s): ${data.target_ids.join(", ")||"none"}.`;
  if (apply) loadGovernance();
}

$("#retention-preview").addEventListener("click", ()=>runRetention(false));
$("#retention-apply").addEventListener("click", ()=>runRetention(true));

$("#graph-load").addEventListener("click", () => {
  const id = $("#graph-target").value || 0;
  table("#entities", `/api/targets/${id}/entities`, ["id","identity","score","sources","flags"],
    (e) => [e.id, esc(e.label||""), bar(e.confidence),
            esc((e.sources||[]).join(", ")),
            (e.flags&&e.flags.length)?`<span class="flag">${esc(e.flags.join(", "))}</span>`:""]);
});

function badge(k){ return `<span class="badge ${esc(k)}">${esc(k)}</span>`; }
function bar(v){ v=v||0; return `<span class="bar"><span style="width:${Math.round(v*100)}%"></span></span> ${v.toFixed(2)}`; }
function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function safeHttpUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(String(value));
    return ["http:", "https:"].includes(url.protocol) ? url.href : null;
  } catch (_) {
    return null;
  }
}

// --- Live execution graph -------------------------------------------------
const LIVE_COLORS = {
  input: "#73aaf5", running: "#73aaf5", success: "#64d68b",
  uncertain: "#e4b459", unverifiable: "#e4b459",
  not_found: "#f07a74", error: "#f07a74",
};
const LIVE_KIND_STROKES = {
  artifact: "#9cc5ff", process: "#d2b9f4", request: "#c3c6c0", finding: "#f0f1ed",
};
const reducedGraphMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const RESEARCH_PHASES = ["understand", "discover", "connect", "verify", "synthesize"];
const researchState = {
  phaseIndex: -1,
  confirmed: 0,
  open: 0,
  leads: 0,
  feedKeys: new Set(),
  mode: "focus",
  milestoneTimer: null,
  autoFitTimer: null,
};
const liveGraph = {
  nodes: new Map(), edges: new Map(), roots: 0,
  width: 0, height: 0, dpr: 1,
  view: { scale: 1, ox: 0, oy: 0 },
  viewTarget: null,
  alpha: 0, raf: null, paused: false, active: false,
  hoverId: null, selectedId: null, keyboardIndex: -1,
  dragNode: null, panning: false, pointerStart: null, panStart: null,
  followedId: null, visibleIds: null, userInteracted: false,
};

function humanizeResearchValue(value) {
  const text = String(value || "").replaceAll("_", " ").replaceAll("-", " ").trim();
  return text ? text.replace(/\b\w/g, letter => letter.toUpperCase()) : "Source";
}

function setResearchNow(kicker, title, detail, tone = "busy") {
  $("#research-now-kicker").textContent = kicker;
  $("#research-now-title").textContent = title;
  $("#research-now-detail").textContent = detail;
  $(".research-now").dataset.tone = tone;
}

function setResearchPhase(phase) {
  const nextIndex = RESEARCH_PHASES.indexOf(phase);
  if (nextIndex < 0 || nextIndex < researchState.phaseIndex) return;
  researchState.phaseIndex = nextIndex;
  document.querySelectorAll("[data-research-phase]").forEach((item, index) => {
    item.classList.toggle("complete", index < nextIndex);
    item.classList.toggle("current", index === nextIndex);
    if (index === nextIndex) item.setAttribute("aria-current", "step");
    else item.removeAttribute("aria-current");
  });
}

function showResearchMilestone(message, tone = "success") {
  const milestone = $("#research-milestone");
  clearTimeout(researchState.milestoneTimer);
  milestone.hidden = false;
  milestone.dataset.tone = tone;
  milestone.textContent = message;
  milestone.classList.remove("arrive");
  void milestone.offsetWidth;
  milestone.classList.add("arrive");
  researchState.milestoneTimer = setTimeout(() => { milestone.hidden = true; }, 3200);
}

function setResearchMode(mode) {
  if (!['focus', 'explore'].includes(mode)) return;
  researchState.mode = mode;
  $("#research-room").dataset.mode = mode;
  document.querySelectorAll("[data-research-mode]").forEach((button) => {
    const selected = button.dataset.researchMode === mode;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  requestAnimationFrame(() => { sizeLiveCanvas(); fitLiveGraph(); });
}

document.querySelectorAll("[data-research-mode]").forEach((button) => {
  button.addEventListener("click", () => setResearchMode(button.dataset.researchMode));
});

function researchActivityCopy(activity) {
  const parent = liveGraph.nodes.get(activity.parent_id);
  const source = humanizeResearchValue(activity.module || activity.source);
  const subject = activity.artifact_label || parent?.artifact_label || parent?.label;
  const type = humanizeResearchValue(activity.artifact_type || activity.category || "lead");
  const outcome = liveOutcome(activity);

  if (activity.phase === "seeded") return {
    phase: "understand", kicker: "Starting clue",
    title: `${type} understood`, detail: `${activity.label} is the root of this investigation.`,
    tone: "busy",
  };
  if (activity.kind === "process" && activity.status === "running") return {
    phase: parent?.depth > 0 ? "connect" : "discover", kicker: "Choosing the next step",
    title: `Checking ${subject || type}`, detail: `${source} was selected to look for a useful connection.`,
    tone: "busy",
  };
  if (activity.kind === "request" && activity.status === "running") return {
    phase: "discover", kicker: "Contacting a public source",
    title: `Searching ${activity.host || "source"}`, detail: `Specter is waiting for a response to this ${activity.method || "web"} request.`,
    tone: "busy",
  };
  if (activity.kind === "request") return {
    phase: "discover", kicker: outcome === "success" ? "Source responded" : "Source checked",
    title: `${activity.host || "Source"} ${outcome === "success" ? "responded" : liveOutcomeLabel(activity).toLowerCase()}`,
    detail: activity.elapsed_ms == null
      ? "The response is being interpreted before it becomes evidence."
      : `The request finished in ${activity.elapsed_ms} ms and is being interpreted.`,
    tone: outcome === "error" ? "error" : outcome === "uncertain" ? "warning" : "busy",
  };
  if (activity.kind === "artifact" && activity.phase === "discovered") return {
    phase: "connect", kicker: "New lead",
    title: `${type} discovered`, detail: `${activity.label} can extend the investigation into another branch.`,
    tone: "success",
  };
  if (activity.kind === "finding") {
    const isConfirmed = outcome === "success";
    const isOpen = ["uncertain", "unverifiable"].includes(outcome);
    return {
      phase: "verify",
      kicker: isConfirmed ? "Evidence confirmed" : isOpen ? "Evidence needs review" : "Check resolved",
      title: isConfirmed ? `${source} supports a finding` : `${source}: ${liveOutcomeLabel(activity)}`,
      detail: activity.reason || `${activity.label || type} was evaluated against the available evidence.`,
      tone: isConfirmed ? "success" : isOpen ? "warning" : outcome === "error" ? "error" : "neutral",
    };
  }
  return {
    phase: parent?.depth > 0 ? "connect" : "discover", kicker: "Check complete",
    title: `${source} finished`, detail: subject
      ? `${subject} produced ${activity.findings || 0} finding(s) and ${activity.artifacts || 0} new lead(s).`
      : "Specter is selecting the next useful branch.",
    tone: outcome === "error" ? "error" : outcome === "uncertain" ? "warning" : "busy",
  };
}

function addDiscoveryEntry(activity, copy) {
  const outcome = liveOutcome(activity);
  const journaled = (
    (activity.kind === "artifact" && activity.phase === "discovered")
    || activity.kind === "finding"
    || (activity.kind === "request" && ["uncertain", "error"].includes(outcome))
  );
  const key = `${activity.id}:${activity.phase}:${outcome}`;
  if (!journaled || researchState.feedKeys.has(key)) return;
  researchState.feedKeys.add(key);
  $("#discovery-feed-empty").hidden = true;

  if (activity.kind === "finding" && outcome === "success") researchState.confirmed += 1;
  if (activity.kind === "finding" && ["uncertain", "unverifiable"].includes(outcome)) researchState.open += 1;
  if (activity.kind === "artifact" && activity.phase === "discovered") researchState.leads += 1;
  $("#discovery-confirmed").textContent = researchState.confirmed;
  $("#discovery-open").textContent = researchState.open;

  const item = document.createElement("li");
  item.className = `discovery-entry ${copy.tone}`;
  const button = document.createElement("button");
  button.type = "button";
  const marker = document.createElement("span"); marker.className = "discovery-marker";
  const body = document.createElement("span"); body.className = "discovery-copy";
  const title = document.createElement("strong"); title.textContent = copy.title;
  const detail = document.createElement("span"); detail.textContent = copy.detail;
  const meta = document.createElement("small");
  meta.textContent = `${humanizeResearchValue(activity.kind)} · ${liveOutcomeLabel(activity)}`;
  body.append(title, detail, meta); button.append(marker, body); item.appendChild(button);
  button.addEventListener("click", () => {
    setResearchMode("explore");
    requestAnimationFrame(() => focusLiveNode(liveGraph.nodes.get(activity.id)));
  });
  const feed = $("#discovery-feed");
  feed.insertBefore(item, feed.firstChild);
  const entries = [...feed.querySelectorAll(".discovery-entry")];
  if (entries.length > 40) entries.at(-1).remove();

  if (researchState.leads === 1)
    showResearchMilestone("First new lead discovered");
  if ([1, 3, 5, 10].includes(researchState.confirmed))
    showResearchMilestone(`${researchState.confirmed} finding${researchState.confirmed === 1 ? "" : "s"} confirmed`);
}

function updateResearchStory(activity) {
  const copy = researchActivityCopy(activity);
  setResearchPhase(copy.phase);
  setResearchNow(copy.kicker, copy.title, copy.detail, copy.tone);
  addDiscoveryEntry(activity, copy);
}

function setLiveGraphStatus(message, tone = "neutral") {
  const status = $("#live-graph-status");
  if (!status) return;
  status.textContent = message;
  status.dataset.tone = tone;
}

function liveOutcome(node) {
  if (node.phase === "seeded") return "input";
  if (node.status === "running") return "running";
  const value = String(node.outcome || node.verdict || "").toLowerCase();
  const aliases = { found: "success" };
  const normalized = aliases[value] || value;
  return Object.hasOwn(LIVE_COLORS, normalized) ? normalized : "running";
}

function liveOutcomeLabel(node) {
  const labels = {
    input: "Input", running: "Running", success: "Successful",
    uncertain: "Uncertain", unverifiable: "Unverifiable",
    not_found: "Not found", error: "Error",
  };
  return labels[liveOutcome(node)] || "Pending";
}

function liveNodeTitle(node) {
  if (node.kind === "request") return node.host || node.url || "Request";
  if (node.kind === "process") return node.module || node.label || "Process";
  if (node.kind === "finding") return node.label || node.source || "Finding";
  return node.label || node.artifact_type || "Input";
}

function sizeLiveCanvas() {
  const canvas = $("#live-graph-canvas");
  if (!canvas) return null;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(1, Math.round(rect.width));
  const height = Math.max(1, Math.round(rect.height));
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
  }
  liveGraph.width = width;
  liveGraph.height = height;
  liveGraph.dpr = dpr;
  if (!liveGraph.view.ox && !liveGraph.view.oy) {
    liveGraph.view.ox = width / 2;
    liveGraph.view.oy = height / 2;
  }
  return canvas.getContext("2d");
}

function liveToScreen(node) {
  return [
    liveGraph.view.ox + node.x * liveGraph.view.scale,
    liveGraph.view.oy + node.y * liveGraph.view.scale,
  ];
}

function liveToWorld(x, y) {
  return [
    (x - liveGraph.view.ox) / liveGraph.view.scale,
    (y - liveGraph.view.oy) / liveGraph.view.scale,
  ];
}

function placeLiveNode(node) {
  const parent = liveGraph.nodes.get(node.parent_id);
  if (parent) {
    const childIndex = parent.children || 0;
    parent.children = childIndex + 1;
    const angle = childIndex * 2.399963 + (node.kind === "request" ? 0.45 : 0);
    const radius = 72 + Math.floor(childIndex / 7) * 28;
    node.x = parent.x + Math.cos(angle) * radius;
    node.y = parent.y + Math.sin(angle) * radius;
  } else {
    const angle = liveGraph.roots * 2.399963;
    const radius = liveGraph.roots ? 70 + Math.floor(liveGraph.roots / 6) * 45 : 0;
    node.x = Math.cos(angle) * radius;
    node.y = Math.sin(angle) * radius;
    liveGraph.roots += 1;
  }
  node.vx = 0;
  node.vy = 0;
  node.children = 0;
}

function ingestLiveActivity(activity) {
  if (!activity || !activity.id || !activity.kind) return;
  let node = liveGraph.nodes.get(activity.id);
  const isNew = !node;
  if (!node) {
    node = { ...activity, bornAt: performance.now() };
    placeLiveNode(node);
    liveGraph.nodes.set(node.id, node);
  } else if (!node.sequence || activity.sequence >= node.sequence) {
    Object.assign(node, activity);
  }
  if (node.parent_id && liveGraph.nodes.has(node.parent_id)) {
    const edgeKey = `${node.parent_id}>${node.id}`;
    if (!liveGraph.edges.has(edgeKey)) {
      liveGraph.edges.set(edgeKey, {
        source: node.parent_id, target: node.id, bornAt: performance.now(),
      });
    }
  }
  liveGraph.active = true;
  liveGraph.alpha = Math.max(liveGraph.alpha, reducedGraphMotion.matches ? 0.12 : 0.8);
  $("#live-graph-empty").hidden = true;
  updateLiveGraphCounts();
  updateResearchStory(node);
  if (liveGraph.selectedId === node.id || liveGraph.hoverId === node.id) renderLiveDetail(node);
  if (liveGraph.followedId) updateFollowedBranch();
  if (isNew && researchState.mode === "focus" && !liveGraph.userInteracted) {
    clearTimeout(researchState.autoFitTimer);
    researchState.autoFitTimer = setTimeout(() => fitLiveGraph(), 260);
  }
  scheduleLiveGraph();
}

function updateLiveGraphCounts() {
  let processes = 0, requests = 0, findings = 0;
  for (const node of liveGraph.nodes.values()) {
    if (node.kind === "process") processes += 1;
    else if (node.kind === "request") requests += 1;
    else if (node.kind === "finding") findings += 1;
  }
  $("#live-count-processes").textContent = processes;
  $("#live-count-requests").textContent = requests;
  $("#live-count-findings").textContent = findings;
  $("#scan-activity-count").textContent = liveGraph.nodes.size;
}

function tickLiveGraph() {
  const nodes = [...liveGraph.nodes.values()];
  if (!nodes.length || liveGraph.paused || liveGraph.alpha < 0.008) return;
  const alpha = liveGraph.alpha;

  for (const edge of liveGraph.edges.values()) {
    const source = liveGraph.nodes.get(edge.source), target = liveGraph.nodes.get(edge.target);
    if (!source || !target) continue;
    let dx = target.x - source.x, dy = target.y - source.y;
    const distance = Math.sqrt(dx * dx + dy * dy) || 1;
    const desired = target.kind === "request" ? 66 : target.kind === "finding" ? 78 : 92;
    const force = (distance - desired) * 0.012 * alpha;
    dx /= distance; dy /= distance;
    source.vx += dx * force; source.vy += dy * force;
    target.vx -= dx * force; target.vy -= dy * force;
  }

  const cellSize = 48;
  const cells = new Map();
  for (const node of nodes) {
    const key = `${Math.floor(node.x / cellSize)},${Math.floor(node.y / cellSize)}`;
    if (!cells.has(key)) cells.set(key, []);
    cells.get(key).push(node);
  }
  for (const node of nodes) {
    const cx = Math.floor(node.x / cellSize), cy = Math.floor(node.y / cellSize);
    for (let gx = cx - 1; gx <= cx + 1; gx += 1) {
      for (let gy = cy - 1; gy <= cy + 1; gy += 1) {
        for (const other of cells.get(`${gx},${gy}`) || []) {
          if (other === node || other.id < node.id) continue;
          let dx = node.x - other.x, dy = node.y - other.y;
          const distance2 = Math.max(16, dx * dx + dy * dy);
          const distance = Math.sqrt(distance2);
          const force = Math.min(2.4, 180 / distance2) * alpha;
          dx /= distance; dy /= distance;
          node.vx += dx * force; node.vy += dy * force;
          other.vx -= dx * force; other.vy -= dy * force;
        }
      }
    }
  }

  for (const node of nodes) {
    if (node === liveGraph.dragNode) continue;
    node.vx += -node.x * 0.00045 * alpha;
    node.vy += -node.y * 0.00045 * alpha;
    node.vx = Math.max(-6, Math.min(6, node.vx)) * 0.84;
    node.vy = Math.max(-6, Math.min(6, node.vy)) * 0.84;
    node.x += node.vx;
    node.y += node.vy;
  }
  liveGraph.alpha *= reducedGraphMotion.matches ? 0.72 : 0.975;
}

function tickLiveView() {
  if (!liveGraph.viewTarget) return;
  if (reducedGraphMotion.matches) {
    liveGraph.view = { ...liveGraph.viewTarget };
    liveGraph.viewTarget = null;
    return;
  }
  const target = liveGraph.viewTarget;
  const factor = 0.16;
  liveGraph.view.scale += (target.scale - liveGraph.view.scale) * factor;
  liveGraph.view.ox += (target.ox - liveGraph.view.ox) * factor;
  liveGraph.view.oy += (target.oy - liveGraph.view.oy) * factor;
  if (Math.abs(target.scale - liveGraph.view.scale) < 0.002
      && Math.abs(target.ox - liveGraph.view.ox) < 0.5
      && Math.abs(target.oy - liveGraph.view.oy) < 0.5) {
    liveGraph.view = { ...target };
    liveGraph.viewTarget = null;
  }
}

function drawLiveNode(ctx, node, x, y, now) {
  const selected = node.id === liveGraph.selectedId || node.id === liveGraph.hoverId;
  const age = Math.max(0, now - (node.bornAt || 0));
  const entrance = reducedGraphMotion.matches ? 1 : Math.min(1, age / 360);
  const easedEntrance = 1 - (1 - entrance) ** 3;
  const baseRadius = node.phase === "seeded" ? 8 : node.kind === "process" ? 7 : 5.5;
  const radius = baseRadius * easedEntrance;
  const dimmed = liveGraph.visibleIds && !liveGraph.visibleIds.has(node.id);
  ctx.globalAlpha = dimmed ? 0.1 : 1;
  ctx.beginPath();
  if (node.kind === "process") {
    ctx.rect(x - radius, y - radius, radius * 2, radius * 2);
  } else if (node.kind === "artifact") {
    ctx.moveTo(x, y - radius - 1); ctx.lineTo(x + radius + 1, y);
    ctx.lineTo(x, y + radius + 1); ctx.lineTo(x - radius - 1, y); ctx.closePath();
  } else {
    ctx.arc(x, y, radius, 0, Math.PI * 2);
  }
  ctx.fillStyle = LIVE_COLORS[liveOutcome(node)];
  ctx.fill();
  ctx.lineWidth = selected ? 2.5 : 1.3;
  ctx.strokeStyle = selected ? "#ffffff" : LIVE_KIND_STROKES[node.kind] || "#c3c6c0";
  ctx.stroke();
  if (node.status === "running") {
    const pulse = reducedGraphMotion.matches ? 0 : (Math.sin(now / 250) + 1) * 1.8;
    ctx.beginPath(); ctx.arc(x, y, radius + 4 + pulse, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(115,170,245,.42)"; ctx.lineWidth = 1; ctx.stroke();
  }
  if (selected || node.phase === "seeded" || (node.kind === "finding" && liveOutcome(node) === "success")) {
    const label = liveNodeTitle(node);
    const shortLabel = label.length > 28 ? `${label.slice(0, 27)}…` : label;
    ctx.font = "600 10px system-ui, sans-serif";
    ctx.fillStyle = selected ? "#f4f6f2" : "rgba(220,224,218,.72)";
    ctx.textBaseline = "middle";
    ctx.fillText(shortLabel, x + radius + 7, y);
  }
  ctx.globalAlpha = 1;
}

function drawLiveGraph() {
  const ctx = sizeLiveCanvas();
  if (!ctx) return;
  const { width, height, dpr } = liveGraph;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const now = performance.now();
  ctx.lineWidth = 1;
  for (const edge of liveGraph.edges.values()) {
    const source = liveGraph.nodes.get(edge.source), target = liveGraph.nodes.get(edge.target);
    if (!source || !target) continue;
    const [sx, sy] = liveToScreen(source), [tx, ty] = liveToScreen(target);
    if ((sx < 0 && tx < 0) || (sx > width && tx > width) ||
        (sy < 0 && ty < 0) || (sy > height && ty > height)) continue;
    const dimmed = liveGraph.visibleIds
      && (!liveGraph.visibleIds.has(source.id) || !liveGraph.visibleIds.has(target.id));
    ctx.globalAlpha = dimmed ? 0.06 : 1;
    ctx.strokeStyle = "rgba(155,159,154,.23)";
    ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
    if (!dimmed && !reducedGraphMotion.matches
        && (target.status === "running" || now - edge.bornAt < 1100)) {
      const progress = ((now / 1050) + ((target.sequence || 0) * 0.17)) % 1;
      const px = sx + (tx - sx) * progress, py = sy + (ty - sy) * progress;
      ctx.beginPath(); ctx.arc(px, py, 2.1, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(156,197,255,.9)"; ctx.fill();
    }
  }
  ctx.globalAlpha = 1;
  for (const node of liveGraph.nodes.values()) {
    const [x, y] = liveToScreen(node);
    if (x < -20 || y < -20 || x > width + 20 || y > height + 20) continue;
    drawLiveNode(ctx, node, x, y, now);
  }
}

function liveGraphFrame() {
  liveGraph.raf = null;
  tickLiveGraph();
  tickLiveView();
  drawLiveGraph();
  const flowing = liveGraph.active && !reducedGraphMotion.matches;
  if (!liveGraph.paused && (liveGraph.alpha >= 0.008 || liveGraph.viewTarget || flowing))
    scheduleLiveGraph();
}

function scheduleLiveGraph() {
  if (liveGraph.raf == null) liveGraph.raf = requestAnimationFrame(liveGraphFrame);
}

function fitLiveGraph({ immediate = false } = {}) {
  sizeLiveCanvas();
  const nodes = [...liveGraph.nodes.values()].filter(
    node => !liveGraph.visibleIds || liveGraph.visibleIds.has(node.id)
  );
  if (!nodes.length) {
    liveGraph.view = { scale: 1, ox: liveGraph.width / 2, oy: liveGraph.height / 2 };
    liveGraph.viewTarget = null;
    drawLiveGraph();
    return;
  }
  const xs = nodes.map(node => node.x), ys = nodes.map(node => node.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const scale = Math.min(
    1.5,
    Math.max(0.16, Math.min(
      (liveGraph.width - 70) / Math.max(70, maxX - minX),
      (liveGraph.height - 70) / Math.max(70, maxY - minY),
    )),
  );
  const target = {
    scale,
    ox: liveGraph.width / 2 - ((minX + maxX) / 2) * scale,
    oy: liveGraph.height / 2 - ((minY + maxY) / 2) * scale,
  };
  if (immediate || reducedGraphMotion.matches) {
    liveGraph.view = target;
    liveGraph.viewTarget = null;
    drawLiveGraph();
  } else {
    liveGraph.viewTarget = target;
    scheduleLiveGraph();
  }
}

function updateFollowedBranch() {
  if (!liveGraph.followedId || !liveGraph.nodes.has(liveGraph.followedId)) {
    liveGraph.visibleIds = null;
    return;
  }
  const visible = new Set([liveGraph.followedId]);
  let current = liveGraph.nodes.get(liveGraph.followedId);
  while (current?.parent_id && liveGraph.nodes.has(current.parent_id)) {
    visible.add(current.parent_id);
    current = liveGraph.nodes.get(current.parent_id);
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const node of liveGraph.nodes.values()) {
      if (node.parent_id && visible.has(node.parent_id) && !visible.has(node.id)) {
        visible.add(node.id);
        changed = true;
      }
    }
  }
  liveGraph.visibleIds = visible;
}

function focusLiveNode(node) {
  if (!node) return;
  liveGraph.selectedId = node.id;
  renderLiveDetail(node);
  sizeLiveCanvas();
  const scale = Math.max(1, Math.min(1.45, liveGraph.view.scale));
  liveGraph.viewTarget = {
    scale,
    ox: liveGraph.width / 2 - node.x * scale,
    oy: liveGraph.height / 2 - node.y * scale,
  };
  scheduleLiveGraph();
  $("#live-graph-canvas").focus({ preventScroll: true });
}

function liveConnectionPath(node) {
  const path = [];
  const visited = new Set();
  let current = node;
  while (current && !visited.has(current.id)) {
    path.unshift(liveNodeTitle(current));
    visited.add(current.id);
    current = current.parent_id ? liveGraph.nodes.get(current.parent_id) : null;
  }
  return path;
}

function explainLiveConnection(node) {
  const parent = node.parent_id ? liveGraph.nodes.get(node.parent_id) : null;
  const path = liveConnectionPath(node);
  const root = path[0] || "the starting clue";
  if (!parent) return "This is a starting clue supplied for the investigation.";
  if (node.kind === "request") {
    return `Specter contacted ${node.host || "this website"} because ${humanizeResearchValue(parent.module)} was checking ${parent.artifact_label || root}.`;
  }
  if (node.kind === "finding") {
    return `${humanizeResearchValue(node.source || parent.module)} evaluated ${parent.artifact_label || root} and produced this evidence. The branch began with ${root}.`;
  }
  if (node.kind === "artifact") {
    return `${humanizeResearchValue(node.module || parent.module)} discovered ${node.label} while checking ${parent.artifact_label || root}, so Specter opened a new research branch.`;
  }
  return `Specter selected ${humanizeResearchValue(node.module)} to examine ${node.artifact_label || root}. This check descends from ${root}.`;
}

function appendLiveDetailField(list, label, value, link = false) {
  if (value === undefined || value === null || value === "") return;
  const term = document.createElement("dt"); term.textContent = label;
  const detail = document.createElement("dd");
  const safeUrl = link ? safeHttpUrl(value) : null;
  if (safeUrl) {
    const anchor = document.createElement("a");
    anchor.href = safeUrl; anchor.target = "_blank"; anchor.rel = "noopener noreferrer";
    anchor.textContent = value; detail.appendChild(anchor);
  } else detail.textContent = String(value);
  list.append(term, detail);
}

function renderLiveDetail(node) {
  const detail = $("#live-graph-detail");
  detail.replaceChildren();
  if (!node) {
    const kicker = document.createElement("span"); kicker.className = "detail-kicker"; kicker.textContent = "Activity details";
    const heading = document.createElement("h4"); heading.textContent = "Nothing selected";
    detail.append(kicker, heading);
    return;
  }
  const kicker = document.createElement("span"); kicker.className = "detail-kicker";
  kicker.textContent = node.kind === "request" ? "Outbound request" : node.kind;
  const heading = document.createElement("h4"); heading.textContent = liveNodeTitle(node);
  const list = document.createElement("dl");
  const outcome = document.createElement("span"); outcome.className = `graph-outcome ${liveOutcome(node)}`;
  outcome.textContent = liveOutcomeLabel(node);
  const term = document.createElement("dt"); term.textContent = "Outcome";
  const outcomeCell = document.createElement("dd"); outcomeCell.appendChild(outcome);
  list.append(term, outcomeCell);
  appendLiveDetailField(list, "Website", node.url, true);
  appendLiveDetailField(list, "Host", node.host);
  appendLiveDetailField(list, "Method", node.method);
  appendLiveDetailField(list, "HTTP status", node.status_code);
  appendLiveDetailField(list, "Duration", node.elapsed_ms == null ? null : `${node.elapsed_ms} ms`);
  appendLiveDetailField(list, "Module", node.module || node.source);
  appendLiveDetailField(list, "Input", node.artifact_label);
  appendLiveDetailField(list, "Type", node.artifact_type || node.category);
  appendLiveDetailField(list, "Verdict", node.verdict);
  appendLiveDetailField(list, "Confidence", node.confidence == null ? null : Number(node.confidence).toFixed(2));
  appendLiveDetailField(list, "Findings", node.findings);
  appendLiveDetailField(list, "Artifacts", node.artifacts);
  appendLiveDetailField(list, "Reason", node.reason || node.error);
  const actions = document.createElement("div"); actions.className = "graph-detail-actions";
  const follow = document.createElement("button"); follow.type = "button"; follow.className = "quiet-action";
  follow.textContent = liveGraph.followedId === node.id ? "Show all branches" : "Follow this branch";
  follow.addEventListener("click", () => {
    liveGraph.followedId = liveGraph.followedId === node.id ? null : node.id;
    updateFollowedBranch();
    renderLiveDetail(node);
    fitLiveGraph();
  });
  const explain = document.createElement("button"); explain.type = "button"; explain.className = "quiet-action";
  explain.textContent = "Explain connection";
  const explanation = document.createElement("div"); explanation.className = "connection-explanation";
  explanation.hidden = true;
  explanation.textContent = explainLiveConnection(node);
  explain.addEventListener("click", () => {
    explanation.hidden = !explanation.hidden;
    explain.setAttribute("aria-expanded", String(!explanation.hidden));
  });
  actions.append(follow, explain);
  if (["artifact", "finding"].includes(node.kind) && node.label) {
    const fieldByArtifact = {
      name: "name", username: "username", email: "email", phone: "phone",
      domain: "domain", subdomain: "domain", hostname: "domain",
      mx_host: "domain", nameserver: "domain", ip_address: "ip_address",
      account_profile: "url", url: "url", link: "url",
    };
    const fieldName = fieldByArtifact[node.artifact_type || node.category];
    if (fieldName) {
      const reuse = document.createElement("button"); reuse.type = "button"; reuse.className = "quiet-action";
      reuse.textContent = "Add to identity clues";
      reuse.addEventListener("click", () => {
        const input = document.querySelector(`#q [name='${fieldName}']`);
        setScanStage("start");
        if (input.value.trim() && input.value.trim() !== node.label.trim()) {
          input.focus();
          setScanStatus(`A different ${identityLabels[fieldName]} is already included.`, "warning");
          return;
        }
        input.value = node.label;
        updateClueSummary();
        input.focus();
        setScanStatus(`${identityLabels[fieldName]} added to the identity clues.`, "neutral");
      });
      actions.appendChild(reuse);
    }
  }
  detail.append(kicker, heading, list, actions, explanation);
}

function showLiveTooltip(node, x, y) {
  const tooltip = $("#live-graph-tooltip");
  tooltip.replaceChildren();
  if (!node) { tooltip.hidden = true; return; }
  const title = document.createElement("strong"); title.textContent = liveNodeTitle(node);
  const sub = document.createElement("span");
  sub.textContent = node.url || `${node.kind} · ${liveOutcomeLabel(node)}`;
  tooltip.append(title, sub); tooltip.hidden = false;
  const maxLeft = Math.max(8, liveGraph.width - tooltip.offsetWidth - 8);
  tooltip.style.left = `${Math.max(8, Math.min(maxLeft, x + 13))}px`;
  tooltip.style.top = `${Math.max(8, Math.min(liveGraph.height - tooltip.offsetHeight - 8, y + 13))}px`;
}

function pickLiveNode(x, y) {
  let closest = null, best = 14 * 14;
  for (const node of liveGraph.nodes.values()) {
    const [sx, sy] = liveToScreen(node);
    const distance2 = (sx - x) ** 2 + (sy - y) ** 2;
    if (distance2 < best) { best = distance2; closest = node; }
  }
  return closest;
}

function inspectLiveNode(node, { selected = false } = {}) {
  if (selected) liveGraph.selectedId = node ? node.id : null;
  renderLiveDetail(node);
  drawLiveGraph();
}

function resetLiveGraph() {
  if (!$("#live-graph-canvas")) return;
  clearTimeout(researchState.autoFitTimer);
  clearTimeout(researchState.milestoneTimer);
  liveGraph.nodes.clear(); liveGraph.edges.clear(); liveGraph.roots = 0;
  liveGraph.alpha = 0; liveGraph.active = false; liveGraph.hoverId = null;
  liveGraph.selectedId = null; liveGraph.keyboardIndex = -1;
  liveGraph.dragNode = null; liveGraph.panning = false;
  liveGraph.view = { scale: 1, ox: 0, oy: 0 };
  liveGraph.viewTarget = null; liveGraph.followedId = null; liveGraph.visibleIds = null;
  liveGraph.userInteracted = false;
  liveGraph.paused = false;
  researchState.phaseIndex = -1; researchState.confirmed = 0; researchState.open = 0;
  researchState.leads = 0;
  researchState.feedKeys.clear();
  $("#live-graph-pause").textContent = "Pause";
  $("#live-graph-pause").setAttribute("aria-pressed", "false");
  $("#live-graph-empty").hidden = false;
  $("#live-graph-tooltip").hidden = true;
  $("#research-milestone").hidden = true;
  $("#discovery-confirmed").textContent = "0";
  $("#discovery-open").textContent = "0";
  document.querySelectorAll("#discovery-feed .discovery-entry").forEach(item => item.remove());
  $("#discovery-feed-empty").hidden = false;
  document.querySelectorAll("[data-research-phase]").forEach((item) => {
    item.classList.remove("complete", "current"); item.removeAttribute("aria-current");
  });
  setResearchNow("Ready", "Waiting for a starting point",
    "Specter will explain each meaningful step as the investigation develops.", "neutral");
  updateLiveGraphCounts(); renderLiveDetail(null); setLiveGraphStatus("Idle"); drawLiveGraph();
}

function beginResearchRoom() {
  setResearchPhase("understand");
  setResearchNow("Preparing", "Understanding the starting clue",
    "Specter is classifying the input before choosing which public sources to contact.", "busy");
}

function finishLiveGraph() {
  liveGraph.active = false;
  setLiveGraphStatus("Complete", "success");
  setResearchPhase("synthesize");
  document.querySelectorAll("[data-research-phase]").forEach((item) => {
    item.classList.add("complete"); item.classList.remove("current");
    item.removeAttribute("aria-current");
  });
  setResearchNow("Investigation complete", "The profile is ready",
    `${researchState.confirmed} confirmed finding(s) and ${researchState.open} item(s) for review were recorded.`,
    "success");
  showResearchMilestone("Research complete");
  setTimeout(fitLiveGraph, 80);
}

function failLiveGraph(message) {
  liveGraph.active = false;
  setLiveGraphStatus(message || "Failed", "error");
  setResearchNow("Investigation interrupted", "Specter could not continue",
    message || "The current research stream stopped unexpectedly.", "error");
  drawLiveGraph();
}

const liveCanvas = $("#live-graph-canvas");
liveCanvas.addEventListener("pointerdown", (event) => {
  const rect = liveCanvas.getBoundingClientRect();
  const x = event.clientX - rect.left, y = event.clientY - rect.top;
  const node = pickLiveNode(x, y);
  liveCanvas.setPointerCapture(event.pointerId);
  liveGraph.userInteracted = true;
  liveGraph.viewTarget = null;
  liveGraph.pointerStart = [x, y];
  if (node) {
    liveGraph.dragNode = node;
    liveGraph.selectedId = node.id;
    inspectLiveNode(node, { selected: true });
  } else {
    liveGraph.panning = true;
    liveGraph.panStart = [x - liveGraph.view.ox, y - liveGraph.view.oy];
  }
});

liveCanvas.addEventListener("pointermove", (event) => {
  const rect = liveCanvas.getBoundingClientRect();
  const x = event.clientX - rect.left, y = event.clientY - rect.top;
  if (liveGraph.dragNode) {
    const [wx, wy] = liveToWorld(x, y);
    liveGraph.dragNode.x = wx; liveGraph.dragNode.y = wy;
    liveGraph.dragNode.vx = 0; liveGraph.dragNode.vy = 0;
    liveGraph.alpha = Math.max(liveGraph.alpha, 0.15); scheduleLiveGraph();
    return;
  }
  if (liveGraph.panning) {
    liveGraph.view.ox = x - liveGraph.panStart[0];
    liveGraph.view.oy = y - liveGraph.panStart[1];
    drawLiveGraph(); return;
  }
  const node = pickLiveNode(x, y);
  liveGraph.hoverId = node ? node.id : null;
  liveCanvas.style.cursor = node ? "pointer" : "grab";
  showLiveTooltip(node, x, y);
  if (node) renderLiveDetail(node);
  else if (liveGraph.selectedId) renderLiveDetail(liveGraph.nodes.get(liveGraph.selectedId));
  drawLiveGraph();
});

function releaseLivePointer(event) {
  if (liveCanvas.hasPointerCapture(event.pointerId)) liveCanvas.releasePointerCapture(event.pointerId);
  liveGraph.dragNode = null; liveGraph.panning = false; liveGraph.pointerStart = null;
}
liveCanvas.addEventListener("pointerup", releaseLivePointer);
liveCanvas.addEventListener("pointercancel", releaseLivePointer);
liveCanvas.addEventListener("pointerleave", () => {
  if (liveGraph.dragNode || liveGraph.panning) return;
  liveGraph.hoverId = null; $("#live-graph-tooltip").hidden = true;
  renderLiveDetail(liveGraph.nodes.get(liveGraph.selectedId)); drawLiveGraph();
});

liveCanvas.addEventListener("wheel", (event) => {
  event.preventDefault();
  liveGraph.userInteracted = true;
  liveGraph.viewTarget = null;
  const rect = liveCanvas.getBoundingClientRect();
  const x = event.clientX - rect.left, y = event.clientY - rect.top;
  const [wx, wy] = liveToWorld(x, y);
  const factor = event.deltaY < 0 ? 1.12 : 0.89;
  liveGraph.view.scale = Math.max(0.12, Math.min(4, liveGraph.view.scale * factor));
  liveGraph.view.ox = x - wx * liveGraph.view.scale;
  liveGraph.view.oy = y - wy * liveGraph.view.scale;
  drawLiveGraph();
}, { passive: false });

liveCanvas.addEventListener("keydown", (event) => {
  if (!["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp", "Home", "End"].includes(event.key)) return;
  const nodes = [...liveGraph.nodes.values()].sort((a, b) => (a.sequence || 0) - (b.sequence || 0));
  if (!nodes.length) return;
  event.preventDefault();
  if (event.key === "Home") liveGraph.keyboardIndex = 0;
  else if (event.key === "End") liveGraph.keyboardIndex = nodes.length - 1;
  else {
    const direction = ["ArrowRight", "ArrowDown"].includes(event.key) ? 1 : -1;
    liveGraph.keyboardIndex = (liveGraph.keyboardIndex + direction + nodes.length) % nodes.length;
  }
  const node = nodes[liveGraph.keyboardIndex];
  liveGraph.hoverId = null;
  $("#live-graph-tooltip").hidden = true;
  liveGraph.selectedId = node.id; inspectLiveNode(node, { selected: true });
});

$("#live-graph-fit").addEventListener("click", fitLiveGraph);
$("#live-graph-pause").addEventListener("click", (event) => {
  liveGraph.paused = !liveGraph.paused;
  event.currentTarget.textContent = liveGraph.paused ? "Resume" : "Pause";
  event.currentTarget.setAttribute("aria-pressed", String(liveGraph.paused));
  if (!liveGraph.paused) { liveGraph.alpha = Math.max(liveGraph.alpha, 0.16); scheduleLiveGraph(); }
  else drawLiveGraph();
});

let liveResizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(liveResizeTimer);
  liveResizeTimer = setTimeout(() => { sizeLiveCanvas(); fitLiveGraph(); }, 150);
});

resetLiveGraph();

// --- Discovery map (self-contained force-directed graph; no external deps) --
const TYPE_COLORS = {
  username:"#58a6ff", account_profile:"#79c0ff",
  email:"#f0883e", domain:"#3fb950", subdomain:"#56d364", hostname:"#56d364",
  mx_host:"#2ea043", nameserver:"#2ea043",
  ip_address:"#bc8cff", asn:"#d2a8ff", netblock:"#d2a8ff",
  url:"#8b949e", link:"#6e7681", hash:"#ff7b72", breach:"#f85149",
  phone:"#e3b341", name:"#e3b341",
};
const typeColor = (t) => TYPE_COLORS[t] || "#8b93a7";
let mapState = null, lastGraph = null, resizeTimer = null;

// Refit the canvas when the window resizes, while the map tab is showing one.
window.addEventListener("resize", () => {
  if (!lastGraph || !$("#panel-map").classList.contains("active")) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => startSim(lastGraph), 180);
});

async function loadMap() {
  const run = $("#map-run").value.trim();
  $("#map-status").textContent = "Loading…";
  let url = run ? `/api/runs/${run}/graph` : null;
  if (!url) {
    const runs = await (await fetch("/api/runs")).json();
    if (!runs.length) { $("#map-status").textContent = "No runs yet — run a saved scan first."; return; }
    url = `/api/runs/${runs[0].id}/graph`;
  }
  const g = await (await fetch(url)).json();
  if (!g.nodes || !g.nodes.length) { $("#map-status").textContent = "No artifacts for this run."; clearMap(); return; }
  $("#map-status").textContent = `run #${g.run_id}: ${g.nodes.length} nodes, ${g.edges.length} edges`;
  $("#map-legend").innerHTML = [...new Set(g.nodes.map(n=>n.type))].sort()
    .map(t=>`<span class="leg"><i style="background:${typeColor(t)}"></i>${esc(t)}</span>`).join("");
  startSim(g);
}

function clearMap(){ if(mapState&&mapState.raf) cancelAnimationFrame(mapState.raf);
  const cv=$("#map-canvas"); if(cv){const c=cv.getContext("2d"); c&&c.clearRect(0,0,cv.width,cv.height);}
  $("#map-detail").innerHTML=""; }

function startSim(g){
  if(mapState){ if(mapState.raf) cancelAnimationFrame(mapState.raf);
    if(mapState.onUp) window.removeEventListener("mouseup", mapState.onUp); }
  const cv=$("#map-canvas"), wrap=$("#map-wrap");
  const W=cv.width=wrap.clientWidth||900, H=cv.height=520, ctx=cv.getContext("2d");
  const byId=new Map();
  lastGraph=g;
  const N=g.nodes.length;
  const nodes=g.nodes.slice(0,400).map((n,i)=>{ const a=(i/Math.max(1,N))*Math.PI*2;
    const node={...n, x:Math.cos(a)*140+(Math.random()*30-15), y:Math.sin(a)*140+(Math.random()*30-15),
                vx:0, vy:0, fx:null, fy:null}; byId.set(n.id,node); return node; });
  const edges=g.edges.map(e=>({s:byId.get(e.source), t:byId.get(e.target)})).filter(e=>e.s&&e.t);
  const view={scale:1, ox:0, oy:0};
  let alpha=1, dragNode=null, hover=null, panning=false, panStart=null;
  mapState={raf:null, onUp:null};

  const toScreen=(n)=>[W/2+view.ox+n.x*view.scale, H/2+view.oy+n.y*view.scale];
  const toWorld=(px,py)=>[(px-W/2-view.ox)/view.scale, (py-H/2-view.oy)/view.scale];
  function pick(px,py){ const [wx,wy]=toWorld(px,py); let best=null,bd=1e9;
    for(const n of nodes){ const d=(n.x-wx)**2+(n.y-wy)**2; if(d<bd){bd=d;best=n;} }
    return bd < (14/view.scale)**2 ? best : null; }

  function tick(){
    if(alpha>0.02){
      for(let i=0;i<nodes.length;i++){ const a=nodes[i];
        for(let j=i+1;j<nodes.length;j++){ const b=nodes[j];
          let dx=a.x-b.x, dy=a.y-b.y, d2=dx*dx+dy*dy+0.01, d=Math.sqrt(d2), f=2400/d2;
          dx/=d; dy/=d; a.vx+=dx*f; a.vy+=dy*f; b.vx-=dx*f; b.vy-=dy*f; } }
      for(const e of edges){ let dx=e.t.x-e.s.x, dy=e.t.y-e.s.y, d=Math.sqrt(dx*dx+dy*dy)+0.01, f=(d-72)*0.02;
        dx/=d; dy/=d; e.s.vx+=dx*f; e.s.vy+=dy*f; e.t.vx-=dx*f; e.t.vy-=dy*f; }
      for(const n of nodes){ n.vx-=n.x*0.0022; n.vy-=n.y*0.0022;
        if(n.fx!=null){ n.x=n.fx; n.y=n.fy; n.vx=0; n.vy=0; }
        else { n.vx*=0.86; n.vy*=0.86; n.x+=n.vx; n.y+=n.vy; } }
      alpha*=0.99;
    }
    draw(); mapState.raf=requestAnimationFrame(tick);
  }
  function draw(){
    ctx.clearRect(0,0,W,H);
    ctx.lineWidth=1; ctx.strokeStyle="rgba(139,147,167,.22)";
    for(const e of edges){ const [sx,sy]=toScreen(e.s),[tx,ty]=toScreen(e.t);
      ctx.beginPath(); ctx.moveTo(sx,sy); ctx.lineTo(tx,ty); ctx.stroke(); }
    for(const n of nodes){ const [x,y]=toScreen(n), r=n.depth===0?7:5;
      ctx.beginPath(); ctx.arc(x,y,r,0,6.2832); ctx.fillStyle=typeColor(n.type); ctx.fill();
      if(n===hover||n.depth===0){ ctx.lineWidth=2; ctx.strokeStyle="#fff"; ctx.stroke(); } }
    if(hover){ const [x,y]=toScreen(hover); const txt=`${hover.type}: ${hover.value}`;
      ctx.font="12px system-ui"; const w=ctx.measureText(txt).width+12;
      ctx.fillStyle="rgba(0,0,0,.82)"; ctx.fillRect(x+8,y-23,w,18);
      ctx.fillStyle="#fff"; ctx.fillText(txt, x+14, y-10); }
  }
  function detail(n){ $("#map-detail").innerHTML =
    `<b style="color:${typeColor(n.type)}">${esc(n.type)}</b><br>${esc(n.value)}`+
    `<br><small class="tag">depth ${n.depth} · via ${esc(n.source_module)} · conf ${(+n.confidence||0).toFixed(2)}</small>`+
    (n.data&&Object.keys(n.data).length?`<pre>${esc(JSON.stringify(n.data,null,1)).slice(0,600)}</pre>`:""); }

  cv.onmousedown=(ev)=>{ const r=cv.getBoundingClientRect(), px=ev.clientX-r.left, py=ev.clientY-r.top;
    const n=pick(px,py);
    if(n){ dragNode=n; n.fx=n.x; n.fy=n.y; detail(n); }
    else { panning=true; panStart=[px-view.ox, py-view.oy]; } };
  cv.onmousemove=(ev)=>{ const r=cv.getBoundingClientRect(), px=ev.clientX-r.left, py=ev.clientY-r.top;
    if(dragNode){ const [wx,wy]=toWorld(px,py); dragNode.fx=wx; dragNode.fy=wy; alpha=Math.max(alpha,0.3); }
    else if(panning){ view.ox=px-panStart[0]; view.oy=py-panStart[1]; }
    else { hover=pick(px,py); cv.style.cursor=hover?"pointer":"grab"; } };
  cv.onwheel=(ev)=>{ ev.preventDefault(); const r=cv.getBoundingClientRect(), px=ev.clientX-r.left, py=ev.clientY-r.top;
    const [wx,wy]=toWorld(px,py), f=ev.deltaY<0?1.1:0.9;
    view.scale=Math.min(4, Math.max(0.25, view.scale*f));
    view.ox=px-W/2-wx*view.scale; view.oy=py-H/2-wy*view.scale; };
  mapState.onUp=()=>{ if(dragNode){ dragNode.fx=null; dragNode.fy=null; dragNode=null; } panning=false; };
  window.addEventListener("mouseup", mapState.onUp);
  tick();
}
$("#map-load").addEventListener("click", loadMap);

// --- Modules & keys --------------------------------------------------------
async function loadModules(){
  const mods = await (await fetch("/api/modules")).json();
  let h = `<table><thead><tr><th>Module</th><th>Consumes</th><th>Produces</th><th>Interaction</th><th>Auth</th><th>State</th></tr></thead><tbody>`;
  for(const m of mods){
    const auth = m.keyless ? `<span class="badge">keyless</span>`
      : `<span class="badge open">key: ${esc(m.requires_keys.join(","))}</span>`;
    const state = m.enabled ? `<span class="v FOUND">enabled</span>` : `<span class="v NOT_FOUND">needs key</span>`;
    h += `<tr><td><b>${esc(m.name)}</b></td><td><small>${esc(m.consumes.join(", "))}</small></td>`+
         `<td><small>${esc(m.produces.join(", ")||"—")}</small></td><td>${esc((m.contract||{}).interaction||"")}</td><td>${auth}</td><td>${state}</td></tr>`;
  }
  $("#modules").innerHTML = h + "</tbody></table>";
}
async function loadKeys(){
  const keys = await (await fetch("/api/keys")).json();
  let h = `<table><thead><tr><th>Key</th><th>Status</th><th>Used by</th><th>Configure</th></tr></thead><tbody>`;
  for(const k of keys){
    const status = k.configured ? `<span class="v FOUND">set (${esc(k.source)})</span>`
      : (k.optional ? `<span class="badge">optional</span>` : `<span class="v NOT_FOUND">not set</span>`);
    h += `<tr><td><b>${esc(k.name)}</b><br><small class="tag">${esc(k.description)}</small></td>`+
         `<td>${status}</td><td><small>${esc((k.modules||[]).join(", "))}</small></td>`+
         `<td><input data-key="${esc(k.name)}" type="password" placeholder="paste key…" style="width:150px" />`+
         ` <button class="setkey" data-key="${esc(k.name)}">Save</button>`+
         (k.source==="file" ? ` <button class="clearkey" data-key="${esc(k.name)}">Clear</button>` : "")+
         (k.source==="env" ? ` <small class="tag">(from env)</small>` : "")+`</td></tr>`;
  }
  $("#keys").innerHTML = h + "</tbody></table>";
  document.querySelectorAll(".setkey").forEach(b=>b.onclick=()=>
    saveKey(b.dataset.key, document.querySelector(`input[data-key="${b.dataset.key}"]`).value));
  document.querySelectorAll(".clearkey").forEach(b=>b.onclick=()=>saveKey(b.dataset.key, ""));
}
// --- Confidence analytics (self-contained canvas charts; no deps) ----------
function barChart(id, labels, values, color) {
  const cv = $("#" + id); if (!cv) return;
  const ctx = cv.getContext("2d"), W = cv.width, H = cv.height, pad = 24;
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(1, ...values), n = values.length;
  const bw = (W - pad * 2) / n;
  ctx.strokeStyle = "rgba(139,147,167,.3)"; ctx.beginPath();
  ctx.moveTo(pad, H - pad); ctx.lineTo(W - pad, H - pad); ctx.stroke();
  ctx.fillStyle = color || "#58a6ff"; ctx.font = "9px system-ui";
  values.forEach((v, i) => {
    const h = (v / max) * (H - pad * 2), x = pad + i * bw + 2;
    ctx.fillStyle = color || "#58a6ff";
    ctx.fillRect(x, H - pad - h, bw - 4, h);
    ctx.fillStyle = "#8b949e";
    if (v) ctx.fillText(String(v), x, H - pad - h - 2);
    ctx.fillText(labels[i], x, H - pad + 10);
  });
}

function lineChart(id, series) {
  // series: [{label, points:[y...], color}], shared x by index, y in [0,1]
  const cv = $("#" + id); if (!cv) return;
  const ctx = cv.getContext("2d"), W = cv.width, H = cv.height, pad = 24;
  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = "rgba(139,147,167,.3)"; ctx.beginPath();
  ctx.moveTo(pad, H - pad); ctx.lineTo(W - pad, H - pad); ctx.moveTo(pad, pad); ctx.lineTo(pad, H - pad); ctx.stroke();
  const n = Math.max(1, ...series.map(s => s.points.length));
  const dx = n > 1 ? (W - pad * 2) / (n - 1) : 0;
  const y = (v) => H - pad - Math.max(0, Math.min(1, v)) * (H - pad * 2);
  series.forEach((s, si) => {
    ctx.strokeStyle = s.color; ctx.fillStyle = s.color; ctx.lineWidth = 2; ctx.beginPath();
    s.points.forEach((v, i) => { const X = pad + i * dx; i ? ctx.lineTo(X, y(v)) : ctx.moveTo(X, y(v)); });
    ctx.stroke();
    s.points.forEach((v, i) => { ctx.beginPath(); ctx.arc(pad + i * dx, y(v), 2.5, 0, 6.29); ctx.fill(); });
    ctx.fillText(s.label, pad + 4, pad + 12 + si * 12);
  });
}

async function loadAnalytics() {
  const a = await (await fetch("/api/analytics")).json();
  if (!a.n_observations) { $("#conf-summary").innerHTML = "<p class='tag'>No observations yet — run a saved scan.</p>"; return; }
  const ic = a.independence_coverage;
  $("#conf-summary").innerHTML = `<div class="cluster">${a.n_observations} observations · `
    + `corroboration ${ic.distinct_sources} source(s) → <b>${ic.distinct_classes}</b> independent class(es) `
    + `<span class="bd-shadow">(inflation ${ic.inflation}×)</span></div>`;

  const h = a.confidence_histogram;
  barChart("conf-hist", h.map(b => b.lo.toFixed(1)), h.map(b => b.count), "#3fb950");

  const drift = a.calibration_drift;
  if (drift.length) lineChart("conf-drift", [
    { label: "Brier", color: "#f0883e", points: drift.map(d => d.brier) },
    { label: "ECE", color: "#bc8cff", points: drift.map(d => d.ece) },
  ]);

  const mix = a.verdict_mix, total = Object.values(mix).reduce((x, y) => x + y, 0) || 1;
  $("#conf-verdicts").innerHTML = Object.entries(mix).sort((x, y) => y[1] - x[1]).map(([v, c]) =>
    `<div class="vmix"><span class="v ${v}">${v}</span> <span class="bar"><span style="width:${Math.round(c / total * 100)}%"></span></span> ${c}</div>`).join("");

  $("#conf-terms").innerHTML = a.top_terms.length
    ? "<table><thead><tr><th>signal</th><th>count</th><th>mean Δ</th></tr></thead><tbody>"
      + a.top_terms.map(t => `<tr><td>${esc(t.term)}</td><td>${t.count}</td><td>${t.mean_delta >= 0 ? "+" : ""}${t.mean_delta.toFixed(2)}</td></tr>`).join("")
      + "</tbody></table>"
    : "<p class='tag'>No score breakdowns recorded yet.</p>";

  $("#conf-sources").innerHTML = a.source_health.length
    ? "<table><thead><tr><th>source</th><th>kind</th><th>reliability</th><th>ok</th><th>fail</th><th>breaker</th></tr></thead><tbody>"
      + a.source_health.map(s => `<tr><td>${esc(s.name)}</td><td>${esc(s.kind || "")}</td><td>${bar(s.reliability)}</td><td>${s.successes}</td><td>${s.failures}</td><td>${badge(s.breaker_state)}</td></tr>`).join("")
      + "</tbody></table>"
    : "<p class='tag'>No source health yet.</p>";
}

// --- Investigation reasoning ----------------------------------------------
async function loadReasoning() {
  let run = $("#reasoning-run").value.trim();
  if (!run) {
    const runs = await (await fetch("/api/runs")).json();
    if (!runs.length) {
      $("#reasoning-status").textContent = "No saved runs yet.";
      renderReasoning(null);
      return;
    }
    run = runs[0].id;
    $("#reasoning-run").value = run;
  }
  const response = await fetch(`/api/runs/${run}/reasoning`);
  const data = await response.json();
  if (!response.ok) {
    $("#reasoning-status").textContent = data.error || "Unable to load reasoning.";
    return;
  }
  const report = data.reasoning;
  $("#reasoning-status").textContent = report
    ? `run #${data.run_id}: ${(report.next_actions || []).length} next action(s)`
    : `run #${data.run_id}: no reasoning recorded`;
  renderReasoning(report);
}

$("#reasoning-load").addEventListener("click", loadReasoning);

// --- Insights (correlation-rule findings) ----------------------------------
const SEV_CLASS = { high:"FOUND", medium:"UNCERTAIN", low:"UNVERIFIABLE", info:"NOT_FOUND" };
const sevBadge = (s) => `<span class="v ${SEV_CLASS[s]||"NOT_FOUND"}">${esc(s)}</span>`;

async function loadInsights(){
  let run = $("#ins-run").value.trim();
  if (!run) {
    const runs = await (await fetch("/api/runs")).json();
    if (!runs.length) { $("#ins-status").textContent = "No runs yet — run a saved scan first."; $("#insights").innerHTML=""; return; }
    run = runs[0].id;
  }
  const d = await (await fetch(`/api/runs/${run}/rules`)).json();
  const items = d.insights || [];
  $("#ins-status").textContent = `run #${d.run_id}: ${items.length} insight(s)`;
  if (!items.length) { $("#insights").innerHTML = "<p class='tag'>No correlation rules fired for this run.</p>"; return; }
  $("#insights").innerHTML = items.map(h => {
    const ev = (h.evidence||[]).slice(0,8)
      .map(e=>`<span class="leg"><i style="background:${typeColor(e.type)}"></i>${esc(e.type)}: ${esc(e.value)}</span>`).join("");
    const key = (h.key && h.key !== "*") ? ` <small class="tag">· ${esc(h.key)}</small>` : "";
    return `<div class="cluster">${sevBadge(h.severity)} <b>${esc(h.title)}</b>${key}`+
           `<br><small>${esc(h.description)}</small>`+
           (ev ? `<div class="map-legend">${ev}</div>` : "")+`</div>`;
  }).join("");
}

async function loadCalibration(){
  const d = await (await fetch("/api/calibration")).json();
  const r = d.latest;
  if (!r || !r.n) { $("#calibration").innerHTML = "<p class='tag'>No calibration runs yet - run <code>specter calibrate</code>.</p>"; return; }
  const bins = (r.bins || []).filter(b => b.count).map(b => {
    const w = Math.round((b.empirical || 0) * 100);
    return `<tr><td>${b.lo.toFixed(1)}–${b.hi.toFixed(1)}</td><td>${b.count}</td>`
      + `<td>${b.mean_pred.toFixed(2)}</td><td>${b.empirical.toFixed(2)}</td>`
      + `<td><span class="bar"><span style="width:${w}%"></span></span></td></tr>`;
  }).join("");
  const cf = r.confusion_found || {};
  const imp = r.independence_impact;
  const quality = r.sample_quality || {};
  const warning = quality.warning ? `<br><small class="v UNCERTAIN">${esc(quality.warning)}</small>` : "";
  $("#calibration").innerHTML =
    `<div class="cluster"><b>Brier ${r.brier}</b> · ECE ${r.ece} · MCE ${r.mce} · `
    + `n=${r.n} (${r.positives}+/${r.negatives}-)<br>`
    + `<small>at FOUND≥${r.found_threshold}: FP-rate ${(cf.fp_rate*100||0).toFixed(0)}% · `
    + `precision ${(cf.precision||0).toFixed(2)} · recall ${(cf.recall||0).toFixed(2)}</small><br>`
    + `<small class="tag">${esc((r.suggestion||{}).rationale||"")}</small>`
    + warning
    + (imp ? `<br><small class="bd-shadow">independence flip: ${imp.entities_changed}/${imp.entities} entities would change (mean Δ ${imp.mean_abs_delta})</small>` : "")
    + `</div>`
    + `<table><thead><tr><th>bin</th><th>n</th><th>pred</th><th>empirical</th><th></th></tr></thead><tbody>${bins}</tbody></table>`;
}

async function loadRuleCatalogue(){
  const rules = await (await fetch("/api/rules")).json();
  let h = `<table><thead><tr><th>Severity</th><th>Rule</th><th>Kind</th><th>What it means</th></tr></thead><tbody>`;
  for (const r of rules)
    h += `<tr><td>${sevBadge(r.severity)}</td><td><b>${esc(r.title)}</b><br><small class="tag">${esc(r.id)}</small></td>`+
         `<td><span class="badge">${esc(r.kind)}</span></td><td><small>${esc(r.description)}</small></td></tr>`;
  $("#rulecat").innerHTML = h + "</tbody></table>";
}
$("#ins-load").addEventListener("click", loadInsights);

async function saveKey(name, value){
  const st = $("#keys-status");
  if (st) st.textContent = value ? `Saving ${name}…` : `Clearing ${name}…`;
  try {
    const r = await fetch("/api/keys", { method:"POST", headers:{"Content-Type":"application/json"},
                                         body: JSON.stringify({ name, value }) });
    const d = await r.json();
    if (!r.ok) { if (st) st.textContent = `Error: ${d.error || r.status}`; return; }
    if (st) st.textContent = d.configured ? `${name}: saved` : `${name}: cleared`;
  } catch (e) {
    if (st) st.textContent = `Error: ${e.message}`;
  }
  loadKeys(); loadModules();
}

// --- expansion and accounts ----------------------------------------------
async function loadExpansion(){
  const response = await fetch("/api/expansion");
  const data = await response.json();
  const rows = (data.checks || []).map(check =>
    `<tr><td><span class="v ${check.passed ? "FOUND" : "UNCERTAIN"}">${check.passed ? "PASS" : "BLOCK"}</span></td>`+
    `<td><b>${esc(check.name)}</b></td><td><small>${esc(check.detail)}</small></td></tr>`
  ).join("");
  $("#expansion-status").innerHTML =
    `<div class="cluster"><b>${data.expansion_ready ? "Expansion ready" : "Expansion blocked"}</b>`+
    `<br><small>requested: ${data.requested ? "yes" : "no"} · ML model: ${data.ml_model_configured ? "configured" : "not configured"} · remote: ${data.remote_mode ? "on" : "off"}</small></div>`+
    `<table><thead><tr><th>State</th><th>Check</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function loadUsers(){
  const response = await fetch("/api/users");
  if (!response.ok) return;
  const users = await response.json();
  $("#users").innerHTML = `<table><thead><tr><th>Account</th><th>Role</th><th>State</th><th></th></tr></thead><tbody>`+
    users.map(user => `<tr><td><b>${esc(user.username)}</b><br><small>${esc(user.display_name || "")}</small></td>`+
      `<td>${esc(user.role)}</td><td>${user.active ? "active" : "disabled"}</td>`+
      `<td><button class="user-toggle secondary" data-id="${user.id}" data-active="${user.active}">${user.active ? "Disable" : "Enable"}</button></td></tr>`).join("")+
    `</tbody></table>`;
  document.querySelectorAll(".user-toggle").forEach(button => button.onclick = async () => {
    const response = await fetch(`/api/users/${button.dataset.id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ active: button.dataset.active !== "true" }),
    });
    const data = await response.json();
    $("#user-status").textContent = response.ok ? "Account updated" : (data.error || "Update failed");
    if (response.ok) loadUsers();
  });
}

$("#user-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const response = await fetch("/api/users", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(form.entries())),
  });
  const data = await response.json();
  $("#user-status").textContent = response.ok ? `Created ${data.username}` : (data.error || "Create failed");
  if (response.ok) { event.currentTarget.reset(); loadUsers(); }
});

$("#pair-review-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    left_observation_id: Number(form.get("left_observation_id")),
    right_observation_id: Number(form.get("right_observation_id")),
    same_identity: form.get("decision") === "same",
    verification_method: form.get("verification_method"),
  };
  const response = await fetch("/api/pair-reviews", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
  const data = await response.json();
  $("#pair-review-status").textContent = response.ok ? `Recorded pair review #${data.id}` : (data.error || "Review failed");
  if (response.ok) event.currentTarget.reset();
});

bootstrapAuth().then(() => {
  const requestedTab = location.hash.slice(1);
  const requestedButton = document.querySelector(`#tabs button[data-tab="${CSS.escape(requestedTab)}"]`);
  const initialTab = (requestedButton && !requestedButton.hidden)
    ? requestedButton
    : document.querySelector("#tabs button.active");
  if (initialTab && !initialTab.classList.contains("active")) activateTab(initialTab, false);
}).catch(() => showLogin("Could not reach the server"));
