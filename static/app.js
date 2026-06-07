// NexusPi — dashboard logic

const ICONS = { wifi: "📡", sdr: "📻", rf: "🛰️", nfc: "💳", ir: "🔦",
                memory: "💾", box: "▣" };
const PHASE_ORDER = ["passive", "capture", "active", "rogue"];
const PHASE_LABEL = {
  passive: "Reconnaissance passive",
  capture: "Capture",
  active:  "Actif · émission",
  rogue:   "Rogue AP · MITM",
};

let MODULES = [];
let current = null;

const $ = (id) => document.getElementById(id);
const labOn = () => $("labtoggle").checked;
const esc = (s) => String(s).replace(/[&<>"']/g, c => (
  { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]
));

async function load() {
  try {
    const res = await fetch("/api/modules");
    MODULES = await res.json();
  } catch (e) {
    $("statusline").innerHTML = '<span style="color:#ff5c5c">● liaison perdue</span>';
    return;
  }
  renderGrid();
  const on = MODULES.filter((m) => m.connected).length;
  $("modcount").textContent = `${on}/${MODULES.length} module(s) en ligne`;
}

function renderGrid() {
  const grid = $("grid");
  grid.innerHTML = "";
  MODULES.forEach((m, i) => {
    const card = document.createElement("div");
    card.className = "card " + (m.connected ? "on" : "off");
    card.style.animationDelay = i * 60 + "ms";
    card.innerHTML = `
      <div class="top">
        <span class="ico">${ICONS[m.icon] || ICONS.box}</span>
        <span class="tag">${m.connected ? "ONLINE" : "OFFLINE"}</span>
      </div>
      <h3>${esc(m.name)}</h3>
      <p>${esc(m.description || "")}</p>
      <div class="count">${m.actions.length} action(s) disponible(s)</div>`;
    if (m.connected) card.onclick = () => openPanel(m);
    grid.appendChild(card);
  });
}

function openPanel(m) {
  current = m;
  $("pico").textContent = ICONS[m.icon] || ICONS.box;
  $("ptitle").textContent = m.name;
  $("console").innerHTML = "en attente…";
  updateClientsBadge(0);
  renderPhases(m);
  $("panel").classList.add("show");
  $("panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderPhases(m) {
  const phases = $("phases");
  phases.innerHTML = "";
  PHASE_ORDER.forEach((p) => {
    const acts = m.actions.filter((a) => a.phase === p);
    if (!acts.length) return;
    const block = document.createElement("div");
    block.className = "phase";
    block.dataset.p = p;
    block.innerHTML = `<div class="label">${PHASE_LABEL[p]}</div>`;
    acts.forEach((a) => block.appendChild(renderAction(m, a)));
    phases.appendChild(block);
  });
}

function renderAction(m, a) {
  const row = document.createElement("div");
  row.className = "act" + (a.lab_gated ? " gated" : "");
  const hasParams = Array.isArray(a.params) && a.params.length > 0;

  const lockHTML = a.lab_gated ? '<span class="lock">🔒 lab</span>' : "";
  row.innerHTML = `
    <div class="actrow">
      <div class="meta">
        <b>${esc(a.label)}</b>
        <span>${esc(a.description || "")}</span>
      </div>
      ${lockHTML}
      <button>EXÉCUTER</button>
    </div>
    ${hasParams ? '<div class="params"></div>' : ""}`;

  if (hasParams) {
    const pwrap = row.querySelector(".params");
    a.params.forEach((p) => pwrap.appendChild(renderParam(m, p)));
    wireTargetFiltering(m, row);
    wireModeDeps(row);
  }
  row.querySelector("button").onclick = () => runAction(m, a, row);
  return row;
}

function wireTargetFiltering(m, row) {
  const apSelect  = row.querySelector('label[data-name="bssid"] select');
  const staSelect = row.querySelector('label[data-name="client"] select');
  const dtcSelect = row.querySelector('label[data-name="deauth_target_client"] select');
  if (!apSelect) return;

  const refilter = () => {
    const target = (apSelect.value || "").toLowerCase();
    const all = (m.state && m.state.last_stations) || [];
    const matched = target
      ? all.filter(s => s.bssid && s.bssid.toLowerCase() === target)
      : all;
    let opts = '<option value="">Tous (broadcast)</option>';
    matched.forEach(s => {
      const assoc = s.ap_essid || s.bssid || "(libre)";
      const txt = `${s.mac} → ${assoc} · ${s.power}dBm`;
      opts += `<option value="${esc(s.mac)}">${esc(txt)}</option>`;
    });
    if (!matched.length && all.length) {
      opts += '<option disabled>— aucun client connu (lance "Clients & probes") —</option>';
    }
    if (staSelect && !staSelect.disabled) staSelect.innerHTML = opts;
    if (dtcSelect && !dtcSelect.disabled) dtcSelect.innerHTML = opts;
  };

  apSelect.addEventListener("change", refilter);
  refilter();
}

function wireModeDeps(row) {
  const sel = (name) => row.querySelector(`label[data-name="${name}"]`);
  const val = (name) => {
    const s = row.querySelector(`label[data-name="${name}"] select`);
    return s ? s.value : "";
  };
  const show = (name, vis) => {
    const el = sel(name);
    if (el) el.style.display = vis ? "" : "none";
  };

  const modeEl     = sel("mode");
  const authEl     = sel("auth_mode");
  const templateEl = sel("template");
  const deauthEl   = sel("deauth_continuous");
  if (!modeEl) return;

  const refresh = () => {
    const mode = val("mode");
    const isCaptive = mode === "captive" || mode === "captive_nat";
    const isMitm    = mode === "mitm" || mode === "mitm_https";

    show("template",            isCaptive);
    show("custom_portal_html",  isCaptive && val("template") === "custom");
    show("portal_name",         isCaptive);
    show("payload_preset",      isMitm);
    show("inject_script",       isMitm);
    show("strip_https",         mode === "mitm");
    show("wpa2_password",       val("auth_mode") === "wpa2");
    show("deauth_target_client", val("deauth_continuous") === "yes");
  };

  modeEl.querySelector("select").addEventListener("change", refresh);
  if (authEl)     authEl.querySelector("select").addEventListener("change", refresh);
  if (templateEl) templateEl.querySelector("select").addEventListener("change", refresh);
  if (deauthEl)   deauthEl.querySelector("select").addEventListener("change", refresh);
  refresh();
}

function renderParam(m, p) {
  const label = document.createElement("label");
  label.dataset.name = p.name;

  if (p.type === "target_ap") {
    const aps = (m.state && m.state.last_aps) || [];
    if (aps.length) {
      const opts = aps.map(a => {
        const txt = `${a.essid} · ch${a.channel} · ${a.power}dBm · ${a.bssid}`;
        return `<option value="${esc(a.bssid)}">${esc(txt)}</option>`;
      }).join("");
      label.innerHTML = `${esc(p.label)} <select>${opts}</select>`;
    } else {
      label.innerHTML = `${esc(p.label)} <select disabled><option>— lance un scan d'abord —</option></select>`;
    }
  } else if (p.type === "target_ap_optional") {
    const aps = (m.state && m.state.last_aps) || [];
    let opts = '<option value="">Tous les réseaux</option>';
    aps.forEach(a => {
      const txt = `${a.essid} · ch${a.channel} · ${a.power}dBm · ${a.bssid}`;
      opts += `<option value="${esc(a.bssid)}">${esc(txt)}</option>`;
    });
    label.innerHTML = `${esc(p.label)} <select>${opts}</select>`;
  } else if (p.type === "target_station") {
    const stations = (m.state && m.state.last_stations) || [];
    let opts = '<option value="">Tous (broadcast)</option>';
    stations.forEach(s => {
      const assoc = s.ap_essid || s.bssid || "(libre)";
      const txt = `${s.mac} → ${assoc} · ${s.power}dBm`;
      opts += `<option value="${esc(s.mac)}">${esc(txt)}</option>`;
    });
    label.innerHTML = `${esc(p.label)} <select>${opts}</select>`;
  } else if (p.type === "memory_network") {
    const nets = (m.state && m.state.memory_networks) || [];
    if (nets.length) {
      const opts = nets.map(n => {
        const tag = `${n.essid || "<hidden>"} · ${n.bssid}`
                  + ` · ${n.handshakes}hs/${n.pmkid}pk`;
        return `<option value="${esc(n.bssid)}">${esc(tag)}</option>`;
      }).join("");
      label.innerHTML = `${esc(p.label)} <select>${opts}</select>`;
    } else {
      label.innerHTML = `${esc(p.label)} <select disabled><option>— mémoire vide —</option></select>`;
    }
  } else if (p.type === "int") {
    const d   = p.default ?? 0;
    const mn  = p.min ?? 0;
    const mx  = p.max ?? 999999;
    label.innerHTML = `${esc(p.label)} <input type="number" min="${mn}" max="${mx}" value="${d}">`;
  } else if (p.type === "select") {
    const opts = (p.options || []).map(o => {
      const sel = (o.value === (p.default ?? "")) ? " selected" : "";
      return `<option value="${esc(o.value)}"${sel}>${esc(o.label)}</option>`;
    }).join("");
    label.innerHTML = `${esc(p.label)} <select>${opts}</select>`;
  } else if (p.type === "textarea") {
    const d  = esc(p.default ?? "");
    const ph = esc(p.placeholder ?? "");
    label.innerHTML = `${esc(p.label)} <textarea placeholder="${ph}" rows="3">${d}</textarea>`;
  } else if (p.type === "checkboxes") {
    let html = `<span class="cb-label">${esc(p.label)}</span><div class="cb-group">`;
    (p.options || []).forEach(o => {
      html += `<label class="cb-item"><input type="checkbox" value="${esc(o.value)}"> ${esc(o.label)}</label>`;
    });
    html += '</div>';
    label.innerHTML = html;
    label.classList.add("cb-wrap");
  } else if (p.type === "text") {
    const d   = esc(p.default ?? "");
    const ph  = esc(p.placeholder ?? "");
    label.innerHTML = `${esc(p.label)} <input type="text" placeholder="${ph}" value="${d}">`;
  } else {
    label.innerHTML = `${esc(p.label)} <input type="text">`;
  }
  return label;
}

function collectParams(row) {
  const out = {};
  row.querySelectorAll(".params > label").forEach((l) => {
    if (l.style.display === "none") return;
    if (l.classList.contains("cb-wrap")) {
      const checked = [];
      l.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
        checked.push(cb.value);
      });
      out[l.dataset.name] = checked.join(",");
      return;
    }
    const ta = l.querySelector("textarea");
    if (ta) { out[l.dataset.name] = ta.value; return; }
    const inp = l.querySelector("select, input");
    if (!inp || inp.disabled) return;
    out[l.dataset.name] = inp.type === "number" ? Number(inp.value) : inp.value;
  });
  return out;
}

let currentTaskId = null;
let pollTimer = null;

async function runAction(m, a, row) {
  if (a.lab_gated && !labOn()) {
    log(`✗ "${a.label}" verrouillé — active le Lab mode.`, "err");
    return;
  }
  if (currentTaskId) {
    log(`⚠ Une tâche est déjà en cours (${currentTaskId}). Arrête-la d'abord.`, "warn");
    return;
  }
  const needsAp = (a.params || []).some(p => p.type === "target_ap");
  const apSel = row.querySelector('label[data-name="bssid"] select');
  if (needsAp && apSel && (apSel.disabled || !apSel.value)) {
    log(`✗ Aucun AP sélectionné — lance un Scan d'abord.`, "err");
    return;
  }
  const params = collectParams(row);
  const ptxt = Object.keys(params).length ? " " + JSON.stringify(params) : "";
  log(`→ ${a.label}${ptxt} …`);

  try {
    const res = await fetch(`/api/modules/${m.id}/run/${a.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ params, lab_mode: labOn() }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      log(`✗ ${err.error || res.statusText}`, "err");
      return;
    }
    const data = await res.json();
    if (data.task_id) {
      currentTaskId = data.task_id;
      showStopButton(data.task_id);
      pollTask(data.task_id, 0);
    } else {
      if (data.ok) log(`✓ ${data.message || JSON.stringify(data)}`, "ok");
      else log(`✗ ${data.error || "échec"}`, "err");
      await postActionRefresh(m);
    }
  } catch (e) {
    log(`✗ erreur réseau : ${e}`, "err");
  }
}

async function pollTask(tid, since) {
  try {
    const r = await fetch(`/api/tasks/${tid}?since=${since}`);
    if (!r.ok) {
      log(`✗ task ${tid} introuvable`, "err");
      finalizeTask();
      return;
    }
    const t = await r.json();
    (t.logs || []).forEach((l) => {
      // Messages meta : compteur clients (pas affiché en console)
      const metaMatch = l.msg.match(/^__CLIENTS:(\d+)__$/);
      if (metaMatch) {
        updateClientsBadge(parseInt(metaMatch[1]));
        return;
      }
      const cls = l.level === "error" ? "err" : (l.level === "warn" ? "warn" : "");
      const tag = `<span class="ts">[${new Date(l.ts * 1000).toLocaleTimeString()}]</span>`;
      $("console").innerHTML += `\n${tag} <span class="${cls}">· ${l.msg}</span>`;
      $("console").scrollTop = $("console").scrollHeight;
    });
    const newSince = t.log_total || since;
    if (t.status === "running") {
      pollTimer = setTimeout(() => pollTask(tid, newSince), 1000);
    } else {
      const res = t.result || {};
      if (res.ok) log(`✓ ${res.message || JSON.stringify(res)}`, "ok");
      else if (res.error) log(`✗ ${res.error}`, "err");
      else log(`${t.status === "stopped" ? "⛔ Arrêté" : "Terminé"} (sans résultat)`, "warn");
      finalizeTask();
      const mod = MODULES.find((mm) => current && mm.id === current.id);
      if (mod) await postActionRefresh({ id: mod.id });
    }
  } catch (e) {
    log(`✗ polling : ${e}`, "err");
    finalizeTask();
  }
}

function finalizeTask() {
  currentTaskId = null;
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  hideStopButton();
  updateClientsBadge(0);
}

async function stopCurrentTask() {
  if (!currentTaskId) return;
  log(`⛔ Stop demandé pour ${currentTaskId}…`, "warn");
  try {
    await fetch(`/api/tasks/${currentTaskId}/stop`, { method: "POST" });
  } catch (e) {
    log(`✗ stop : ${e}`, "err");
  }
}

function showStopButton(tid) {
  const btn = $("stopbtn");
  if (!btn) return;
  btn.style.display = "flex";
  btn.dataset.taskId = tid;
  btn.querySelector(".lbl").textContent = `ARRÊTER (${tid})`;
}

function hideStopButton() {
  const btn = $("stopbtn");
  if (btn) btn.style.display = "none";
}

function updateClientsBadge(n) {
  const badge = $("clients-badge");
  if (!badge) return;
  if (n > 0) {
    badge.style.display = "flex";
    badge.textContent = `📱 ${n} client${n > 1 ? "s" : ""} connecté${n > 1 ? "s" : ""}`;
  } else {
    badge.style.display = "none";
  }
}

function copyConsoleLogs() {
  const c = $("console");
  if (!c) return;
  const text = c.innerText || c.textContent || "";
  navigator.clipboard.writeText(text).then(() => {
    const btn = $("copybtn");
    if (btn) { btn.textContent = "✓ copié"; setTimeout(() => { btn.textContent = "📋 Copier"; }, 1500); }
  });
}

async function postActionRefresh(m) {
  await load();
  if (current) {
    const updated = MODULES.find((mm) => mm.id === current.id);
    if (updated && $("panel").classList.contains("show")) {
      current = updated;
      renderPhases(updated);
    }
  }
}

function log(msg, cls = "") {
  const ts = new Date().toLocaleTimeString();
  const c = $("console");
  c.innerHTML += `\n<span class="ts">[${ts}]</span> <span class="${cls}">${msg}</span>`;
  c.scrollTop = c.scrollHeight;
}

$("pclose").onclick = () => $("panel").classList.remove("show");
$("labtoggle").onchange = () => document.body.classList.toggle("lab", labOn());

load();
setInterval(load, 8000);
