// NexusPi — app.js
// Command center : modules, action cards, console rail, live scan

/* ===================================================
   CONSTANTES & DESIGN
   =================================================== */
const PHASE_ORDER = ["passive", "capture", "active", "rogue"];
const PHASE_META = {
  passive: { label: "RECONNAISSANCE", color: "var(--cyan)" },
  capture: { label: "CAPTURE",        color: "var(--amber)" },
  active:  { label: "ACTIF",          color: "var(--orange)" },
  rogue:   { label: "ROGUE",          color: "var(--red)" },
};

const MODULE_SVGS = {
  sdr:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2 16c2-1 3-7 5-7s3 11 5 11 3-15 5-15 3 9 5 8"/></svg>',
  wifi:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12a10 10 0 0114 0M8.5 15.5a5 5 0 017 0"/><circle cx="12" cy="19" r="1" fill="currentColor"/></svg>',
  nfc:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 9c2 0 2 6 0 6M11 9c4 0 4 6 0 6" stroke-linecap="round"/></svg>',
  ir:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="6" cy="18" r="2"/><path d="M6 12a6 6 0 016 6M6 6a12 12 0 0112 12"/></svg>',
  memory: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>',
  rf:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2v20M5 8a9 9 0 0114 0M8 11a5 5 0 018 0"/></svg>',
  box:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l10 5v10l-10 5-10-5V7z"/></svg>',
};

const MODULE_COLORS = {
  sdr:    { glow: "rgba(52,224,196,.1)",   stroke: "var(--cyan)" },
  wifi:   { glow: "rgba(255,77,77,.1)",    stroke: "var(--red)" },
  nfc:    { glow: "rgba(52,224,196,.1)",   stroke: "var(--cyan)" },
  ir:     { glow: "rgba(155,140,255,.12)", stroke: "var(--violet)" },
  rf:     { glow: "rgba(255,176,0,.1)",    stroke: "var(--amber)" },
  memory: { glow: "rgba(90,100,108,.1)",   stroke: "var(--txt-faint)" },
};

/* ===================================================
   ETAT GLOBAL
   =================================================== */
let MODULES = [];
let current = null;
let currentTaskId = null;
let currentTaskModuleId = null;
let pollTimer = null;
let moduleViewsRendered = {};
let liveAps = [];
let liveStations = [];
let liveSignals = [];
let liveSpectrum = [];
let sdrTargetFreq = ""; // Hz string, "" = pas de filtre
// Logs console par module { moduleId: [{msg, cls}] }
let consoleLogs = {};

/* ===================================================
   UTILITAIRES
   =================================================== */
const $ = (id) => document.getElementById(id);
const labOn = () => $("labtoggle").checked;
const esc = (s) => String(s).replace(/[&<>"']/g, c =>
  ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));

function getModuleSvg(m) { return MODULE_SVGS[m.icon] || MODULE_SVGS[m.id] || MODULE_SVGS.box; }
function getModuleColor(m) { return MODULE_COLORS[m.icon] || MODULE_COLORS[m.id] || MODULE_COLORS.memory; }

/* ===================================================
   NAVIGATION
   =================================================== */
function go(id) {
  document.querySelectorAll(".view").forEach(v =>
    v.classList.toggle("active", v.id === "view-" + id));
  document.querySelectorAll(".navbtn[data-view]").forEach(b =>
    b.classList.toggle("active", b.dataset.view === id));
  document.querySelectorAll(".mobnav .mb").forEach(b =>
    b.classList.toggle("active", b.dataset.view === id));
  document.querySelector(".main").scrollTop = 0;

  const m = MODULES.find(mm => mm.id === id);
  if (m && m.id !== "memory") {
    current = m;
    if (!moduleViewsRendered[id]) {
      ensureModuleView(m);
      moduleViewsRendered[id] = true;
    }
  }
  if (id === "captures") renderCapturesView();
}

function initNavigation() {
  document.querySelectorAll("[data-view]").forEach(b =>
    b.addEventListener("click", () => go(b.dataset.view)));
}

/* ===================================================
   CHARGEMENT
   =================================================== */
async function load() {
  try {
    const res = await fetch("/api/modules");
    MODULES = await res.json();
  } catch (e) {
    $("link-val").textContent = "deconnecte";
    $("pill-link").className = "pill link-err";
    return;
  }
  $("link-val").textContent = "connecte";
  $("pill-link").className = "pill link-ok";
  const on = MODULES.filter(m => m.connected).length;
  $("mod-count-pill").textContent = `${on}/${MODULES.length}`;
  renderSidebar();
  renderDashboard();
}

/* ===================================================
   SIDEBAR
   =================================================== */
function renderSidebar() {
  const container = $("nav-modules");
  const curView = document.querySelector(".navbtn.active[data-view]");
  const activeId = curView ? curView.dataset.view : "dashboard";
  container.innerHTML = "";
  MODULES.forEach(m => {
    if (m.id === "memory") return;
    const btn = document.createElement("div");
    btn.className = "navbtn" + (!m.connected ? " offline" : "");
    btn.dataset.view = m.id;
    if (m.id === activeId) btn.classList.add("active");
    const badge = m.connected
      ? `<span class="badge">${m.actions.length}</span>`
      : '<span class="badge">OFF</span>';
    btn.innerHTML = `${getModuleSvg(m)} ${esc(m.name)} ${badge}`;
    btn.addEventListener("click", () => go(m.id));
    container.appendChild(btn);
  });
  renderMobileNav(activeId);
}

function renderMobileNav(activeId) {
  const mobnav = $("mobnav");
  mobnav.innerHTML = "";
  const dashSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>';
  [{ id: "dashboard", svg: dashSvg, label: "HOME" },
    ...MODULES.filter(m => m.id !== "memory").map(m => ({
      id: m.id, svg: getModuleSvg(m), label: m.name.substring(0, 5).toUpperCase(),
    }))
  ].forEach(e => {
    const mb = document.createElement("div");
    mb.className = "mb" + (e.id === activeId ? " active" : "");
    mb.dataset.view = e.id;
    mb.innerHTML = `${e.svg}${e.label}`;
    mb.addEventListener("click", () => go(e.id));
    mobnav.appendChild(mb);
  });
}

/* ===================================================
   DASHBOARD
   =================================================== */
function renderDashboard() {
  const on = MODULES.filter(m => m.connected).length;
  const total = MODULES.reduce((s, m) => s + m.actions.length, 0);
  $("dash-stats").innerHTML = `
    <div class="stat cyan"><div class="sv">${on}<span class="u">/${MODULES.length}</span></div><div class="sl">Modules connectes</div></div>
    <div class="stat"><div class="sv">${total}</div><div class="sl">Actions disponibles</div></div>`;
  const grid = $("dash-grid");
  grid.innerHTML = "";
  MODULES.forEach(m => {
    if (m.id === "memory") return;
    const col = getModuleColor(m);
    const card = document.createElement("div");
    card.className = "modcard" + (!m.connected ? " off" : "");
    card.style.setProperty("--gl", m.connected ? col.glow : "transparent");
    const svgColored = getModuleSvg(m).replace('stroke="currentColor"', `stroke="${col.stroke}"`);
    card.innerHTML = `
      <div class="mc-top">
        <div class="mc-ico">${svgColored}</div>
        <span class="tagchip ${m.connected ? "t-cyan" : "t-grey"}">${m.connected ? "ONLINE" : "OFFLINE"}</span>
      </div>
      <h4>${esc(m.name)}</h4>
      <p>${esc(m.description || "")}</p>
      <div class="mc-hw">
        <span class="status-dot ${m.connected ? "s-on" : "s-off"}"></span>
        ${m.actions.length} action(s)
      </div>`;
    if (m.connected) card.onclick = () => go(m.id);
    grid.appendChild(card);
  });
}

/* ===================================================
   VUES MODULES — command center layout
   =================================================== */
function ensureModuleView(m) {
  let view = $("view-" + m.id);
  if (!view) {
    view = document.createElement("section");
    view.className = "view";
    view.id = "view-" + m.id;
    $("module-views").appendChild(view);
  }
  refreshModuleView(m, view);
}

function refreshModuleView(m, view) {
  // Section live scan — au-dessus du cmd-layout
  let liveHTML = "";
  if (m.id === "wifi") {
    liveHTML = `
      <div id="wifi-live" class="live-scan" style="display:none">
        <div class="live-header">
          <h2>Reseaux detectes</h2>
          <span class="live-count" id="ap-count"></span>
        </div>
        <div class="ap-grid" id="ap-grid"></div>
      </div>
      <div id="wifi-stations-live" class="live-scan" style="display:none">
        <div class="live-header">
          <h2>Stations detectees</h2>
          <span class="live-count" id="sta-count"></span>
        </div>
        <div class="sta-grid" id="sta-grid"></div>
      </div>`;
  }
  if (m.id === "sdr") {
    const ambCnt = (m.state && m.state.ambient_count) || 0;
    liveHTML += `
      <div id="sdr-filter" class="filter-block">
        <div class="fb-head">
          <span class="fb-title">FILTRE AMBIANT</span>
          <span class="fb-badge" id="fb-badge">${ambCnt} source(s)</span>
        </div>
        <div class="fb-body">
          <label class="fb-check">
            <input type="checkbox" id="sig-hide-ambient" checked>
            <span>Masquer les signaux permanents (bruit de fond)</span>
          </label>
          <div class="fb-hint">Les 8 premieres secondes de chaque scan detectent le bruit ambiant. Les sources deja connues restent filtrees entre les scans.</div>
        </div>
      </div>
      <div id="sdr-target" class="sdr-target" style="display:none">
        <span>🎯 Cible : <b id="sdr-target-txt"></b></span>
        <button onclick="clearTargetFreq()">✕</button>
      </div>
      <div id="sdr-live" class="live-scan" style="display:none">
        <div class="live-header">
          <h2>Signaux detectes</h2>
          <span class="live-count" id="sig-count"></span>
        </div>
        <div id="sig-ambient-note" class="sig-ambient-note" style="display:none"></div>
        <div class="sig-grid" id="sig-grid"></div>
      </div>
      <div id="sdr-spectrum" class="live-scan" style="display:none">
        <div class="live-header">
          <h2>Spectre radio</h2>
          <span class="live-count" id="spec-count"></span>
        </div>
        <div class="sig-grid" id="spec-grid"></div>
      </div>`;
  }

  // Construire la vue
  view.innerHTML = `
    <div class="view-head">
      <h1>${esc(m.name)}</h1>
      <span class="sub">${esc(m.description || "")}</span>
    </div>
    <div class="cmd-bar" id="bar-${m.id}"></div>
    ${liveHTML}
    <div class="cmd-layout">
      <div class="lib" id="lib-${m.id}"></div>
      <div class="rail">
        ${buildConsoleHTML(m.id)}
      </div>
    </div>`;

  if (m.connected) {
    buildCmdBar(m);
    renderSections(m);
  } else {
    $("lib-" + m.id).innerHTML = `
      <div class="note" style="margin-top:12px">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="9"/></svg>
        <span>Module deconnecte. Verifiez le branchement materiel.</span>
      </div>`;
  }

  // Restaurer logs console
  restoreConsoleLogs(m.id);

  // Restaurer donnees live wifi
  if (m.id === "wifi") {
    const aps = liveAps.length ? liveAps : (m.state && m.state.last_aps) || [];
    if (aps.length) { liveAps = aps; renderLiveAps(aps); }
    const stas = liveStations.length ? liveStations : (m.state && m.state.last_stations) || [];
    if (stas.length) { liveStations = stas; renderLiveStations(stas); }
  }
  // Restaurer donnees live SDR + wiring filtre
  if (m.id === "sdr") {
    wireSdrFilter();
    const sigs = liveSignals.length ? liveSignals : (m.state && m.state.last_signals) || [];
    if (sigs.length) { liveSignals = sigs; renderLiveSignals(sigs); }
    if (liveSpectrum.length) renderSpectrumCards(liveSpectrum);
  }
}

/* ===================================================
   BARRE DE COMMANDE — filtre phases + lab switch
   =================================================== */
function buildCmdBar(m) {
  const bar = $("bar-" + m.id);
  if (!bar) return;
  const phaseSet = new Set(m.actions.map(a => a.phase));
  const phases = PHASE_ORDER.filter(p => phaseSet.has(p));

  // Filtre phases
  let pf = '<div class="phasefilter"><button class="on" data-f="all">Tous</button>';
  phases.forEach(p => {
    const meta = PHASE_META[p] || { label: p.toUpperCase(), color: "var(--txt-dim)" };
    pf += `<button data-f="${p}"><span class="pd" style="background:${meta.color}"></span>${meta.label}</button>`;
  });
  pf += '</div>';

  // Lab switch
  const armed = labOn();
  pf += `<div class="lab-switch${armed ? " armed" : ""}" id="ls-${m.id}">
    <div><div class="ls-t">MODE LAB</div><div class="ls-sub">actions offensives</div></div>
    <span class="toggle red"><input type="checkbox" id="labmod-${m.id}"${armed ? " checked" : ""}>
    <label for="labmod-${m.id}"></label></span>
  </div>`;
  bar.innerHTML = pf;

  // Wire phase filter
  bar.querySelectorAll(".phasefilter button").forEach(b => b.addEventListener("click", () => {
    bar.querySelectorAll(".phasefilter button").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    const f = b.dataset.f;
    const lib = $("lib-" + m.id);
    if (lib) lib.querySelectorAll(".section").forEach(s =>
      s.style.display = (f === "all" || s.dataset.phase === f) ? "" : "none");
  }));

  // Wire lab switch
  const labInput = $("labmod-" + m.id);
  if (labInput) labInput.addEventListener("change", () => {
    syncLab(labInput.checked);
  });
}

/* ===================================================
   SECTIONS & CARTES D'ACTION
   =================================================== */
function renderSections(m) {
  const lib = $("lib-" + m.id);
  if (!lib) return;
  lib.innerHTML = "";

  PHASE_ORDER.forEach(p => {
    const acts = m.actions.filter(a => a.phase === p);
    if (!acts.length) return;
    const meta = PHASE_META[p] || { label: p.toUpperCase(), color: "var(--txt-dim)" };
    const section = document.createElement("div");
    section.className = "section";
    section.dataset.phase = p;
    section.style.setProperty("--pa", meta.color);

    section.innerHTML = `
      <div class="section-head">
        <span class="sh-dot"></span>
        <span class="sh-t">${meta.label}</span>
        <span class="sh-line"></span>
        <span class="sh-n">${acts.length}</span>
      </div>
      <div class="cards"></div>`;

    const grid = section.querySelector(".cards");
    acts.forEach(a => grid.appendChild(renderActionCard(m, a, p)));
    lib.appendChild(section);
  });
}

function renderActionCard(m, a, phase) {
  const card = document.createElement("div");
  const isLocked = a.lab_gated && !labOn();
  card.className = "acard" + (isLocked ? " locked" : "");
  card.dataset.moduleId = m.id;
  card.dataset.actionId = a.id;
  card.dataset.labGated = a.lab_gated ? "1" : "";

  const labChip = a.lab_gated ? '<span class="lab-chip">LAB</span>' : '';
  const hintHTML = a.hint ? `<div class="ac-hint">ex : <b>${esc(a.hint)}</b></div>` : '';
  const hasParams = Array.isArray(a.params) && a.params.length > 0;

  let paramsHTML = "";
  if (hasParams) {
    paramsHTML = '<div class="params">';
    a.params.forEach(p => { paramsHTML += renderField(m, p); });
    paramsHTML += '</div>';
  }

  card.innerHTML = `
    ${labChip}
    <span class="lockhint">LAB requis</span>
    <div class="ac-top"><span class="ac-title">${esc(a.label)}</span></div>
    <div class="ac-desc">${esc(a.description || "")}</div>
    ${hintHTML}
    ${paramsHTML}
    <button class="exec">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l14 9-14 9z"/></svg>
      EXECUTER
    </button>`;

  // Wire range live values
  card.querySelectorAll('input[type=range]').forEach(r => {
    const rv = r.parentElement.querySelector('.rv');
    if (rv) r.addEventListener('input', () => rv.textContent = r.value + (r.dataset.suf || ''));
  });

  // Wire param dependencies
  if (hasParams) {
    wireTargetFiltering(m, card);
    wireModeDeps(card);
    wireShowIf(card, a.params);
    wireFreqCustom(card);
    wireSignalButtons(m, card);
  }

  // Wire exec button
  card.querySelector(".exec").onclick = () => runAction(m, a, card);

  return card;
}

/* ===================================================
   FIELDS — generation des inputs dans les cartes
   =================================================== */
function renderField(m, p) {
  const name = esc(p.name);
  const label = esc(p.label).toUpperCase();

  if (p.type === "target_ap") {
    const aps = (m.state && m.state.last_aps) || [];
    let opts = "";
    if (aps.length) {
      opts = aps.map(a => {
        const txt = `${a.essid} · ch${a.channel} · ${a.power}dBm`;
        return `<option value="${esc(a.bssid)}">${esc(txt)}</option>`;
      }).join("");
    } else {
      opts = '<option disabled selected>scan requis</option>';
    }
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select${!aps.length ? " disabled" : ""}>${opts}</select></div>`;
  }

  if (p.type === "target_ap_optional") {
    const aps = (m.state && m.state.last_aps) || [];
    let opts = '<option value="">Tous les reseaux</option>';
    aps.forEach(a => {
      const txt = `${a.essid} · ch${a.channel} · ${a.power}dBm`;
      opts += `<option value="${esc(a.bssid)}">${esc(txt)}</option>`;
    });
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select>${opts}</select></div>`;
  }

  if (p.type === "target_station") {
    const stations = (m.state && m.state.last_stations) || [];
    let opts = '<option value="">Tous (broadcast)</option>';
    stations.forEach(s => {
      const assoc = s.ap_essid || s.bssid || "(libre)";
      const txt = `${s.mac} → ${assoc}`;
      opts += `<option value="${esc(s.mac)}">${esc(txt)}</option>`;
    });
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select>${opts}</select></div>`;
  }

  if (p.type === "target_wps_ap") {
    const wps = (m.state && m.state.last_wps_aps) || [];
    let opts = '<option value="_all">Tous les reseaux WPS</option>';
    if (wps.length) {
      wps.forEach(w => {
        const lck = w.wps_locked ? " [LOCKED]" : "";
        const txt = `${w.essid} · ${w.bssid} · ch${w.channel} WPS${w.wps_version}${lck}`;
        opts += `<option value="${esc(w.bssid)}">${esc(txt)}</option>`;
      });
    } else {
      opts = '<option value="_all" selected>Scan WPS requis</option>';
    }
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select>${opts}</select></div>`;
  }

  if (p.type === "ir_signal") {
    const sigs = (m.state && m.state.saved_signals) || [];
    let opts = "";
    if (sigs.length) {
      opts = sigs.map(s => {
        const kb = s.size ? Math.round(s.size / 1024) + " KB" : "";
        const txt = kb ? `${s.name} · ${kb}` : s.name;
        return `<option value="${esc(s.file)}">${esc(txt)}</option>`;
      }).join("");
    } else {
      opts = '<option disabled selected>capture un signal d\'abord</option>';
    }
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select${!sigs.length ? " disabled" : ""}>${opts}</select></div>`;
  }

  if (p.type === "nfc_dump") {
    const dumps = (m.state && m.state.saved_dumps) || [];
    let opts = "";
    if (dumps.length) {
      opts = dumps.map(d => {
        const kb = d.size ? Math.round(d.size / 1024) + " KB" : "";
        const txt = kb ? `${d.name} · ${kb}` : d.name;
        return `<option value="${esc(d.file)}">${esc(txt)}</option>`;
      }).join("");
    } else {
      opts = '<option disabled selected>aucun dump — fais un dump d\'abord</option>';
    }
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select${!dumps.length ? " disabled" : ""}>${opts}</select></div>`;
  }

  if (p.type === "memory_network") {
    const nets = (m.state && m.state.memory_networks) || [];
    let opts = "";
    if (nets.length) {
      opts = nets.map(n => {
        const tag = `${n.essid || "<hidden>"} · ${n.bssid}`;
        return `<option value="${esc(n.bssid)}">${esc(tag)}</option>`;
      }).join("");
    } else {
      opts = '<option disabled>memoire vide</option>';
    }
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select${!nets.length ? " disabled" : ""}>${opts}</select></div>`;
  }

  if (p.type === "freq") {
    const opts = (p.options || []).map(o => {
      const txt = o.hint ? `${o.label} - ${o.hint}` : o.label;
      return `<option value="${esc(o.value)}">${esc(txt)}</option>`;
    }).join("") + '<option value="_custom">Personnalise...</option>';
    return `<div class="field freq-field" data-name="${name}"><span class="fl">${label}</span>
      <select>${opts}</select>
      <input type="text" class="freq-custom-input" placeholder="ex: 432 MHz" style="display:none"></div>`;
  }

  if (p.type === "signal_file") {
    const files = (m.state && m.state.signal_files) || [];
    let opts = "";
    if (files.length) {
      opts = files.map(f => {
        const freqMhz = f.freq !== "?" ? (f.freq / 1e6).toFixed(2).replace(/\.?0+$/, "") + " MHz" : "";
        const kb = f.size ? Math.round(f.size / 1024) + " KB" : "";
        let txt = f.label || f.name;
        if (f.label && freqMhz) txt += ` · ${freqMhz}`;
        else if (!f.label && freqMhz) txt = `${freqMhz} · ${f.name}`;
        if (kb) txt += ` · ${kb}`;
        return `<option value="${esc(f.path)}">${esc(txt)}</option>`;
      }).join("");
    } else {
      opts = '<option disabled>enregistre un signal d\'abord</option>';
    }
    return `<div class="field sig-field" data-name="${name}"><span class="fl">${label}</span>
      <select${!files.length ? " disabled" : ""}>${opts}</select>
      ${files.length ? '<div class="sig-btns"><button type="button" class="ren" title="Renommer">✏️</button><button type="button" class="del" title="Supprimer">🗑️</button></div>' : ''}
    </div>`;
  }

  if (p.type === "int") {
    const d = p.default ?? 0, mn = p.min ?? 0, mx = p.max ?? 999999;
    // Si plage raisonnable, afficher comme range slider
    if (mx - mn <= 1000 && mx > mn) {
      return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
        <div class="rng"><input type="range" min="${mn}" max="${mx}" value="${d}" data-suf="${p.unit || ""}">
        <span class="rv">${d}${p.unit || ""}</span></div></div>`;
    }
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <input type="number" min="${mn}" max="${mx}" value="${d}"></div>`;
  }

  if (p.type === "select") {
    const opts = (p.options || []).map(o => {
      const hint = o.hint ? ` - ${o.hint}` : "";
      const sel = (o.value === (p.default ?? "")) ? " selected" : "";
      return `<option value="${esc(o.value)}"${sel}>${esc(o.label)}${esc(hint)}</option>`;
    }).join("");
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <select>${opts}</select></div>`;
  }

  if (p.type === "textarea") {
    const d = esc(p.default ?? ""), ph = esc(p.placeholder ?? "");
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <textarea placeholder="${ph}" rows="3">${d}</textarea></div>`;
  }

  if (p.type === "checkboxes") {
    let html = `<div class="field cb-field" data-name="${name}"><span class="fl">${label}</span><div class="cb-group">`;
    (p.options || []).forEach(o => {
      html += `<label class="cb-item"><input type="checkbox" value="${esc(o.value)}"> ${esc(o.label)}</label>`;
    });
    return html + '</div></div>';
  }

  if (p.type === "text") {
    const d = esc(p.default ?? ""), ph = esc(p.placeholder ?? "");
    return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
      <input type="text" placeholder="${ph}" value="${d}"></div>`;
  }

  // Fallback
  return `<div class="field" data-name="${name}"><span class="fl">${label}</span>
    <input type="text"></div>`;
}

/* ===================================================
   WIRE — logique interactive des params
   =================================================== */
function wireTargetFiltering(m, card) {
  const apSel  = card.querySelector('.field[data-name="bssid"] select');
  const staSel = card.querySelector('.field[data-name="client"] select');
  const dtcSel = card.querySelector('.field[data-name="deauth_target_client"] select');
  if (!apSel) return;

  const refilter = () => {
    const target = (apSel.value || "").toLowerCase();
    const all = (m.state && m.state.last_stations) || [];
    const matched = target ? all.filter(s => s.bssid && s.bssid.toLowerCase() === target) : all;
    let opts = '<option value="">Tous (broadcast)</option>';
    matched.forEach(s => {
      const assoc = s.ap_essid || s.bssid || "(libre)";
      opts += `<option value="${esc(s.mac)}">${esc(s.mac)} → ${esc(assoc)}</option>`;
    });
    if (!matched.length && all.length) opts += '<option disabled>aucun client connu</option>';
    if (staSel && !staSel.disabled) staSel.innerHTML = opts;
    if (dtcSel && !dtcSel.disabled) dtcSel.innerHTML = opts;
  };
  apSel.addEventListener("change", refilter);
  refilter();
}

function wireModeDeps(card) {
  const sel = (n) => card.querySelector(`.field[data-name="${n}"]`);
  const val = (n) => { const s = card.querySelector(`.field[data-name="${n}"] select`); return s ? s.value : ""; };
  const show = (n, vis) => { const el = sel(n); if (el) el.style.display = vis ? "" : "none"; };
  if (!sel("mode")) return;
  const refresh = () => {
    const mode = val("mode");
    const isCaptive = mode === "captive" || mode === "captive_nat";
    const isMitm = mode === "mitm" || mode === "mitm_https";
    show("template", isCaptive);
    show("custom_portal_html", isCaptive && val("template") === "custom");
    show("portal_name", isCaptive);
    show("payload_preset", isMitm);
    show("inject_script", isMitm);
    show("strip_https", mode === "mitm");
    show("wpa2_password", val("auth_mode") === "wpa2");
    show("deauth_target_client", val("deauth_continuous") === "yes");
  };
  ["mode", "auth_mode", "template", "deauth_continuous"].forEach(n => {
    const s = card.querySelector(`.field[data-name="${n}"] select`);
    if (s) s.addEventListener("change", refresh);
  });
  refresh();
}

function wireShowIf(card, params) {
  params.forEach(p => {
    if (!p.show_if) return;
    const lbl = card.querySelector(`.field[data-name="${p.name}"]`);
    if (!lbl) return;
    Object.entries(p.show_if).forEach(([depName, depVal]) => {
      const depSel = card.querySelector(`.field[data-name="${depName}"] select`);
      if (!depSel) return;
      const update = () => { lbl.style.display = (depSel.value === depVal) ? "flex" : "none"; };
      depSel.addEventListener("change", update);
      update();
    });
  });
}

function wireFreqCustom(card) {
  card.querySelectorAll(".field.freq-field").forEach(field => {
    const sel = field.querySelector("select");
    const inp = field.querySelector(".freq-custom-input");
    if (!sel || !inp) return;
    const update = () => { inp.style.display = (sel.value === "_custom") ? "block" : "none"; };
    sel.addEventListener("change", update);
    update();
  });
}

function wireSignalButtons(m, card) {
  card.querySelectorAll(".field.sig-field").forEach(field => {
    const sel = field.querySelector("select");
    const btnRen = field.querySelector(".ren");
    const btnDel = field.querySelector(".del");
    if (!sel) return;
    if (btnRen) btnRen.onclick = async (e) => {
      e.preventDefault();
      if (!sel.value) return;
      const cur = sel.selectedOptions[0]?.textContent || "";
      const name = prompt("Nommer ce signal :", cur.split("·")[0].trim());
      if (name === null || !name.trim()) return;
      try {
        const res = await fetch(`/api/modules/${m.id}/run/rename_signal`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ params: { file: sel.value, name: name.trim() }, lab_mode: false }),
        });
        const data = await res.json();
        if (data.ok) { conLog(m.id, `✓ ${data.message}`, "ok"); await postActionRefresh(m); }
        else conLog(m.id, `✗ ${data.error}`, "err");
      } catch (err) { conLog(m.id, `✗ ${err}`, "err"); }
    };
    if (btnDel) btnDel.onclick = async (e) => {
      e.preventDefault();
      if (!sel.value) return;
      const name = sel.selectedOptions[0]?.textContent || sel.value;
      if (!confirm(`Supprimer « ${name.split("·")[0].trim()} » ?`)) return;
      try {
        const res = await fetch(`/api/modules/${m.id}/run/delete_signal`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ params: { file: sel.value }, lab_mode: false }),
        });
        const data = await res.json();
        if (data.ok) { conLog(m.id, `✓ ${data.message}`, "ok"); await postActionRefresh(m); }
        else conLog(m.id, `✗ ${data.error}`, "err");
      } catch (err) { conLog(m.id, `✗ ${err}`, "err"); }
    };
  });
}

/* ===================================================
   COLLECT PARAMS
   =================================================== */
function collectParams(card) {
  const out = {};
  card.querySelectorAll(".params > .field").forEach(f => {
    if (f.style.display === "none") return;
    const name = f.dataset.name;
    if (!name) return;
    // Checkboxes
    if (f.classList.contains("cb-field")) {
      const checked = [];
      f.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => checked.push(cb.value));
      out[name] = checked.join(",");
      return;
    }
    // Freq custom
    if (f.classList.contains("freq-field")) {
      const sel = f.querySelector("select");
      const cust = f.querySelector(".freq-custom-input");
      if (sel) out[name] = sel.value;
      if (sel && sel.value === "_custom" && cust) out[name + "_custom"] = cust.value;
      return;
    }
    // Textarea
    const ta = f.querySelector("textarea");
    if (ta) { out[name] = ta.value; return; }
    // Range
    const rng = f.querySelector('input[type="range"]');
    if (rng) { out[name] = Number(rng.value); return; }
    // Select / input
    const inp = f.querySelector("select, input");
    if (!inp || inp.disabled) return;
    out[name] = inp.type === "number" ? Number(inp.value) : inp.value;
  });
  return out;
}

/* ===================================================
   EXECUTION
   =================================================== */
async function runAction(m, a, card) {
  if (a.lab_gated && !labOn()) {
    conLog(m.id, `✗ "${a.label}" verrouille — active le Lab mode.`, "err");
    return;
  }
  if (currentTaskId) {
    conLog(m.id, `⚠ Tache en cours (${currentTaskId}). Arrete-la d'abord.`, "warn");
    return;
  }
  const needsAp = (a.params || []).some(p => p.type === "target_ap");
  const apSel = card.querySelector('.field[data-name="bssid"] select');
  if (needsAp && apSel && (apSel.disabled || !apSel.value)) {
    conLog(m.id, `✗ Aucun AP selectionne — lance un Scan d'abord.`, "err");
    return;
  }
  const params = collectParams(card);
  // Vider les données live du module quand un nouveau scan démarre
  if (m.id === "sdr") {
    if (a.id === "scan_spectrum") { liveSpectrum = []; const sw = $("sdr-spectrum"); if (sw) sw.style.display = "none"; }
    if (a.id === "rtl433_listen") { liveSignals = []; const sl = $("sdr-live"); if (sl) sl.style.display = "none"; }
  }
  conLog(m.id, `→ ${a.label}...`);
  setConsoleState(m.id, "run");

  try {
    const res = await fetch(`/api/modules/${m.id}/run/${a.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ params, lab_mode: labOn() }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      conLog(m.id, `✗ ${err.error || res.statusText}`, "err");
      setConsoleState(m.id, "err");
      return;
    }
    const data = await res.json();
    if (data.task_id) {
      currentTaskId = data.task_id;
      currentTaskModuleId = m.id;
      pollTask(data.task_id, 0);
    } else {
      if (data.ok) conLog(m.id, `✓ ${data.message || data.log || "Termine."}`, "ok");
      else conLog(m.id, `✗ ${data.error || "echec"}`, "err");
      setConsoleState(m.id, data.ok ? "done" : "err");
      await postActionRefresh(m);
    }
  } catch (e) {
    conLog(m.id, `✗ erreur reseau : ${e}`, "err");
    setConsoleState(m.id, "err");
  }
}

/* ===================================================
   POLLING TACHES
   =================================================== */
async function pollTask(tid, since) {
  const mid = currentTaskModuleId;
  try {
    const r = await fetch(`/api/tasks/${tid}?since=${since}`);
    if (!r.ok) {
      conLog(mid, `✗ task ${tid} introuvable`, "err");
      finalizeTask("err");
      return;
    }
    const t = await r.json();
    (t.logs || []).forEach(l => {
      // Meta : clients eviltwin
      const meta = l.msg.match(/^__CLIENTS:(\d+)__$/);
      if (meta) { updateClientsBadge(parseInt(meta[1])); return; }
      // Meta : APs live
      if (l.msg.startsWith("__APS_LIVE__")) {
        try { liveAps = JSON.parse(l.msg.slice(12)); renderLiveAps(liveAps); } catch(e) {}
        return;
      }
      // Meta : stations live
      if (l.msg.startsWith("__STA_LIVE__")) {
        try { liveStations = JSON.parse(l.msg.slice(12)); renderLiveStations(liveStations); } catch(e) {}
        return;
      }
      // Meta : signaux SDR live
      if (l.msg.startsWith("__SIGNALS_LIVE__")) {
        try { liveSignals = JSON.parse(l.msg.slice(16)); renderLiveSignals(liveSignals); } catch(e) {}
        return;
      }
      // Meta : spectre live
      if (l.msg.startsWith("__SPECTRUM_LIVE__")) {
        try { liveSpectrum = JSON.parse(l.msg.slice(17)); renderSpectrumCards(liveSpectrum); } catch(e) {}
        return;
      }
      const cls = l.level === "error" ? "err" : (l.level === "warn" ? "warn" : "");
      conLog(mid, l.msg, cls);
    });
    const newSince = t.log_total || since;
    if (t.status === "running") {
      pollTimer = setTimeout(() => pollTask(tid, newSince), 1000);
    } else {
      const res = t.result || {};
      if (res.ok) conLog(mid, `✓ ${res.message || res.log || "Termine."}`, "ok");
      else if (res.error) conLog(mid, `✗ ${res.error}`, "err");
      else conLog(mid, `${t.status === "stopped" ? "⛔ Arrete" : "Termine"} (sans resultat)`, "warn");
      const refreshId = currentTaskModuleId;  // sauver AVANT finalizeTask
      finalizeTask(res.ok ? "done" : (res.error ? "err" : "done"));
      if (refreshId) await postActionRefresh({ id: refreshId });
    }
  } catch (e) {
    conLog(mid, `✗ polling : ${e}`, "err");
    finalizeTask("err");
  }
}

function finalizeTask(state) {
  if (currentTaskModuleId) setConsoleState(currentTaskModuleId, state || "done");
  currentTaskId = null;
  currentTaskModuleId = null;
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  updateClientsBadge(0);
}

async function stopCurrentTask() {
  if (!currentTaskId) return;
  const mid = currentTaskModuleId;
  conLog(mid, `⛔ Stop demande...`, "warn");
  try {
    await fetch(`/api/tasks/${currentTaskId}/stop`, { method: "POST" });
  } catch (e) {
    conLog(mid, `✗ stop : ${e}`, "err");
  }
}

/* ===================================================
   POST-ACTION REFRESH
   =================================================== */
async function postActionRefresh(m) {
  await load();
  const updated = MODULES.find(mm => mm.id === m.id);
  if (updated) {
    const view = $("view-" + updated.id);
    if (view) {
      current = updated;
      refreshModuleView(updated, view);
    }
    if (updated.id === "memory") renderCapturesView();
  }
}

/* ===================================================
   CONSOLE — rail droit
   =================================================== */
function buildConsoleHTML(moduleId) {
  return `<div class="console" id="con-${moduleId}">
    <div class="con-head">
      <span class="ico" style="color:var(--cyan)"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6M12 19h8"/></svg></span>
      <span class="ct">SORTIE</span>
      <span class="cstate" id="cstate-${moduleId}"><span class="cdot"></span>IDLE</span>
      <button class="stopbtn" onclick="stopCurrentTask()">STOP</button>
      <button class="copybtn" onclick="copyConsole('${moduleId}')" title="Copier">📋</button>
    </div>
    <div class="progress"><div class="bar" id="cbar-${moduleId}"></div></div>
    <div class="con-body" id="cbody-${moduleId}">
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 17l6-6-6-6M12 19h8"/></svg>
        Lance une action — la sortie live s'affiche ici
      </div>
    </div>
  </div>`;
}

function conLog(moduleId, msg, cls) {
  if (!moduleId) return;
  // Stocker
  if (!consoleLogs[moduleId]) consoleLogs[moduleId] = [];
  const ts = new Date().toLocaleTimeString("fr-FR");
  consoleLogs[moduleId].push({ msg, cls: cls || "", ts });
  // Limiter à 500 lignes
  if (consoleLogs[moduleId].length > 500) consoleLogs[moduleId] = consoleLogs[moduleId].slice(-400);
  // Afficher
  const body = $("cbody-" + moduleId);
  if (!body) return;
  // Supprimer le placeholder "empty"
  const empty = body.querySelector(".empty");
  if (empty) empty.remove();
  const ln = document.createElement("div");
  ln.className = "ln " + (cls || "");
  ln.innerHTML = `<span class="t">[${ts}]</span> ${msg}`;
  body.appendChild(ln);
  body.scrollTop = body.scrollHeight;
}

function restoreConsoleLogs(moduleId) {
  const logs = consoleLogs[moduleId];
  if (!logs || !logs.length) return;
  const body = $("cbody-" + moduleId);
  if (!body) return;
  body.innerHTML = "";
  logs.forEach(l => {
    const ln = document.createElement("div");
    ln.className = "ln " + (l.cls || "");
    ln.innerHTML = `<span class="t">[${l.ts}]</span> ${l.msg}`;
    body.appendChild(ln);
  });
  body.scrollTop = body.scrollHeight;
}

function setConsoleState(moduleId, state) {
  const el = $("cstate-" + moduleId);
  if (!el) return;
  el.className = "cstate " + (state || "");
  const labels = { run: "RUNNING", done: "DONE", err: "ERREUR", "": "IDLE" };
  el.innerHTML = `<span class="cdot"></span>${labels[state] || "IDLE"}`;
  // Progress bar
  const bar = $("cbar-" + moduleId);
  if (bar) {
    if (state === "run") {
      bar.style.width = "0";
      bar.style.background = "var(--cyan)";
      bar.style.boxShadow = "0 0 8px var(--cyan)";
      // Animation indeterminee
      bar.style.transition = "width 60s linear";
      requestAnimationFrame(() => { bar.style.width = "90%"; });
    } else if (state === "done") {
      bar.style.transition = "width .3s";
      bar.style.width = "100%";
      bar.style.background = "var(--green)";
      bar.style.boxShadow = "0 0 8px var(--green)";
    } else if (state === "err") {
      bar.style.transition = "width .3s";
      bar.style.width = "100%";
      bar.style.background = "var(--red)";
      bar.style.boxShadow = "0 0 8px var(--red)";
    } else {
      bar.style.transition = "none";
      bar.style.width = "0";
    }
  }
}

function copyConsole(moduleId) {
  const body = $("cbody-" + moduleId);
  if (!body) return;
  const text = body.innerText || body.textContent || "";
  navigator.clipboard.writeText(text).then(() => {
    const con = $("con-" + moduleId);
    const btn = con && con.querySelector(".copybtn");
    if (btn) { btn.textContent = "✓"; setTimeout(() => { btn.textContent = "📋"; }, 1200); }
  });
}

/* ===================================================
   CAPTURES — vue module memory
   =================================================== */
function renderCapturesView() {
  const content = $("captures-content");
  const mem = MODULES.find(m => m.id === "memory");
  if (!mem || !mem.connected) {
    content.innerHTML = `<div class="note">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="9"/></svg>
      <span>Aucune capture disponible.</span></div>`;
    return;
  }
  current = mem;
  // Rendu en style command center pour memory aussi
  content.innerHTML = `
    <div class="cmd-layout">
      <div class="lib" id="lib-memory"></div>
      <div class="rail">${buildConsoleHTML("memory")}</div>
    </div>`;
  renderSections(mem);
  restoreConsoleLogs("memory");
}

/* ===================================================
   LIVE SCAN — AP & stations
   =================================================== */
function signalStrength(power) {
  if (power >= -50) return 4;
  if (power >= -60) return 3;
  if (power >= -70) return 2;
  if (power >= -80) return 1;
  return 0;
}
function signalBarsHTML(level) {
  let h = '<div class="signal-bars">';
  for (let i = 1; i <= 4; i++) h += `<span class="${i <= level ? 'active' : ''}"></span>`;
  return h + '</div>';
}
function toggleApActions(el) { el.closest(".ap-card").classList.toggle("expanded"); }
function toggleStaActions(el) { el.closest(".sta-card").classList.toggle("expanded"); }

function renderLiveAps(aps) {
  const section = $("wifi-live");
  if (!section) return;
  section.style.display = aps.length ? "block" : "none";
  $("ap-count").textContent = `${aps.length} reseau(x)`;
  const grid = $("ap-grid");
  grid.innerHTML = "";
  aps.forEach(ap => {
    const card = document.createElement("div");
    card.className = "ap-card";
    card.dataset.bssid = ap.bssid;
    const str = signalStrength(ap.power);
    const enc = (ap.encryption || "OPN").toUpperCase();
    const encCls = enc === "OPN" ? "enc-open" : enc.includes("WEP") ? "enc-wep" : "enc-wpa";
    const bssidEsc = esc(ap.bssid);
    card.innerHTML = `
      <div class="ap-main" onclick="toggleApActions(this)">
        <div class="ap-signal">
          ${signalBarsHTML(str)}
          <span class="ap-dbm">${ap.power}</span>
        </div>
        <div class="ap-info">
          <div class="ap-essid">${esc(ap.essid)}</div>
          <div class="ap-meta">${esc(enc)} · ch${ap.channel} · ${bssidEsc}</div>
        </div>
        <span class="enc-badge ${encCls}">${esc(enc).substring(0, 7)}</span>
      </div>
      <div class="ap-actions">
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('wifi','clients',{bssid:'${bssidEsc}',duration:15})">Clients</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('wifi','pmkid',{bssid:'${bssidEsc}',duration:60})">PMKID</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('wifi','handshake',{bssid:'${bssidEsc}',duration:60})">Handshake</button>
        <button class="qa qa-amber" onclick="event.stopPropagation();quickAction('wifi','handshake_deauth',{bssid:'${bssidEsc}',client:'',count:10,duration:60})">HS+Deauth</button>
        <button class="qa qa-amber" onclick="event.stopPropagation();quickAction('wifi','deauth',{bssid:'${bssidEsc}',client:'',count:10})">Deauth</button>
        <button class="qa qa-amber" onclick="event.stopPropagation();quickAction('wifi','wifite',{bssid:'${bssidEsc}',duration:180})">Wifite</button>
      </div>`;
    grid.appendChild(card);
  });
}

function renderLiveStations(stations) {
  const section = $("wifi-stations-live");
  if (!section) return;
  section.style.display = stations.length ? "block" : "none";
  $("sta-count").textContent = `${stations.length} station(s)`;
  const grid = $("sta-grid");
  grid.innerHTML = "";
  stations.forEach(st => {
    const card = document.createElement("div");
    card.className = "sta-card";
    const str = signalStrength(st.power);
    const assoc = st.ap_essid || st.bssid || "(non associe)";
    const probes = (st.probes || []).slice(0, 4).join(", ") || "";
    const macEsc = esc(st.mac);
    const bssidEsc = esc(st.bssid || "");
    card.innerHTML = `
      <div class="sta-main" onclick="toggleStaActions(this)">
        <div class="sta-signal">${signalBarsHTML(str)}</div>
        <div class="sta-info">
          <div class="sta-mac">${macEsc}</div>
          <div class="sta-meta">→ ${esc(assoc)} · ${st.packets || 0} pkts</div>
          ${probes ? `<div class="sta-probes">Probes: ${esc(probes)}</div>` : ""}
        </div>
      </div>
      <div class="sta-actions">
        <button class="qa qa-amber" onclick="event.stopPropagation();quickAction('wifi','deauth',{bssid:'${bssidEsc}',client:'${macEsc}',count:10})">Deauth</button>
      </div>`;
    grid.appendChild(card);
  });
}

/* ===================================================
   SDR FILTRE — bloc fréquence + ambiant
   =================================================== */
function wireSdrFilter() {
  const ambCb = $("sig-hide-ambient");
  if (ambCb) ambCb.addEventListener("change", () => applyAmbientFilter());
  // Restaurer cible fréquence
  if (sdrTargetFreq) showTargetFreq(sdrTargetFreq);
}

function setTargetFreq(freqHz) {
  /* Depuis carte signal : cible cette fréquence dans toutes les actions */
  sdrTargetFreq = String(freqHz);
  showTargetFreq(sdrTargetFreq);
  // Appliquer à toutes les cartes d'action SDR
  const lib = $("lib-sdr");
  if (!lib) return;
  lib.querySelectorAll(".field.freq-field").forEach(field => {
    const fSel = field.querySelector("select");
    const fCust = field.querySelector(".freq-custom-input");
    if (!fSel) return;
    const opt = Array.from(fSel.options).find(o => o.value === sdrTargetFreq);
    if (opt) {
      fSel.value = sdrTargetFreq;
      if (fCust) fCust.style.display = "none";
    } else {
      fSel.value = "_custom";
      if (fCust) { fCust.style.display = "block"; fCust.value = sdrTargetFreq; }
    }
  });
}

function showTargetFreq(hz) {
  const el = $("sdr-target");
  const txt = $("sdr-target-txt");
  if (!el || !txt) return;
  const mhz = (parseFloat(hz) / 1e6).toFixed(2).replace(/\.?0+$/, "");
  txt.textContent = `${mhz} MHz`;
  el.style.display = "flex";
}

function clearTargetFreq() {
  sdrTargetFreq = "";
  const el = $("sdr-target");
  if (el) el.style.display = "none";
}

/* ===================================================
   LIVE SIGNALS SDR — cartes de signaux
   =================================================== */
function renderLiveSignals(signals) {
  const section = $("sdr-live");
  if (!section) return;
  section.style.display = signals.length ? "block" : "none";
  const hideAmb = $("sig-hide-ambient");
  const hiding = hideAmb ? hideAmb.checked : true;
  const nAmb = signals.filter(s => s.ambient).length;
  const nNew = signals.filter(s => !s.ambient).length;
  const shown = hiding ? nNew : signals.length;
  $("sig-count").textContent = `${shown} signal(aux)`;
  const note = $("sig-ambient-note");
  if (note) {
    if (hiding && nAmb > 0) {
      note.style.display = "block";
      note.innerHTML = `🔇 ${nAmb} ambiant(s) masque(s) — <a href="#" onclick="event.preventDefault();document.getElementById('sig-hide-ambient').checked=false;applyAmbientFilter()">afficher</a>`;
    } else { note.style.display = "none"; }
  }
  const grid = $("sig-grid");
  grid.innerHTML = "";
  signals.forEach(s => {
    const card = document.createElement("div");
    const isUnk = s.unknown === true;
    card.className = "sig-card" + (s.ambient ? " sig-ambient" : " sig-new")
                   + (isUnk ? " sig-unknown" : "");
    card.dataset.ambient = s.ambient ? "true" : "false";
    if (hiding && s.ambient) card.style.display = "none";
    const freqEsc = esc(String(s.freq_hz));
    const d = s.data || {};
    let dataLine = "";
    if (isUnk) {
      // Signal inconnu : afficher code, modulation, bits
      if (d.modulation) dataLine += `${d.modulation} `;
      if (d.bits) dataLine += `${d.bits} bits `;
      if (d.code) dataLine += `code:${d.code} `;
      if (d.short_us) dataLine += `${d.short_us}/${d.long_us || 0}µs`;
    } else {
      // Signal connu : afficher les données décodées
      if (d.temperature_C !== undefined) dataLine += `${d.temperature_C}°C `;
      if (d.humidity !== undefined) dataLine += `${d.humidity}% `;
      if (d.battery_ok !== undefined) dataLine += d.battery_ok ? "pile OK " : "pile ⚠️ ";
      const skip = new Set(["model","id","channel","temperature_C","humidity","battery_ok"]);
      Object.keys(d).filter(k => !skip.has(k)).slice(0, 3).forEach(k => { dataLine += `${k}=${d[k]} `; });
    }
    let badge;
    if (isUnk) badge = '<span class="sig-badge badge-unk">INCONNU</span>';
    else if (s.ambient) badge = '<span class="sig-badge badge-amb">AMBIANT</span>';
    else badge = '<span class="sig-badge badge-new">NOUVEAU</span>';
    const rssiTxt = s.rssi !== "" ? `${s.rssi} dB` : "";
    const countTxt = s.count > 1 ? `${s.count}×` : "";
    const metaParts = [s.id ? `id:${esc(String(s.id))}` : "", esc(s.freq_display), rssiTxt, countTxt].filter(Boolean).join(" · ");
    card.innerHTML = `
      <div class="sig-main" onclick="toggleSigActions(this)">
        <div class="sig-icon">${s.icon || "📦"}</div>
        <div class="sig-info">
          <div class="sig-model">${esc(s.model)}</div>
          <div class="sig-meta">${metaParts}</div>
          ${dataLine.trim() ? `<div class="sig-data">${esc(dataLine.trim())}</div>` : ""}
        </div>
        ${badge}
      </div>
      <div class="sig-actions">
        ${(d.code && !s.ambient) ? `<button class="qa qa-orange" onclick="event.stopPropagation();quickAction('sdr','flipper_send',{code:'${esc(String(d.code))}',frequency:'${freqEsc}',modulation:'${d.modulation && d.modulation.toLowerCase().includes('manchester') ? 'OOK_MC' : 'OOK_RAW'}',short_us:'${d.short_us || 500}',repeat:'5'})">📤 Rejouer</button>` : ""}
        <button class="qa qa-green" onclick="event.stopPropagation();setTargetFreq('${freqEsc}')">Cibler</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('sdr','record_signal',{frequency:'${freqEsc}',duration:'10',gain:'49'})">Enregistrer</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('sdr','rtl433_listen',{frequency:'${freqEsc}',duration:'30'})">Identifier</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('sdr','capture_iq',{frequency:'${freqEsc}',duration:'10',sample_rate:'250000',gain:'40'})">Capturer IQ</button>
      </div>`;
    grid.appendChild(card);
  });
}

function toggleSigActions(el) {
  const card = el.closest(".sig-card");
  if (card) card.classList.toggle("expanded");
}

function applyAmbientFilter() {
  const hide = $("sig-hide-ambient") ? $("sig-hide-ambient").checked : true;
  const grid = $("sig-grid");
  if (!grid) return;
  let nHidden = 0;
  grid.querySelectorAll(".sig-card").forEach(c => {
    if (c.dataset.ambient === "true") {
      c.style.display = hide ? "none" : "";
      if (hide) nHidden++;
    }
  });
  const total = grid.querySelectorAll(".sig-card").length;
  const shown = hide ? total - nHidden : total;
  const cnt = $("sig-count");
  if (cnt) cnt.textContent = `${shown} signal(aux)`;
  const note = $("sig-ambient-note");
  if (note) {
    if (hide && nHidden > 0) {
      note.style.display = "block";
      note.innerHTML = `🔇 ${nHidden} ambiant(s) masque(s) — <a href="#" onclick="event.preventDefault();document.getElementById('sig-hide-ambient').checked=false;applyAmbientFilter()">afficher</a>`;
    } else { note.style.display = "none"; }
  }
}

/* ===================================================
   SPECTRE — cartes fréquences actives
   =================================================== */
function renderSpectrumCards(cards) {
  const wrap = $("sdr-spectrum");
  const grid = $("spec-grid");
  const cnt  = $("spec-count");
  if (!wrap || !grid) return;
  wrap.style.display = "";
  if (cnt) cnt.textContent = `${cards.length} signal(aux) reel(s)`;
  grid.innerHTML = "";
  cards.forEach((s, i) => {
    const card = document.createElement("div");
    card.className = "sig-card spec-card";
    const lvlCls = s.level === "fort" ? "badge-new" : (s.level === "moyen" ? "badge-med" : "badge-amb");
    const freqEsc = String(s.freq_hz).replace(/'/g, "\\'");
    const above = s.above_noise != null ? `+${s.above_noise.toFixed(0)} dB` : `${(s.power||0).toFixed(0)} dB`;
    const barLen = Math.max(1, Math.min(20, Math.round(s.above_noise || 0)));
    const bar = "█".repeat(barLen);
    card.innerHTML = `
      <div class="sig-main" onclick="toggleSigActions(this)">
        <div class="sig-icon">📡</div>
        <div class="sig-info">
          <div class="sig-model">${s.freq_display}</div>
          <div class="sig-meta">${above} au-dessus du bruit · ${s.level} ${bar}</div>
        </div>
        <span class="sig-badge ${lvlCls}">#${i+1}</span>
      </div>
      <div class="sig-actions">
        <button class="qa qa-green" onclick="event.stopPropagation();setTargetFreq('${freqEsc}')">Cibler</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('sdr','rtl433_listen',{frequency:'${freqEsc}',duration:'30'})">Identifier</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('sdr','record_signal',{frequency:'${freqEsc}',duration:'10'})">Enregistrer</button>
        <button class="qa qa-cyan" onclick="event.stopPropagation();quickAction('sdr','capture_iq',{frequency:'${freqEsc}',duration:'10',sample_rate:'250000',gain:'40'})">Capturer IQ</button>
      </div>`;
    grid.appendChild(card);
  });
}

/* ===================================================
   QUICK ACTION — depuis carte AP/STA
   =================================================== */
async function quickAction(moduleId, actionId, params) {
  const m = MODULES.find(mm => mm.id === moduleId);
  if (!m) { conLog(moduleId, "Module introuvable", "err"); return; }
  const a = m.actions.find(aa => aa.id === actionId);
  if (!a) { conLog(moduleId, `Action "${actionId}" introuvable`, "err"); return; }
  if (a.lab_gated && !labOn()) {
    conLog(moduleId, `✗ "${a.label}" verrouille — active le Lab mode.`, "err");
    return;
  }
  if (currentTaskId) {
    conLog(moduleId, `⚠ Tache en cours. Arrete-la d'abord.`, "warn");
    return;
  }
  conLog(moduleId, `→ ${a.label}...`);
  setConsoleState(moduleId, "run");
  try {
    const res = await fetch(`/api/modules/${moduleId}/run/${actionId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ params, lab_mode: labOn() }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      conLog(moduleId, `✗ ${err.error || res.statusText}`, "err");
      setConsoleState(moduleId, "err");
      return;
    }
    const data = await res.json();
    if (data.task_id) {
      currentTaskId = data.task_id;
      currentTaskModuleId = moduleId;
      pollTask(data.task_id, 0);
    } else {
      if (data.ok) conLog(moduleId, `✓ ${data.message || "Termine."}`, "ok");
      else conLog(moduleId, `✗ ${data.error || "echec"}`, "err");
      setConsoleState(moduleId, data.ok ? "done" : "err");
      await postActionRefresh(m);
    }
  } catch (e) {
    conLog(moduleId, `✗ erreur reseau : ${e}`, "err");
    setConsoleState(moduleId, "err");
  }
}

/* ===================================================
   LAB MODE — synchronisation globale
   =================================================== */
function syncLab(on) {
  // Sync toggle settings
  $("labtoggle").checked = on;
  document.body.classList.toggle("lab", on);
  $("lab-indicator").style.display = on ? "flex" : "none";
  // Sync global lab indicator
  const gl = $("globalLab");
  if (gl) { gl.textContent = on ? "LAB ARME" : "STANDARD"; gl.style.color = on ? "var(--red)" : "var(--amber)"; }
  // Sync tous les lab switches des modules
  MODULES.forEach(m => {
    const inp = $("labmod-" + m.id);
    if (inp) inp.checked = on;
    const ls = $("ls-" + m.id);
    if (ls) ls.classList.toggle("armed", on);
  });
  // Mettre a jour les cartes locked
  document.querySelectorAll(".acard[data-lab-gated='1']").forEach(card => {
    card.classList.toggle("locked", !on);
  });
}

$("labtoggle").onchange = () => syncLab(labOn());

/* ===================================================
   UI HELPERS
   =================================================== */
function updateClientsBadge(n) {
  const badge = $("clients-badge");
  if (!badge) return;
  if (n > 0) {
    badge.className = "show";
    badge.textContent = `📱 ${n} client${n > 1 ? "s" : ""} connecte${n > 1 ? "s" : ""}`;
  } else {
    badge.className = "";
  }
}

/* ===================================================
   INIT
   =================================================== */
initNavigation();
load();
setInterval(load, 8000);
