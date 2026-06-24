/**
 * Project Shield — Dashboard Controller
 * Manages charts, live feed, log table, upload, and real-time updates.
 */

// ── Chart color palette ────────────────────────────────────────────
const COLORS = {
  Normal:   "#00e676",
  DoS:      "#ff3d5a",
  Probe:    "#ffd600",
  R2L:      "#ff8c00",
  U2R:      "#d500f9",
  Low:      "#00e676",
  Medium:   "#ffd600",
  High:     "#ff8c00",
  Critical: "#ff3d5a"
};

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: { color: "#6b7a99", font: { family: "Inter" }, boxWidth: 12 }
    },
    tooltip: {
      backgroundColor: "#0d1120",
      titleColor: "#e8eaf6",
      bodyColor: "#6b7a99",
      borderColor: "rgba(255,255,255,0.08)",
      borderWidth: 1
    }
  }
};

// ── State ──────────────────────────────────────────────────────────
let charts = {};
let logsPage = 1;
let totalLogs = 0;
let liveInterval = null;
let lastStats = null;

// ── Init ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  AuthManager.requireAuth();
  initUI();
  loadDashboard();
  startLiveFeed();
});

// ── UI Initialisation ──────────────────────────────────────────────
function initUI() {
  // User info
  document.getElementById("sidebarUsername").textContent = AuthManager.getUsername();
  document.getElementById("sidebarRole").textContent     = AuthManager.getRole();
  document.getElementById("topbarUser").textContent      = AuthManager.getUsername();

  // Nav routing
  document.querySelectorAll(".nav-item[data-page]").forEach(item => {
    item.addEventListener("click", () => {
      const page = item.dataset.page;
      navigateTo(page);
    });
  });

  // Logout
  document.getElementById("logoutBtn").addEventListener("click", () => {
    AuthManager.logout();
  });

  // File upload
  initUpload();

  // Log filters
  document.getElementById("filterLabel")?.addEventListener("change",    () => loadLogs(1));
  document.getElementById("filterSeverity")?.addEventListener("change", () => loadLogs(1));
  document.getElementById("prevPage")?.addEventListener("click", () => {
    if (logsPage > 1) loadLogs(logsPage - 1);
  });
  document.getElementById("nextPage")?.addEventListener("click", () => {
    loadLogs(logsPage + 1);
  });

  // Generate demo data
  document.getElementById("generateDemoBtn")?.addEventListener("click", async () => {
    showToast("Generating 150 demo log entries...", "info");
    try {
      await API.generateDemoLogs(150);
      showToast("Demo data generated!", "success");
      loadDashboard();
    } catch(e) { showToast("Failed: " + e.message, "error"); }
  });

  // Refresh button
  document.getElementById("refreshBtn")?.addEventListener("click", () => {
    loadDashboard();
    showToast("Dashboard refreshed", "info");
  });

  // Report page
  document.getElementById("downloadReportBtn")?.addEventListener("click", async () => {
    const status = document.getElementById("reportStatus");
    const btn    = document.getElementById("downloadReportBtn");
    btn.disabled      = true;
    btn.textContent   = "⏳ Generating PDF...";
    if (status) status.textContent = "Building report from current log data...";
    try {
      await API.generateReport();
      if (status) status.textContent = "✅ Report downloaded successfully!";
      showToast("PDF report downloaded!", "success");
    } catch(e) {
      if (status) status.textContent = "❌ " + e.message;
      showToast("Report failed: " + e.message, "error");
    } finally {
      btn.disabled    = false;
      btn.textContent = "⬇️ Download PDF Report";
    }
  });
  document.getElementById("refreshReportStatsBtn")?.addEventListener("click", loadReportPage);
}

// ── Navigation ─────────────────────────────────────────────────────
function navigateTo(page) {
  document.querySelectorAll(".page-section").forEach(s => s.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  const section = document.getElementById("page-" + page);
  const navItem = document.querySelector(`.nav-item[data-page="${page}"]`);

  if (section) section.classList.add("active");
  if (navItem) navItem.classList.add("active");

  document.getElementById("topbarTitle").textContent =
    navItem ? navItem.querySelector(".nav-label-text")?.textContent : "Overview";

  if (page === "logs")    loadLogs(1);
  if (page === "threats") loadThreats();
  if (page === "report")  loadReportPage();
}

// ── Report page ───────────────────────────────────────────────────
async function loadReportPage() {
  try {
    const stats = await API.getDashboardStats();
    setEl("rptTotal",    stats.total_events?.toLocaleString() || "—");
    setEl("rptAttacks",  stats.total_attacks?.toLocaleString() || "—");
    setEl("rptAvg",      (stats.avg_threat_score || 0).toFixed(1));
    setEl("rptCritical", stats.severity_counts?.Critical?.toLocaleString() || "0");
  } catch(e) {
    // silently fail — stats are non-critical on this page
  }
}

// ── Load dashboard stats + charts ──────────────────────────────────
async function loadDashboard() {
  try {
    const stats = await API.getDashboardStats();
    lastStats = stats;
    updateStatCards(stats);
    updateThreatLevel(stats.avg_threat_score);
    renderAttackTypeChart(stats.type_distribution);
    renderSeverityChart(stats.severity_counts);
    renderTimelineChart(stats.timeline);
    renderProtocolChart(stats.protocol_distribution);
    renderServiceChart(stats.top_services);
    renderGauge(stats.avg_threat_score);
    updateAlertBadge(stats.severity_counts?.Critical || 0);
  } catch(e) {
    showToast("Failed to load stats: " + e.message, "error");
  }
}

// ── Stat cards ─────────────────────────────────────────────────────
function updateStatCards(stats) {
  setEl("statTotal",    stats.total_events?.toLocaleString() || "—");
  setEl("statAttacks",  stats.total_attacks?.toLocaleString() || "—");
  setEl("statNormal",   stats.total_normal?.toLocaleString() || "—");
  setEl("statRate",     (stats.attack_rate || 0) + "%");
  setEl("statAvgScore", (stats.avg_threat_score || 0).toFixed(1));
  setEl("statMaxScore", (stats.max_threat_score || 0).toFixed(1));
}

// ── Threat level indicator ─────────────────────────────────────────
function updateThreatLevel(score) {
  const el = document.getElementById("threatLevel");
  if (!el) return;
  el.className = "topbar-threat";
  let label, cls;
  if (score >= 75)      { label = "🔴 CRITICAL"; cls = "threat-critical"; }
  else if (score >= 50) { label = "🟠 HIGH";     cls = "threat-high"; }
  else if (score >= 25) { label = "🟡 MEDIUM";   cls = "threat-medium"; }
  else                  { label = "🟢 LOW";       cls = "threat-low"; }
  el.classList.add(cls);
  el.textContent = label;
}

// ── Charts ─────────────────────────────────────────────────────────
function renderAttackTypeChart(data) {
  const ctx = document.getElementById("attackTypeChart");
  if (!ctx || !data) return;
  if (charts.attackType) charts.attackType.destroy();
  const labels = Object.keys(data);
  const values = Object.values(data);
  charts.attackType = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: labels.map(l => hexToRgba(COLORS[l] || "#6b7a99", 0.8)),
        borderColor:     labels.map(l => COLORS[l] || "#6b7a99"),
        borderWidth: 2,
        hoverOffset: 8
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      cutout: "65%",
      plugins: {
        ...CHART_DEFAULTS.plugins,
        legend: { position: "right", labels: { color: "#6b7a99", font: { family: "Inter" }, boxWidth: 12, padding: 12 } }
      }
    }
  });
}

function renderSeverityChart(data) {
  const ctx = document.getElementById("severityChart");
  if (!ctx || !data) return;
  if (charts.severity) charts.severity.destroy();
  const labels = ["Low", "Medium", "High", "Critical"];
  charts.severity = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Events",
        data: labels.map(l => data[l] || 0),
        backgroundColor: labels.map(l => hexToRgba(COLORS[l], 0.7)),
        borderColor:     labels.map(l => COLORS[l]),
        borderWidth: 2,
        borderRadius: 6
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#6b7a99" } },
        y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#6b7a99" }, beginAtZero: true }
      }
    }
  });
}

function renderTimelineChart(timeline) {
  const ctx = document.getElementById("timelineChart");
  if (!ctx || !timeline) return;
  if (charts.timeline) charts.timeline.destroy();

  // Group into buckets with attack type
  const grouped = {};
  timeline.forEach((t, i) => {
    const lbl = new Date(t.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (!grouped[lbl]) grouped[lbl] = { score: 0, count: 0 };
    grouped[lbl].score += t.threat_score;
    grouped[lbl].count++;
  });
  const labels = Object.keys(grouped).slice(-20);
  const scores = labels.map(l => +(grouped[l].score / grouped[l].count).toFixed(1));

  charts.timeline = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Avg Threat Score",
        data: scores,
        borderColor: "#00ffd5",
        backgroundColor: "rgba(0,255,213,0.08)",
        borderWidth: 2,
        pointRadius: 4,
        pointBackgroundColor: "#00ffd5",
        pointBorderColor: "#070b18",
        pointBorderWidth: 2,
        tension: 0.4,
        fill: true
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#6b7a99", maxTicksLimit: 8 } },
        y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#6b7a99" }, min: 0, max: 100 }
      }
    }
  });
}

function renderProtocolChart(data) {
  const ctx = document.getElementById("protocolChart");
  if (!ctx || !data) return;
  if (charts.protocol) charts.protocol.destroy();
  const labels = Object.keys(data);
  const values = Object.values(data);
  charts.protocol = new Chart(ctx, {
    type: "polarArea",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: ["rgba(0,255,213,0.5)", "rgba(124,58,237,0.5)", "rgba(59,130,246,0.5)"],
        borderColor:     ["#00ffd5", "#7c3aed", "#3b82f6"],
        borderWidth: 2
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        r: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#6b7a99", backdropColor: "transparent" } }
      }
    }
  });
}

function renderServiceChart(data) {
  const ctx = document.getElementById("serviceChart");
  if (!ctx || !data) return;
  if (charts.service) charts.service.destroy();
  const labels = Object.keys(data);
  const values = Object.values(data);
  const gradient = ["#00ffd5","#00c4a3","#48cae4","#90e0ef","#ade8f4","#caf0f8"];
  charts.service = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Events",
        data: values,
        backgroundColor: labels.map((_, i) => hexToRgba(gradient[i % gradient.length], 0.7)),
        borderColor:     gradient,
        borderWidth: 2,
        borderRadius: 6
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      indexAxis: "y",
      plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#6b7a99" }, beginAtZero: true },
        y: { grid: { display: false }, ticks: { color: "#e8eaf6" } }
      }
    }
  });
}

// ── Gauge ──────────────────────────────────────────────────────────
function renderGauge(score) {
  const ctx = document.getElementById("gaugeChart");
  if (!ctx) return;
  if (charts.gauge) charts.gauge.destroy();

  const clipped = Math.min(100, Math.max(0, score));
  const color = clipped >= 75 ? "#ff3d5a" : clipped >= 50 ? "#ff8c00" : clipped >= 25 ? "#ffd600" : "#00e676";
  const remaining = 100 - clipped;

  charts.gauge = new Chart(ctx, {
    type: "doughnut",
    data: {
      datasets: [{
        data: [clipped, remaining],
        backgroundColor: [color, "rgba(255,255,255,0.04)"],
        borderColor:     [color, "transparent"],
        borderWidth: [3, 0],
        circumference: 240,
        rotation: -120
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "78%",
      plugins: { legend: { display: false }, tooltip: { enabled: false } }
    }
  });

  setEl("gaugeValue", clipped.toFixed(0));
  const gLabel = document.getElementById("gaugeThreatLabel");
  if (gLabel) {
    if (clipped >= 75)      { gLabel.textContent = "CRITICAL"; gLabel.style.color = "#ff3d5a"; }
    else if (clipped >= 50) { gLabel.textContent = "HIGH";     gLabel.style.color = "#ff8c00"; }
    else if (clipped >= 25) { gLabel.textContent = "MEDIUM";   gLabel.style.color = "#ffd600"; }
    else                    { gLabel.textContent = "LOW";       gLabel.style.color = "#00e676"; }
  }
}

// ── Live feed ──────────────────────────────────────────────────────
function startLiveFeed() {
  if (liveInterval) clearInterval(liveInterval);
  liveInterval = setInterval(fetchLiveFeed, 8000);
  fetchLiveFeed();
}

async function fetchLiveFeed() {
  try {
    const data = await API.getLiveFeed();
    if (!data?.events) return;
    const feed = document.getElementById("liveFeed");
    if (!feed) return;

    data.events.forEach(ev => {
      const item = createFeedItem(ev);
      feed.insertBefore(item, feed.firstChild);
    });

    // Keep only 30 items
    while (feed.children.length > 30) feed.removeChild(feed.lastChild);

    // Update alert badge
    const criticals = data.events.filter(e => e.severity === "Critical").length;
    if (criticals > 0) {
      const badge = document.getElementById("alertBadge");
      if (badge) badge.textContent = parseInt(badge.textContent || "0") + criticals;
    }
  } catch(e) {
    // silently fail for live feed
  }
}

function createFeedItem(ev) {
  const sev = (ev.severity || "Low").toLowerCase();
  const ts  = new Date(ev.timestamp).toLocaleTimeString();
  const div = document.createElement("div");
  div.className = "feed-item";
  div.innerHTML = `
    <div class="pulse-dot ${sev}"></div>
    <div class="feed-content">
      <div class="feed-label">
        <span style="color:${COLORS[ev.label]||'#00ffd5'}">${ev.label || "Normal"}</span>
        — Threat Score: <span style="font-weight:700">${(ev.threat_score||0).toFixed(0)}/100</span>
      </div>
      <div class="feed-meta">
        ${ev.src_ip || "N/A"} → ${ev.dst_ip || "N/A"} &nbsp;|&nbsp;
        ${(ev.protocol_type||"tcp").toUpperCase()} / ${ev.service || "http"} &nbsp;|&nbsp;
        ${ts}
      </div>
    </div>
    <span class="badge badge-${sev}">${ev.severity || "Low"}</span>
  `;
  return div;
}

// ── Logs table ─────────────────────────────────────────────────────
async function loadLogs(page = 1) {
  logsPage = page;
  const label    = document.getElementById("filterLabel")?.value    || null;
  const severity = document.getElementById("filterSeverity")?.value || null;
  try {
    const data = await API.getLogs(page, 50, label || null, severity || null);
    totalLogs = data.total;
    renderLogsTable(data.data);
    updatePagination(data.total, data.page, data.per_page);
  } catch(e) {
    showToast("Failed to load logs", "error");
  }
}

function renderLogsTable(logs) {
  const tbody = document.getElementById("logsTableBody");
  if (!tbody) return;
  if (!logs || logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:32px">No log entries found</td></tr>`;
    return;
  }
  tbody.innerHTML = logs.map(log => {
    const sev = (log.severity || "Low").toLowerCase();
    const ts  = new Date(log.timestamp).toLocaleString();
    const bar = Math.min(100, log.threat_score || 0);
    const barClass = bar >= 75 ? "critical" : bar >= 50 ? "high" : bar >= 25 ? "medium" : "low";
    return `
      <tr>
        <td>${ts}</td>
        <td>${log.src_ip || "—"}</td>
        <td>${log.dst_ip || "—"}</td>
        <td>${(log.protocol_type || "tcp").toUpperCase()}</td>
        <td>${log.service || "—"}</td>
        <td style="color:${COLORS[log.label]||'#e8eaf6'};font-weight:600">${log.label || "Normal"}</td>
        <td>
          <div class="threat-bar-wrap">
            <div class="threat-bar">
              <div class="threat-bar-fill ${barClass}" style="width:${bar}%"></div>
            </div>
            <span style="font-size:0.75rem;color:${COLORS[log.severity]||'#fff'}">${bar.toFixed(0)}</span>
          </div>
        </td>
        <td><span class="badge badge-${sev}">${log.severity || "Low"}</span></td>
        <td>${log.is_anomaly ? '<span style="color:#ff3d5a">⚠ Yes</span>' : '<span style="color:#6b7a99">No</span>'}</td>
      </tr>`;
  }).join("");
}

function updatePagination(total, page, perPage) {
  const totalPages = Math.ceil(total / perPage);
  setEl("paginationInfo", `Page ${page} of ${totalPages} (${total} total)`);
  const prev = document.getElementById("prevPage");
  const next = document.getElementById("nextPage");
  if (prev) prev.disabled = page <= 1;
  if (next) next.disabled = page >= totalPages;
}

// ── Threats page ───────────────────────────────────────────────────
async function loadThreats() {
  try {
    const data = await API.getRecentThreats();
    renderThreatsTable(data.threats || []);
  } catch(e) {
    showToast("Failed to load threats", "error");
  }
}

function renderThreatsTable(threats) {
  const tbody = document.getElementById("threatsTableBody");
  if (!tbody) return;
  if (!threats.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:32px">No critical threats detected</td></tr>`;
    return;
  }
  tbody.innerHTML = threats.map(t => {
    const sev = (t.severity || "Low").toLowerCase();
    const ts  = new Date(t.timestamp).toLocaleString();
    return `
      <tr>
        <td>${ts}</td>
        <td>${t.src_ip || "—"}</td>
        <td>${t.dst_ip || "—"}</td>
        <td style="color:${COLORS[t.label]||'#fff'};font-weight:700">${t.label||"—"}</td>
        <td><span style="font-size:1rem;font-weight:800;color:${COLORS[t.severity]||'#fff'}">${(t.threat_score||0).toFixed(0)}</span>/100</td>
        <td><span class="badge badge-${sev}">${t.severity||"Low"}</span></td>
        <td>${(t.protocol_type||"tcp").toUpperCase()} / ${t.service||"—"}</td>
      </tr>`;
  }).join("");
}

// ── File upload ────────────────────────────────────────────────────
function initUpload() {
  const zone   = document.getElementById("uploadZone");
  const input  = document.getElementById("fileInput");
  const btn    = document.getElementById("uploadBtn");
  if (!zone) return;

  zone.addEventListener("click",  () => input.click());
  zone.addEventListener("dragover",  e => { e.preventDefault(); zone.classList.add("drag-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    const file = e.dataTransfer.files[0];
    if (file) handleFileUpload(file);
  });

  input.addEventListener("change", () => {
    if (input.files[0]) handleFileUpload(input.files[0]);
  });

  btn?.addEventListener("click", () => {
    if (input.files[0]) handleFileUpload(input.files[0]);
    else showToast("Please select a file first", "info");
  });
}

async function handleFileUpload(file) {
  if (!file.name.endsWith(".csv")) {
    showToast("Only CSV files are supported", "error");
    return;
  }
  const progress = document.getElementById("uploadProgress");
  const result   = document.getElementById("uploadResult");
  if (progress) { progress.style.display = "block"; }
  if (result)   { result.textContent = ""; }

  // Animate progress
  let pct = 0;
  const fill = document.getElementById("progressFill");
  const prog = setInterval(() => {
    pct = Math.min(pct + 5, 85);
    if (fill) fill.style.width = pct + "%";
  }, 100);

  try {
    showToast(`Uploading ${file.name}...`, "info");
    const data = await API.uploadLogFile(file);
    clearInterval(prog);
    if (fill) fill.style.width = "100%";
    setTimeout(() => { if (progress) progress.style.display = "none"; }, 800);
    if (result) {
      result.innerHTML = `
        <div style="background:rgba(0,230,118,0.08);border:1px solid rgba(0,230,118,0.2);border-radius:10px;padding:16px;margin-top:16px">
          <div style="color:#00e676;font-weight:700;margin-bottom:8px">✓ Upload Complete</div>
          <div>Total Records: <strong>${data.total}</strong></div>
          <div>Attacks Found: <strong style="color:#ff3d5a">${data.attacks_found}</strong></div>
          <div>Avg Threat Score: <strong>${data.avg_threat_score}</strong>/100</div>
        </div>`;
    }
    showToast(`Analyzed ${data.total} records — ${data.attacks_found} attacks detected`, "success");
    loadDashboard();
  } catch(e) {
    clearInterval(prog);
    showToast("Upload failed: " + e.message, "error");
    if (progress) progress.style.display = "none";
  }
}

// ── Alert badge ────────────────────────────────────────────────────
function updateAlertBadge(count) {
  const badge = document.getElementById("alertBadge");
  if (!badge) return;
  badge.textContent = count || "";
  badge.style.display = count > 0 ? "inline-block" : "none";
}

// ── Toast notifications ────────────────────────────────────────────
function showToast(msg, type = "info") {
  let container = document.getElementById("toastContainer");
  if (!container) {
    container = document.createElement("div");
    container.id = "toastContainer";
    container.className = "toast-container";
    document.body.appendChild(container);
  }
  const icons = { success: "✓", error: "✕", info: "ℹ" };
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || "ℹ"}</span><span>${msg}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = "toastOut 0.4s ease forwards";
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

// ── Helpers ────────────────────────────────────────────────────────
function setEl(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function hexToRgba(hex, alpha = 1) {
  const r = parseInt(hex.slice(1,3), 16);
  const g = parseInt(hex.slice(3,5), 16);
  const b = parseInt(hex.slice(5,7), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}
