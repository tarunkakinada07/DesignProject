// Sentinel Extension Detector - Production Frontend Controller
// Dynamically connect to backend: if served from port 8000, use relative paths; if using VS Code Go Live (e.g. port 5500), connect to http://127.0.0.1:8000
const API_BASE = (window.location.protocol === "http:" && window.location.port === "8000") ? "" : "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", () => {
  const pdfLink = document.querySelector('a[href*="/api/docs/download-pdf"]');
  if (pdfLink && API_BASE) {
    pdfLink.href = `${API_BASE}/api/docs/download-pdf`;
  }
  initTabs();
  checkHealth();
  loadOverview();
  initScanner();
  initHistory();
  initEvaluation();
  initModal();
});

let currentScanResult = null;

// ==========================================
// 1. TAB NAVIGATION
// ==========================================
function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  const views = document.querySelectorAll(".view-panel");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = tab.getAttribute("data-tab");

      tabs.forEach(t => t.classList.remove("active"));
      views.forEach(v => v.classList.remove("active"));

      tab.classList.add("active");
      const targetView = document.getElementById(targetId);
      if (targetView) targetView.classList.add("active");

      // Lazy load tab data on click
      if (targetId === "overview-view") loadOverview();
      if (targetId === "history-view") loadHistory();
      if (targetId === "evaluation-view") loadEvaluation();
    });
  });
}

// ==========================================
// 2. SYSTEM HEALTH CHECK
// ==========================================
async function checkHealth() {
  const dot = document.getElementById("system-status-dot");
  const label = document.getElementById("system-status-text");

  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    dot.className = "status-indicator healthy";
    label.textContent = `Backend Operational (Localhost) &middot; ${data.model_loaded ? "Model Ready" : "Untrained"}`;
  } catch (err) {
    dot.className = "status-indicator error";
    label.textContent = "Backend Offline / Unreachable";
    console.error("Health check error:", err);
  }
}

// ==========================================
// 3. OVERVIEW VIEW CONTROLLER
// ==========================================
async function loadOverview() {
  try {
    const res = await fetch(`${API_BASE}/api/overview`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    document.getElementById("stats-total-samples").textContent = data.total_samples.toLocaleString();
    document.getElementById("stats-breakdown").textContent =
      `${data.malicious_samples} malicious &middot; ${data.benign_samples} benign &middot; ${data.suspicious_samples} suspicious`;
    document.getElementById("stats-malicious").textContent = data.malicious_samples.toLocaleString();
    document.getElementById("stats-benign").textContent = data.benign_samples.toLocaleString();
    document.getElementById("stats-total-scans").textContent = data.total_scans.toLocaleString();

    // Active model card
    const card = data.active_model;
    const badge = document.getElementById("active-model-status-badge");
    if (card) {
      badge.textContent = "Loaded & Active";
      badge.className = "badge-pill success";
      document.getElementById("model-algo").textContent = card.model_name.toUpperCase().replace("_", " ");
      document.getElementById("model-schema").textContent = card.schema_version || "1.0.0";
      document.getElementById("model-threshold").textContent = `${card.alert_threshold ?? 0.50} (Operating Threshold)`;
      document.getElementById("model-calibration").textContent = card.calibration_applied ? "Calibrated (Sigmoid/Isotonic)" : "None";
      document.getElementById("model-trained-at").textContent = card.trained_at ? new Date(card.trained_at).toLocaleString() : "Pre-trained";
    } else {
      badge.textContent = "No Model Registered";
      badge.className = "badge-pill warning";
      document.getElementById("model-algo").textContent = "Heuristic Baseline Rule";
      document.getElementById("model-schema").textContent = "1.0.0";
      document.getElementById("model-threshold").textContent = "0.50";
      document.getElementById("model-calibration").textContent = "N/A";
      document.getElementById("model-trained-at").textContent = "N/A";
    }
  } catch (err) {
    console.error("Failed to load overview stats:", err);
  }
}

// ==========================================
// 4. SCANNER CONTROLLER
// ==========================================
function initScanner() {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  const progressBox = document.getElementById("scan-progress");
  const progressText = document.getElementById("progress-text");
  const resultCard = document.getElementById("scan-result");

  if (!dropZone || !fileInput) return;

  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      handleUpload(fileInput.files[0]);
    }
  });

  async function handleUpload(file) {
    resultCard.classList.add("hidden");
    resultCard.innerHTML = "";
    progressBox.classList.remove("hidden");
    progressText.textContent = `Uploading and safely unpacking ${file.name}...`;

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/api/scan/upload`, {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      progressBox.classList.add("hidden");

      if (!res.ok) {
        showError(data.detail || "Upload or safe static inspection failed.");
        return;
      }

      currentScanResult = data;
      renderScanResult(data);
      loadOverview(); // Refresh scan count
    } catch (err) {
      progressBox.classList.add("hidden");
      showError(`Network or server error: ${err.message}`);
    } finally {
      fileInput.value = "";
    }
  }

  function showError(message) {
    resultCard.classList.remove("hidden");
    resultCard.innerHTML = `
      <div class="verdict-banner verdict-high-risk">
        <div class="verdict-title">
          <span>🚫</span> Inspection Blocked / Security Violation
        </div>
      </div>
      <div class="notice-box danger">
        <strong>Security & Parser Notice:</strong> ${escapeHtml(message)}
      </div>
    `;
  }

  function renderScanResult(data) {
    resultCard.classList.remove("hidden");
    const mf = data.manifest;
    const sum = data.extraction_summary;
    const isIOC = data.matched_threat_intel;
    const scorePct = Math.round(data.risk_score * 100);
    const thresholdPct = Math.round(data.alert_threshold * 100);

    // Determine banner theme
    let bannerClass = "verdict-low-risk";
    let scoreColor = "var(--accent-green)";
    let bannerIcon = "🛡️";

    if (isIOC || data.risk_verdict === "HIGH_RISK") {
      bannerClass = isIOC ? "verdict-known-ioc" : "verdict-high-risk";
      scoreColor = "var(--accent-red)";
      bannerIcon = "🚨";
    } else if (data.risk_verdict === "SUSPICIOUS_UNCERTAIN") {
      bannerClass = "verdict-suspicious";
      scoreColor = "var(--accent-yellow)";
      bannerIcon = "⚠️";
    }

    // Threat Intel details box
    let threatIntelHtml = "";
    if (isIOC && data.threat_intel_details) {
      const ti = data.threat_intel_details;
      threatIntelHtml = `
        <div class="notice-box danger" style="margin-bottom: 1rem;">
          <h4 style="margin-bottom: 0.3rem;">⚠️ Matched Verified Threat Intelligence Record</h4>
          <p><strong>Threat Family:</strong> ${escapeHtml(ti.threat_family || 'Generic Malware')} &middot; <strong>Repository Source:</strong> ${escapeHtml(ti.source)}</p>
          <p style="font-size: 0.82rem; margin-top: 0.2rem;"><strong>Label Evidence:</strong> ${escapeHtml(ti.label_evidence || 'Exact hash or extension ID match in malicious provenance catalog.')}</p>
        </div>
      `;
    }

    // Top SHAP Risk Factors
    let topRiskHtml = "";
    if (data.top_risk_factors && data.top_risk_factors.length > 0) {
      topRiskHtml = data.top_risk_factors.map(f => `
        <div class="factor-item">
          <div>
            <div class="factor-name">${escapeHtml(f.feature_name)} = ${f.feature_value}</div>
            <div class="factor-desc">${escapeHtml(f.description)}</div>
          </div>
          <span class="factor-badge risk">+${(f.shap_value * 100).toFixed(1)}% Risk</span>
        </div>
      `).join("");
    } else {
      topRiskHtml = `<div class="sub-desc">No significant high-risk indicators detected by model.</div>`;
    }

    // Protective factors
    let protectiveHtml = "";
    if (data.protective_factors && data.protective_factors.length > 0) {
      protectiveHtml = data.protective_factors.map(f => `
        <div class="factor-item">
          <div>
            <div class="factor-name">${escapeHtml(f.feature_name)} = ${f.feature_value}</div>
            <div class="factor-desc">${escapeHtml(f.description)}</div>
          </div>
          <span class="factor-badge protective">${(f.shap_value * 100).toFixed(1)}% Protective</span>
        </div>
      `).join("");
    }

    // Permissions tags
    const permsHtml = mf.permissions && mf.permissions.length > 0
      ? mf.permissions.map(p => {
          const isHigh = ["cookies", "webRequest", "webRequestBlocking", "proxy", "debugger", "management", "nativeMessaging"].includes(p);
          return `<span class="tag ${isHigh ? 'high-risk' : ''}">${escapeHtml(p)}</span>`;
        }).join(" ")
      : "<em>None declared</em>";

    const hostPermsHtml = mf.host_permissions && mf.host_permissions.length > 0
      ? mf.host_permissions.map(p => `<span class="tag high-risk">${escapeHtml(p)}</span>`).join(" ")
      : "<em>None declared</em>";

    // Evidence observations
    const evidenceHtml = data.evidence && data.evidence.length > 0
      ? data.evidence.map(e => `<li>${escapeHtml(e)}</li>`).join("")
      : "<li>No abnormal static heuristic rules triggered.</li>";

    resultCard.innerHTML = `
      <!-- Verdict Banner -->
      <div class="verdict-banner ${bannerClass}">
        <div class="verdict-title">
          <span>${bannerIcon}</span>
          <div>
            <div>${escapeHtml(data.risk_verdict_label)}</div>
            <div style="font-size: 0.8rem; font-weight: normal; color: var(--text-secondary); margin-top: 0.2rem;">
              Verdict Category: <code>${escapeHtml(data.risk_verdict)}</code>
            </div>
          </div>
        </div>
        <div class="verdict-score-box">
          <div class="verdict-score-num" style="color: ${scoreColor};">${(data.risk_score * 100).toFixed(1)}%</div>
          <div class="verdict-score-sub">Model Risk Score</div>
        </div>
      </div>

      ${threatIntelHtml}

      <!-- Risk Meter Gauge -->
      <div class="risk-meter-container">
        <div style="display: flex; justify-content: space-between; font-size: 0.8rem; font-weight: 600;">
          <span>Risk Assessment Meter</span>
          <span>Operating Alert Threshold: ${thresholdPct}%</span>
        </div>
        <div class="risk-meter-bar">
          <div class="risk-meter-fill" style="width: ${scorePct}%; background: ${scoreColor};"></div>
          <div class="risk-meter-threshold-marker" style="left: ${thresholdPct}%;" title="Alert Threshold (${thresholdPct}%)"></div>
        </div>
        <div class="risk-meter-labels">
          <span>0.0 (Benign Baseline)</span>
          <span>Threshold Marker (${thresholdPct}%)</span>
          <span>1.0 (Malicious)</span>
        </div>
      </div>

      <!-- Two Column: Manifest Meta & Evidence -->
      <div class="two-col-grid">
        <div class="sub-card">
          <h3>Manifest & Package Profile</h3>
          <table class="meta-table">
            <tr><th>Extension Name</th><td><strong>${escapeHtml(mf.name)}</strong></td></tr>
            <tr><th>Version</th><td>${escapeHtml(mf.version)} (Manifest V${mf.manifest_version})</td></tr>
            <tr><th>Package SHA-256</th><td><code title="${escapeHtml(data.sha256)}">${escapeHtml(data.sha256.substring(0, 24))}...</code></td></tr>
            <tr><th>Format / Files</th><td>${data.format.toUpperCase()} &middot; ${sum.file_count} files (${sum.js_file_count} JS, ${formatBytes(sum.total_bytes)})</td></tr>
            <tr><th>Background Type</th><td>${escapeHtml(mf.background_type)}</td></tr>
            <tr><th>CSP Unsafe Eval</th><td>${mf.csp_has_unsafe_eval ? "<strong class='text-red'>⚠️ Permitted (unsafe-eval)</strong>" : "Restricted"}</td></tr>
            <tr><th>Update URL</th><td>${mf.update_url_is_official_store ? "<span class='text-green'>Official Chrome Web Store</span>" : (mf.update_url ? "<span class='text-red'>Custom / External URL</span>" : "None declared")}</td></tr>
          </table>
        </div>

        <div class="sub-card">
          <h3>Permissions Security Audit</h3>
          <p class="sub-desc">Declared extension capabilities in browser manifest.</p>
          <div style="margin-bottom: 0.75rem;">
            <div style="font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 0.25rem;">API Permissions:</div>
            <div class="tag-list">${permsHtml}</div>
          </div>
          <div>
            <div style="font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 0.25rem;">Host Permissions (Origin Access):</div>
            <div class="tag-list">${hostPermsHtml}</div>
          </div>
        </div>
      </div>

      <!-- SHAP Explainability Section -->
      <div class="sub-card">
        <h3>Local Feature Attribution (Tree SHAP Contributors)</h3>
        <p class="sub-desc">Features driving the risk score up or down for this specific extension.</p>
        
        <div class="two-col-grid">
          <div>
            <h4 style="color: var(--accent-red); margin-bottom: 0.4rem; font-size: 0.88rem;">Top Risk-Elevating Factors</h4>
            <div class="factor-list">${topRiskHtml}</div>
          </div>
          <div>
            <h4 style="color: var(--accent-green); margin-bottom: 0.4rem; font-size: 0.88rem;">Protective Factors</h4>
            <div class="factor-list">${protectiveHtml || '<div class="sub-desc">No protective benign factors detected.</div>'}</div>
          </div>
        </div>
      </div>

      <!-- Static Heuristic Evidence -->
      <div class="sub-card">
        <h3>Static Code & Heuristic Observations</h3>
        <ul class="error-list">${evidenceHtml}</ul>
      </div>

      <!-- Disclaimers & Action Buttons -->
      <div class="notice-box warning">
        <strong>Prevalence Warning:</strong> ${escapeHtml(data.prevalence_warning)}
      </div>
      <div class="notice-box info">
        <strong>Static Analysis Limitation:</strong> ${escapeHtml(data.limitations_disclaimer)}
      </div>

      <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 0.5rem;">
        <button class="btn btn-secondary" id="btn-download-scan-json">⬇️ Download JSON Report</button>
      </div>
    `;

    document.getElementById("btn-download-scan-json").addEventListener("click", () => {
      downloadJson(data, `scan_${data.sha256.substring(0, 12)}.json`);
    });
  }
}

// ==========================================
// 5. SCAN HISTORY CONTROLLER
// ==========================================
function initHistory() {
  const searchInput = document.getElementById("history-search");
  const refreshBtn = document.getElementById("btn-refresh-history");

  if (refreshBtn) refreshBtn.addEventListener("click", () => loadHistory());

  let debounceTimer;
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        loadHistory(searchInput.value.trim());
      }, 300);
    });
  }
}

async function loadHistory(searchQuery = "") {
  const tbody = document.getElementById("history-table-body");
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="7" class="text-center">Loading scan history...</td></tr>`;

  try {
    const url = searchQuery ? `${API_BASE}/api/history?search=${encodeURIComponent(searchQuery)}` : `${API_BASE}/api/history`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const rows = await res.json();

    if (rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding: 2rem;">No scan history found.</td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map(r => {
      const dt = new Date(r.timestamp).toLocaleString();
      const scoreStr = r.score !== null ? `${(r.score * 100).toFixed(1)}%` : "N/A";
      
      let pillClass = "success";
      if (r.matched_threat_intel || r.risk_category === "HIGH_RISK") pillClass = "danger";
      else if (r.risk_category === "SUSPICIOUS_UNCERTAIN") pillClass = "warning";

      return `
        <tr>
          <td><span style="font-size: 0.78rem; color: var(--text-secondary);">${dt}</span></td>
          <td><strong>${escapeHtml(r.extension_name || 'Unnamed')}</strong></td>
          <td>${escapeHtml(r.version || '1.0')}</td>
          <td><code title="${escapeHtml(r.sha256)}">${escapeHtml(r.sha256.substring(0, 12))}...</code></td>
          <td><span class="badge-pill ${pillClass}">${escapeHtml(r.risk_category)}</span></td>
          <td><strong>${scoreStr}</strong></td>
          <td>
            <div style="display: flex; gap: 0.4rem;">
              <button class="btn-action-sm" onclick="viewHistoryDetail('${r.scan_id}')">Inspect</button>
              <button class="btn-danger-sm" onclick="deleteHistoryRecord('${r.scan_id}')">&times;</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-red">Failed to load history: ${escapeHtml(err.message)}</td></tr>`;
  }
}

window.viewHistoryDetail = async function(scanId) {
  try {
    const res = await fetch(`${API_BASE}/api/history/${scanId}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const report = await res.json();
    openDetailModal(report);
  } catch (err) {
    alert(`Could not load scan details: ${err.message}`);
  }
};

window.deleteHistoryRecord = async function(scanId) {
  if (!confirm("Are you sure you want to delete this scan audit record?")) return;
  try {
    const res = await fetch(`${API_BASE}/api/history/${scanId}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    loadHistory();
    loadOverview();
  } catch (err) {
    alert(`Deletion failed: ${err.message}`);
  }
};

// ==========================================
// 6. MODEL EVALUATION CONTROLLER
// ==========================================
function initEvaluation() {
  const btnRefresh = document.getElementById("btn-refresh-eval");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", () => loadEvaluation());
  }
}

async function loadEvaluation() {
  try {
    const res = await fetch(`${API_BASE}/api/evaluation`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const report = await res.json();
    renderEvaluationReport(report);
  } catch (err) {
    console.error("Failed to load evaluation report:", err);
  }
}

function renderEvaluationReport(report) {
  const m = report.metrics;
  const rates = m.rates;
  const raw = m.raw_counts;
  const prev = m.realistic_prevalence_adjustment;
  const boot = report.bootstrap;

  // Core metrics
  document.getElementById("eval-prec").textContent = `${(rates.precision * 100).toFixed(1)}%`;
  document.getElementById("eval-rec").textContent = `${(rates.recall * 100).toFixed(1)}%`;
  document.getElementById("eval-f1").textContent = rates.f1.toFixed(3);
  document.getElementById("eval-fpr").textContent = `${(rates.false_positive_rate * 100).toFixed(1)}%`;
  document.getElementById("eval-roc").textContent = rates.roc_auc.toFixed(3);
  document.getElementById("eval-prauc").textContent = rates.pr_auc.toFixed(3);
  document.getElementById("eval-latency").textContent = `${rates.avg_inference_latency_ms.toFixed(2)} ms`;
  document.getElementById("eval-brier").textContent = rates.brier_calibration_score.toFixed(3);

  // Confusion matrix
  document.getElementById("cm-tn").textContent = raw.tn;
  document.getElementById("cm-fp").textContent = raw.fp;
  document.getElementById("cm-fn").textContent = raw.fn;
  document.getElementById("cm-tp").textContent = raw.tp;

  // Prevalence
  document.getElementById("prev-test-prec").textContent = `${(rates.precision * 100).toFixed(1)}%`;
  document.getElementById("prev-1pct").textContent = `${(prev.precision_at_1pct_prevalence * 100).toFixed(2)}%`;
  document.getElementById("prev-01pct").textContent = `${(prev.precision_at_0_1pct_prevalence * 100).toFixed(3)}%`;
  document.getElementById("eval-prev-warning").textContent = prev.prevalence_warning;

  // Ablation Table
  const abTable = document.getElementById("ablation-table-body");
  if (report.ablation_study && report.ablation_study.length > 0) {
    abTable.innerHTML = report.ablation_study.map(row => `
      <tr>
        <td><strong>${escapeHtml(row.tier.replace(/_/g, ' '))}</strong></td>
        <td>${row.feature_count} features</td>
        <td>${(row.precision * 100).toFixed(1)}%</td>
        <td>${(row.recall * 100).toFixed(1)}%</td>
        <td><strong>${row.f1.toFixed(3)}</strong></td>
        <td>${(row.fpr * 100).toFixed(1)}%</td>
        <td style="color: ${row.delta_f1_gain >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
          ${row.delta_f1_gain >= 0 ? '+' : ''}${row.delta_f1_gain.toFixed(4)}
        </td>
      </tr>
    `).join("");
  }

  // Bootstrap Table
  const bTable = document.getElementById("bootstrap-table-body");
  if (boot && boot.confidence_intervals) {
    const cis = boot.confidence_intervals;
    bTable.innerHTML = Object.entries(cis).map(([key, val]) => `
      <tr>
        <td><strong>${key.toUpperCase()}</strong></td>
        <td>${val.estimate.toFixed(4)}</td>
        <td><code>[${val.ci_lower.toFixed(4)}, ${val.ci_upper.toFixed(4)}]</code></td>
      </tr>
    `).join("");

    if (boot.sample_size_disclosure) {
      const disc = boot.sample_size_disclosure;
      document.getElementById("bootstrap-disclosure").textContent =
        `Evaluated on N=${disc.total_samples} samples (${disc.malicious_samples} malicious, ${disc.benign_samples} benign) across ${disc.successful_bootstrap_iterations} iterations.`;
    }
  }

  // Obfuscation Test
  const obf = report.obfuscation_robustness;
  if (obf) {
    document.getElementById("obf-recall-shift").textContent =
      `${(obf.clean_baseline.recall * 100).toFixed(1)}% &rarr; ${(obf.under_obfuscation.recall * 100).toFixed(1)}% (&Delta; ${obf.robustness_deltas.delta_recall >= 0 ? '+' : ''}${(obf.robustness_deltas.delta_recall * 100).toFixed(1)}%)`;
    document.getElementById("obf-fpr-shift").textContent =
      `${(obf.clean_baseline.fpr * 100).toFixed(1)}% &rarr; ${(obf.under_obfuscation.fpr * 100).toFixed(1)}% (&Delta; ${obf.robustness_deltas.delta_fpr >= 0 ? '+' : ''}${(obf.robustness_deltas.delta_fpr * 100).toFixed(1)}%)`;
    document.getElementById("obf-interpretation").textContent = obf.robustness_deltas.interpretation;
  }

  // Error Analysis
  const ea = report.error_analysis;
  if (ea) {
    document.getElementById("fp-count").textContent = ea.summary.false_positive_count;
    document.getElementById("fn-count").textContent = ea.summary.false_negative_count;

    const fpList = document.getElementById("fp-category-list");
    const fpCats = ea.false_positive_breakdown.category_distribution;
    if (Object.keys(fpCats).length > 0) {
      fpList.innerHTML = Object.entries(fpCats).map(([cat, cnt]) => `
        <li><strong>${cnt}x</strong> &middot; ${escapeHtml(cat)}</li>
      `).join("");
    } else {
      fpList.innerHTML = `<li>Zero False Positives in held-out partition.</li>`;
    }

    const fnList = document.getElementById("fn-category-list");
    const fnCats = ea.false_negative_breakdown.category_distribution;
    if (Object.keys(fnCats).length > 0) {
      fnList.innerHTML = Object.entries(fnCats).map(([cat, cnt]) => `
        <li><strong>${cnt}x</strong> &middot; ${escapeHtml(cat)}</li>
      `).join("");
    } else {
      fnList.innerHTML = `<li>Zero False Negatives in held-out partition.</li>`;
    }
  }
}

// ==========================================
// 7. MODAL CONTROLLER
// ==========================================
let activeModalReport = null;

function initModal() {
  const overlay = document.getElementById("detail-modal");
  const closeBtn = document.getElementById("modal-close");
  const closeBtn2 = document.getElementById("modal-btn-close");
  const downloadBtn = document.getElementById("modal-btn-download");

  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (closeBtn2) closeBtn2.addEventListener("click", closeModal);
  if (overlay) {
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeModal();
    });
  }

  if (downloadBtn) {
    downloadBtn.addEventListener("click", () => {
      if (activeModalReport) {
        const hash = activeModalReport.sha256 ? activeModalReport.sha256.substring(0, 12) : "report";
        downloadJson(activeModalReport, `scan_report_${hash}.json`);
      }
    });
  }
}

function openDetailModal(report) {
  activeModalReport = report;
  const overlay = document.getElementById("detail-modal");
  const body = document.getElementById("modal-body");
  const title = document.getElementById("modal-title");

  const mf = report.manifest || {};
  title.textContent = `Scan Report: ${mf.name || report.extension_name || 'Extension'}`;

  body.innerHTML = `
    <div style="margin-bottom: 1rem;">
      <span class="badge-pill danger">${escapeHtml(report.risk_verdict || report.risk_category || 'RECORD')}</span>
      <span style="margin-left: 0.5rem; font-size: 0.85rem; color: var(--text-secondary);">Score: ${(report.risk_score || report.score || 0) * 100}%</span>
    </div>
    <pre class="json-pre">${escapeHtml(JSON.stringify(report, null, 2))}</pre>
  `;

  overlay.classList.remove("hidden");
}

function closeModal() {
  const overlay = document.getElementById("detail-modal");
  if (overlay) overlay.classList.add("hidden");
}

// ==========================================
// UTILITY FUNCTIONS
// ==========================================
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str).replace(/[&<>"']/g, s => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[s]);
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function downloadJson(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
