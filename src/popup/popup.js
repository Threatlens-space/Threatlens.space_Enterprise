import { DEFAULT_CONFIG, storageManager } from "../shared/storageManager.js";
import { formatTimestamp, getRiskLabel, humanizeRuleType, maskSecret, isHighRiskExtension } from "../shared/utils.js";

const tabButtons = document.querySelectorAll(".tab-button");
const sections = document.querySelectorAll(".panel-section");
const ruleForms = document.querySelectorAll(".rule-form");
const generalSettingInputs = document.querySelectorAll("[data-setting]");
const vtSettingInputs = document.querySelectorAll("[data-vt-setting]");
const vtForm = document.getElementById("vt-form");
const vtDeleteButton = document.getElementById("vt-delete");
const vtKeyInput = document.getElementById("vt-api-key");
const vtKeyMask = document.getElementById("vt-key-mask");
const vtMessage = document.getElementById("vt-message");

const haSettingInputs = document.querySelectorAll("[data-ha-setting]");
const haForm = document.getElementById("form-ha-key");
const haDeleteButton = document.getElementById("ha-delete");
const haKeyInput = document.getElementById("ha-api-key");
const haKeyMask = document.getElementById("ha-key-mask");
const haMessage = document.getElementById("ha-message");

const pendingList = document.getElementById("pending-list");
const pendingCountCopy = document.getElementById("pending-count-copy");
const reviewShell = document.getElementById("review-shell");
const sandboxContentContainer = document.getElementById("sandbox-content-container");
const heroCopy = document.getElementById("hero-copy");
const heroStatus = document.getElementById("hero-status");
const heroMeta = document.getElementById("hero-meta");
const activitySummary = document.getElementById("activity-summary");
const resetStatsButton = document.getElementById("reset-stats");
const btnClearQueue = document.getElementById("btn-clear-queue");

let busyAction = "";
let activeSection = "intel";
let activeInsightTab = "summary";
let selectedDownloadId = null;
const addedQuickRules = new Set();

let lastRenderedStateJson = null;
const automaticScanRequests = new Map();   // key → timestamp of last fire
const scanErrorCounts = new Map();          // downloadId → { vt, urlscan, hash, ip, domain }
const lastSeenStatuses = new Map();         // downloadId → { vt, urlscan } — tracks last-seen status per provider for transition detection
const MAX_AUTO_RETRY = 2;                   // max retries per provider per download
// Cooldown between automatic scan requests for the same download.
// Set to 2 minutes to prevent the popup from re-firing scans in a tight loop.
const AUTOMATIC_SCAN_REQUEST_TTL_MS = 120_000; // 2 minutes
// A scan stuck in 'loading' is only considered truly stuck after 5 minutes.
const POPUP_SCAN_STALE_MS = 300_000; // 5 minutes — prevents false re-trigger loops
const RENDER_DEBOUNCE_MS = 300;

// Performance: debounce + RAF render lock
let _renderDebounceTimer = null;
let _renderPending = false;
let _renderQueued = false;
let _configCache = null;
let _statsCache = null;
let _pendingChangedOnly = false; // Track if only pending keys changed (skip config/stats refetch)
// Render signature — skip full DOM rebuild when data hasn't meaningfully changed
let _lastRenderSignature = "";
// SVG mascot cache — avoids regenerating + re-parsing the same SVG every render
let _lastMascotState = "";
let _lastMascotHtml = "";

/**
 * Copies text to clipboard and briefly changes the feedback element's text.
 */
function copyToClipboard(text, feedbackEl) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    if (!feedbackEl) return;
    const orig = feedbackEl.textContent;
    feedbackEl.textContent = "✓ Copied!";
    setTimeout(() => { feedbackEl.textContent = orig; }, 1500);
  }).catch(() => {});
}

/**
 * Returns a short display string for sourceDisplay values that are data: URLs.
 */
function truncateSourceDisplay(display) {
  if (!display) return "Unknown";
  if (display.startsWith("data:")) {
    const mime = display.split(";")[0].replace("data:", "") || "data";
    return `Data URL (${mime})`;
  }
  return display;
}

/**
 * Utility to prevent DOM thrashing.
 * Compares against the last requested HTML string to avoid browser serialization mismatches.
 * Returns true if the DOM was actually updated (meaning event listeners need rebinding).
 */
function updateDOM(element, htmlString) {
  if (element._lastHtml !== htmlString) {
    element._lastHtml = htmlString;
    element.innerHTML = htmlString;
    return true;
  }
  return false;
}

initialize();

function initialize() {
  bindTabs();
  bindRuleForms();
  bindGeneralSettings();
  bindVirusTotalControls();
  bindHybridAnalysisControls();
  bindSessionControls();
  chrome.storage.onChanged.addListener(handleStorageChanged);
  void render();
}

function bindTabs() {
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      showSection(button.dataset.sectionTarget);
    });
  });
}

function showSection(target) {
  activeSection = target;
  tabButtons.forEach((tab) => tab.classList.toggle("is-active", tab.dataset.sectionTarget === target));
  sections.forEach((section) => section.classList.toggle("is-visible", section.dataset.section === target));
}

function bindRuleForms() {
  ruleForms.forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const listType = form.dataset.listType;
      const formData = new FormData(form);
      const ruleType = formData.get("ruleType");
      const ruleValue = formData.get("ruleValue");
      const message = document.querySelector(`[data-form-message="${listType}"]`);

      try {
        await storageManager.addRule(listType, ruleType, ruleValue);
        message.textContent = `${humanizeRuleType(ruleType)} rule saved.`;
        form.reset();
        form.querySelector('select[name="ruleType"]').value = ruleType;
        await render();
      } catch (error) {
        message.textContent = error.message;
      }
    });
  });
}

function bindGeneralSettings() {
  generalSettingInputs.forEach((input) => {
    input.addEventListener("change", async () => {
      await storageManager.updateSettings({
        [input.dataset.setting]: input.checked
      });
      await render();
    });
  });
}

function bindVirusTotalControls() {
  vtForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const apiKey = vtKeyInput.value.trim();

    await storageManager.updateVirusTotal({
      apiKey
    });

    vtMessage.textContent = apiKey
      ? "VirusTotal API key saved. ThreatLens will use it for inline results."
      : "VirusTotal API key cleared.";
    await render();
  });

  vtDeleteButton.addEventListener("click", async () => {
    await storageManager.updateVirusTotal({
      apiKey: ""
    });
    vtMessage.textContent = "VirusTotal API key deleted.";
    await render();
  });

  vtSettingInputs.forEach((input) => {
    input.addEventListener("change", async () => {
      await storageManager.updateVirusTotal({
        [input.dataset.vtSetting]: input.checked
      });
      await render();
    });
  });
}

function bindHybridAnalysisControls() {
  haForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const apiKey = haKeyInput.value.trim();

    await storageManager.updateHybridAnalysis({ apiKey });

    haMessage.textContent = apiKey
      ? "Hybrid Analysis API key saved."
      : "Hybrid Analysis API key cleared.";
    await render();
  });

  haDeleteButton.addEventListener("click", async () => {
    await storageManager.updateHybridAnalysis({ apiKey: "" });
    haMessage.textContent = "Hybrid Analysis API key deleted.";
    await render();
  });

  haSettingInputs.forEach((input) => {
    input.addEventListener("change", async () => {
      await storageManager.updateHybridAnalysis({
        [input.dataset.haSetting]: input.checked
      });
      await render();
    });
  });
}

function bindSessionControls() {
  resetStatsButton.addEventListener("click", async () => {
    await storageManager.resetStats();
    await render();
  });

  btnClearQueue.addEventListener("click", async () => {
    const originalText = btnClearQueue.textContent;
    btnClearQueue.textContent = "Clearing...";
    btnClearQueue.disabled = true;

    try {
      const allPending = await storageManager.listPendingDownloadsRaw();
      const activePending = allPending.filter((item) =>
        item.status === "awaiting_user" ||
        item.status === "checking_reputation"
      );

      if (activePending && activePending.length > 0) {
        const promises = activePending.map(item => {
          return new Promise(resolve => {
            chrome.runtime.sendMessage(
              { type: "threatlens:download-action", downloadId: item.downloadId, action: "block" },
              (resp) => {
                const _ = chrome.runtime.lastError;
                resolve(resp);
              }
            );
          });
        });
        await Promise.allSettled(promises);
      }
      selectedDownloadId = null;
      void render();
    } catch (e) {
      console.error("Failed to clear queue", e);
    } finally {
      btnClearQueue.textContent = originalText;
      btnClearQueue.disabled = false;
    }
  });
}

function scheduleRender() {
  _renderQueued = true;
  clearTimeout(_renderDebounceTimer);
  _renderDebounceTimer = setTimeout(flushScheduledRender, RENDER_DEBOUNCE_MS);
}

function flushScheduledRender() {
  _renderDebounceTimer = null;

  if (_renderPending) {
    return;
  }

  _renderPending = true;
  _renderQueued = false;
  requestAnimationFrame(async () => {
    try {
      await render();
    } finally {
      _renderPending = false;
      if (_renderQueued) {
        clearTimeout(_renderDebounceTimer);
        _renderDebounceTimer = setTimeout(flushScheduledRender, RENDER_DEBOUNCE_MS);
      }
    }
  });
}

async function render() {
  let config, stats, pending;

  if (_pendingChangedOnly && _configCache && _statsCache) {
    // Only pending data changed — reuse cached config and stats
    config = _configCache;
    stats = _statsCache;
    pending = await storageManager.listPendingDownloadsRaw();
  } else {
    // Full fetch — config or stats changed, or first render
    [config, stats, pending] = await Promise.all([
      storageManager.getConfig(),
      storageManager.getStats(),
      storageManager.listPendingDownloadsRaw()
    ]);
    _configCache = config;
    _statsCache = stats;
  }

  const activePending = pending.filter((item) =>
    item.status === "awaiting_user" ||
    item.status === "checking_reputation"
  );

  const blockedPending = pending.filter((item) =>
    item.status === "blocked_rule" ||
    item.status === "blocked_user"
  );

  const current = getSelectedRecord(activePending);
  const blockedCurrent = !current ? (blockedPending[0] || null) : null;
  const record = current || blockedCurrent;

  // Build a lightweight fingerprint of the data that actually drives the UI.
  // If nothing meaningful changed, skip the expensive DOM rebuild entirely.
  // fileHashProgress is bucketed to 5% increments so minor sub-percent changes
  // don't cause unnecessary redraws — only meaningful progress steps do.
  const rawPct = record?.fileHashProgress || "";
  const pctMatch = rawPct.match(/^(\d+)%$/);
  const progressBucket = pctMatch ? Math.floor(parseInt(pctMatch[1], 10) / 5) * 5 : rawPct;

  const sig = JSON.stringify({
    id: record?.downloadId || null,
    st: record?.status,
    // Use live-computed indicator — not stored riskIndicator
    li: computeLiveIndicator(record),
    rs: record?.reputation?.status,
    rv: record?.reputation?.verdict,
    rm: record?.reputation?.stats?.malicious ?? 0,
    fhs: record?.fileHashStatus,
    fhp: progressBucket,
    fh: record?.fileHash ? "y" : "n",
    ips: record?.providerReports?.ipReputation?.status,
    ipsc: record?.providerReports?.ipReputation?.scanStatus,
    das: record?.domainAudit?.status,
    us: record?.providerReports?.urlscan?.status,
    uv: record?.providerReports?.urlscan?.verdict,
    has: record?.providerReports?.hybridAnalysis?.status,
    hav: record?.providerReports?.hybridAnalysis?.verdict,
    hsj: record?.sandboxJob?.status,
    ac: activePending.length,
    bc: blockedPending.length,
    rules: JSON.stringify(config.allowlist) + JSON.stringify(config.blocklist),
    vtConfig: JSON.stringify(config.integrations?.virusTotal || {}),
    cfg: _pendingChangedOnly ? "same" : "new"
  });
  _pendingChangedOnly = false;

  if (sig === _lastRenderSignature) {
    return; // Nothing meaningful changed — skip DOM rebuild
  }
  _lastRenderSignature = sig;

  // Render all sections every cycle — ensures all event listeners are always bound
  renderHero(record, activePending.length, stats.lastEventAt);
  renderIntelPanel(record, config.integrations.virusTotal);
  renderCurrentReview(current, blockedCurrent, config.integrations.virusTotal);
  renderPendingList(activePending, current?.downloadId || null);
  renderRuleGroups("allowlist", config.allowlist);
  renderRuleGroups("blocklist", config.blocklist);
  renderSettings(config.settings);
  renderVirusTotal(config.integrations.virusTotal);
  renderHybridAnalysis(config.integrations.hybridAnalysis);
  renderSandboxTab(current);
  renderActivitySummary(stats);
  showSection(activeSection);
  scheduleAutomaticScan(current, config.integrations.virusTotal);
}

function getSelectedRecord(activePending) {
  if (!activePending.length) {
    selectedDownloadId = null;
    return null;
  }

  const current = activePending.find((item) => item.downloadId === selectedDownloadId) || activePending[0];
  selectedDownloadId = current.downloadId;
  return current;
}

function renderHero(current, pendingCount, lastEventAt) {
  if (current) {
    // Use live indicator — not stored riskIndicator which may be stale
    const liveLabel = computeLiveIndicator(current);
    heroStatus.textContent = liveLabel;
    heroStatus.className = `status-pill ${getToneClassFromIndicator(liveLabel)}`;
    heroCopy.textContent = getReviewCopy(current);
    heroMeta.textContent = pendingCount > 1
      ? `${pendingCount} intercepted downloads are waiting`
      : "1 intercepted download is waiting";
    return;
  }

  heroStatus.textContent = "Monitoring";
  heroStatus.className = "status-pill tone-good";
  heroCopy.textContent = "ThreatLens monitors new downloads and intercepts only the ones that need a decision.";
  heroMeta.textContent = lastEventAt ? `Last activity ${formatTimestamp(lastEventAt)}` : "No active decisions";
}

function renderIntelPanel(record, vtConfig) {
  const container = document.getElementById("intel-mascot-container");
  const title = document.getElementById("intel-verdict-title");
  const copyBox = document.getElementById("intel-why-box");
  const copyFallback = document.getElementById("intel-verdict-fallback");
  const copyText = document.getElementById("intel-verdict-copy");
  const detailsBtn = document.getElementById("intel-more-details");
  const actionGroup = document.getElementById("intel-action-group");
  const advancedScanContainer = document.getElementById("intel-advanced-scan-container");
  const advancedScanBtn = document.getElementById("intel-btn-advanced-scan");
  const fileHashDisplay = document.getElementById("intel-file-hash-display");
  const fileHashValue = document.getElementById("intel-file-hash-value");
  
  let allowBtn = document.getElementById("intel-btn-allow");
  let blockBtn = document.getElementById("intel-btn-block");
  if (!container || !title || !copyBox || !copyFallback || !copyText || !detailsBtn || !actionGroup) return;

  // Threat Hunter Eye Drone - Premium High-Fidelity Mascot
  const getMascotSvg = (colorVar, state) => {
    // Chrome sometimes fails to resolve CSS variables inside SVG gradients/strokes when injected dynamically via innerHTML.
    // We map them to hardcoded hex colors to guarantee visibility.
    const colorMap = {
      "var(--brand-mid)": "#1A4F9C",
      "var(--info)": "#2563eb",
      "var(--danger)": "#dc2626",
      "var(--warn)": "#d97706",
      "var(--good)": "#16a34a"
    };
    const color = colorMap[colorVar] || colorVar;

    let eyeCenter = `
       <circle cx="80" cy="80" r="28" fill="${color}" class="tl-pupil"/>
       <circle cx="70" cy="70" r="8" fill="#ffffff" opacity="0.8"/>
    `;
    let lidTop = `M 20,80 Q 80,20 140,80`;
    let lidBot = `Q 80,140 20,80`;
    let expressionClass = "tl-state-safe";

    if (state === "scanning" || state === "unknown") {
       expressionClass = state === "scanning" ? "tl-state-scan" : "tl-state-unknown";
    } else if (state === "danger") {
       expressionClass = "tl-state-danger";
       // Keeping lidTop and lidBot the same as idle (wide open) instead of narrowing them
    }

    const clipId = 'eye-clip-' + Math.random().toString(36).substr(2, 9);
    return `
      <svg class="tl-mascot ${expressionClass}" width="140" height="140" viewBox="0 0 160 160" xmlns="http://www.w3.org/2000/svg">
         <defs>
           <radialGradient id="glow-${state}" cx="50%" cy="50%" r="50%">
             <stop offset="0%" stop-color="${color}" stop-opacity="0.4" />
             <stop offset="100%" stop-color="${color}" stop-opacity="0" />
           </radialGradient>
           <linearGradient id="armor-grad" x1="0%" y1="0%" x2="100%" y2="100%">
             <stop offset="0%" stop-color="#1e293b" />
             <stop offset="100%" stop-color="#0f172a" />
           </linearGradient>
           <clipPath id="${clipId}">
             <path d="${lidTop} ${lidBot} Z" />
           </clipPath>
         </defs>
         
         <!-- Ambient Glow -->
         <circle cx="80" cy="80" r="75" fill="url(#glow-${state})" class="tl-ambient-glow"/>

         <!-- Cybernetic Outer Rings -->
         <circle cx="80" cy="80" r="68" fill="none" stroke="${color}" stroke-width="1" stroke-dasharray="4 8" class="tl-ring-slow" opacity="0.5"/>
         <circle cx="80" cy="80" r="62" fill="none" stroke="var(--border)" stroke-width="2" stroke-dasharray="20 10 5 10" class="tl-ring-fast"/>

         <!-- Core Armor Housing -->
         <circle cx="80" cy="80" r="50" fill="url(#armor-grad)" stroke="#334155" stroke-width="4" class="tl-armor"/>
         
         <!-- Dynamic Pupil & Eye Elements Grouped for Blinking -->
         <g class="tl-eye-group">
           <!-- Inner Eye Socket (White Sclera) -->
           <path d="${lidTop} ${lidBot} Z" fill="#ffffff" stroke="#94a3b8" stroke-width="2" class="tl-sclera"/>
           
           <!-- Strictly Clip Internal Effects to the Eye Socket -->
           <g clip-path="url(#${clipId})">
             <g class="tl-iris-container">
                ${eyeCenter}
             </g>
           </g>
         </g>
      </svg>
    `;
  };

  if (!record) {
    container.style.display = "none";
    title.innerHTML = "";
    
    copyBox.style.display = "none";
    copyFallback.style.display = "block";
    copyFallback.style.textAlign = "left";
    
    const svgOpts = `xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`;
    
    const shieldSvg = `<svg ${svgOpts}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`;
    const engineSvg = `<svg ${svgOpts}><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>`;
    const privacySvg = `<svg ${svgOpts}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`;
    const osintSvg = `<svg ${svgOpts}><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`;
    const structureSvg = `<svg ${svgOpts}><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>`;

    copyFallback.innerHTML = `
      <div class="premium-shield-dashboard" style="margin-top: 0; animation: tl-fade-in 0.4s ease-out;">
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px 0 28px; background: linear-gradient(180deg, rgba(239, 246, 255, 0.6) 0%, transparent 100%); border-radius: 14px 14px 0 0; margin: -14px -14px 16px -14px; border-bottom: 1px solid var(--border-soft);">
          <div style="margin-bottom: 12px; display: flex; align-items: center; justify-content: center;">
             ${getMascotSvg("var(--brand-mid)", "safe").replace('width="140" height="140"', 'width="76" height="76"')}
          </div>
          <h2 style="font-size: 20px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; margin: 0 0 8px;">ThreatLens Active</h2>
          <span style="font-size: 11px; font-weight: 700; color: #16a34a; background: #f0fdf4; padding: 4px 12px; border-radius: 999px; display: inline-flex; align-items: center; gap: 6px; border: 1px solid #bbf7d0; text-transform: uppercase; letter-spacing: 0.05em;">
             <span style="width: 6px; height: 6px; background: #16a34a; border-radius: 50%; box-shadow: 0 0 6px #16a34a; animation: tl-status-pulse 2s infinite;"></span>
             System Protected
          </span>
        </div>
        
        <div class="security-modules" style="padding: 0 2px; border: none; box-shadow: none; background: transparent;">
           <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding: 0 6px;">
             <span style="font-size: 10px; font-weight: 800; color: #64748b; text-transform: uppercase; letter-spacing: 0.08em;">Security Modules</span>
             <span style="font-size: 10px; font-weight: 800; color: var(--brand-mid); text-transform: uppercase; letter-spacing: 0.05em;">5 Online</span>
           </div>
          <div style="display: flex; align-items: center; gap: 14px; padding: 14px 16px; background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 12px; margin-bottom: 8px;">
            <div style="color: var(--brand-mid); opacity: 0.9;">${shieldSvg}</div>
            <div style="flex: 1; text-align: left;">
              <div style="font-size: 13px; font-weight: 700; color: #0f172a;">Zero-Trust Edge</div>
              <div style="font-size: 11.5px; color: #64748b; margin-top: 2px;">Intercepting downloads pre-disk</div>
            </div>
            <div style="font-size: 10px; font-weight: 800; color: #16a34a; text-transform: uppercase; letter-spacing: 0.05em;">Active</div>
          </div>
          <div style="display: flex; align-items: center; gap: 14px; padding: 14px 16px; background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 12px; margin-bottom: 8px;">
            <div style="color: var(--brand-mid); opacity: 0.9;">${engineSvg}</div>
            <div style="flex: 1; text-align: left;">
              <div style="font-size: 13px; font-weight: 700; color: #0f172a;">Heuristic Engine</div>
              <div style="font-size: 11.5px; color: #64748b; margin-top: 2px;">Deep file &amp; hash analysis</div>
            </div>
            <div style="font-size: 10px; font-weight: 800; color: #16a34a; text-transform: uppercase; letter-spacing: 0.05em;">Active</div>
          </div>
          <div style="display: flex; align-items: center; gap: 14px; padding: 14px 16px; background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 12px; margin-bottom: 8px;">
            <div style="color: var(--brand-mid); opacity: 0.9;">${osintSvg}</div>
            <div style="flex: 1; text-align: left;">
              <div style="font-size: 13px; font-weight: 700; color: #0f172a;">OSINT Integration</div>
              <div style="font-size: 11.5px; color: #64748b; margin-top: 2px;">Global threat intelligence mapping</div>
            </div>
            <div style="font-size: 10px; font-weight: 800; color: #16a34a; text-transform: uppercase; letter-spacing: 0.05em;">Active</div>
          </div>
          <div style="display: flex; align-items: center; gap: 14px; padding: 14px 16px; background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 12px; margin-bottom: 8px;">
            <div style="color: var(--brand-mid); opacity: 0.9;">${structureSvg}</div>
            <div style="flex: 1; text-align: left;">
              <div style="font-size: 13px; font-weight: 700; color: #0f172a;">Structural Analysis</div>
              <div style="font-size: 11.5px; color: #64748b; margin-top: 2px;">PE, signature &amp; entropy parsing</div>
            </div>
            <div style="font-size: 10px; font-weight: 800; color: #16a34a; text-transform: uppercase; letter-spacing: 0.05em;">Active</div>
          </div>
          <div style="display: flex; align-items: center; gap: 14px; padding: 14px 16px; background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 12px;">
            <div style="color: var(--brand-mid); opacity: 0.9;">${privacySvg}</div>
            <div style="flex: 1; text-align: left;">
              <div style="font-size: 13px; font-weight: 700; color: #0f172a;">Privacy Sandbox</div>
              <div style="font-size: 11.5px; color: #64748b; margin-top: 2px;">100% local processing</div>
            </div>
            <div style="font-size: 10px; font-weight: 800; color: #16a34a; text-transform: uppercase; letter-spacing: 0.05em;">Active</div>
          </div>
        </div>

        <div style="text-align: center; font-size: 11.5px; color: #94a3b8; margin-top: 20px; line-height: 1.5; font-weight: 500;">
          ThreatLens is actively monitoring your browser traffic.<br>No downloads are currently pending interception.
        </div>
      </div>

    `;
    
    detailsBtn.textContent = "View Review Dashboard";
    detailsBtn.dataset.sectionJump = "review";
    bindSectionJumps(detailsBtn);
    actionGroup.style.display = "none";
    if (advancedScanContainer) advancedScanContainer.style.display = "none";
    if (fileHashDisplay) fileHashDisplay.style.display = "none";
    const dtg = document.getElementById("intel-domain-trust-group");
    if (dtg) dtg.style.display = "none";
    return;
  }

  const isBlocked = record.status === "blocked_rule" || record.status === "blocked_user";
  const urlscan = record.providerReports?.urlscan || {};
  const rep = record.reputation || {};
  const ipRep = record.providerReports?.ipReputation || {};
  const domainAudit = record.domainAudit || {};
  
  // Compute indicator live — never trust stored riskIndicator which may be stale
  const indicator = computeLiveIndicator(record);
  const isScanDone = (rep.status === "complete" || rep.status === "error");
  const hashDone = record.fileHashStatus === "complete" || record.fileHashStatus === "error";
  const isChecking = !isScanDone || (!hashDone && indicator !== "Malicious" && indicator !== "Elevated");
  const ipStatusRaw = ipRep.status || "idle";
  const ipScanStatusRaw = ipRep.scanStatus || ipStatusRaw;
  const domainAuditStatusRaw = domainAudit.status || "idle";
  const isNetworkChecking = ipStatusRaw === "loading" || ipStatusRaw === "queued" || ipScanStatusRaw === "loading" || ipScanStatusRaw === "queued" || domainAuditStatusRaw === "loading";
  const isNetworkError = (ipScanStatusRaw === "error" || ipScanStatusRaw === "unsupported") && !ipRep.owner;
  const isDomainError = domainAuditStatusRaw === "error";
  const isAuditActive = isChecking || isNetworkChecking;

  const getVal = (val, isScanActive) => val ? escapeHtml(val) : (isScanActive ? "Loading..." : "Unavailable");
  const getIp = (val, isScanActive) => val ? escapeHtml(val) : (isScanActive ? "Resolving... ↻" : "Unavailable");
  const getOwner = (val, isScanActive) => val ? escapeHtml(val) : (isScanActive ? "Scanning... ↻" : "Unavailable");

  const hostingValue = (() => {
    if (ipRep.owner) {
      return `${escapeHtml(ipRep.owner)}${ipRep.country ? ` (${escapeHtml(ipRep.country)})` : ""}`;
    }
    if (isAuditActive) {
      return "Checking... ↻";
    }
    if (ipScanStatusRaw === "not_configured" && (urlscan.pageIp || ipRep.ip)) {
      return "IP Scan Needs API Key";
    }
    if (isNetworkError) {
      return "Network Reputation Unavailable";
    }
    if (urlscan.pageIp || ipRep.ip) {
      return "Owner Not Exposed";
    }
    return "Awaiting Discovery";
  })();

  const ageStr = `
    <div style="margin-top: 8px; padding: 10px; background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 14px; font-size: 11px;">
      <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
        <span style="color: var(--text-soft); font-weight: 600;">REGISTRATION:</span>
        <span style="color: var(--text); font-weight: 700;">${record.domainMetadata?.creationDate ? new Date(record.domainMetadata.creationDate * 1000).toLocaleDateString() : (domainAuditStatusRaw === "loading" || domainAuditStatusRaw === "idle" ? 'Checking...' : isDomainError ? 'RDAP Unavailable' : 'Not Exposed by RDAP')}</span>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-soft); padding-bottom: 6px;">
        <span style="color: var(--text-soft); font-size: 11px;">REGISTRAR:</span>
        <span style="color: var(--text); font-weight: 500; font-size: 10px; max-width: 160px; text-align: right; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${record.domainMetadata?.registrar || (domainAuditStatusRaw === "loading" || domainAuditStatusRaw === "idle" ? 'Checking...' : isDomainError ? 'RDAP Unavailable' : 'Not Exposed by RDAP')}</span>
      </div>
      <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
        <span style="color: var(--text-soft); font-weight: 600;">SERVER IP:</span>
        <span style="color: var(--text); font-weight: 700; font-family: monospace;">${urlscan.pageIp || ipRep.ip || (isNetworkChecking ? 'Checking...' : isNetworkError ? 'Unavailable' : 'Audit Complete')}</span>
      </div>
      <div style="display:flex; justify-content:space-between;">
        <span style="color: var(--text-soft); font-weight: 600;">HOSTING:</span>
        <span style="color: var(--brand-mid); font-weight: 800; font-size: 12px; text-align: right; line-height: 1.3;">${hostingValue}</span>
      </div>
    </div>
  `;

  let stateClass = "mascot-state-search";
  let mascotColor = "var(--info)";
  let verdictTitle = "Awaiting Analysis";

  // Render an ordered decision trail to keep Intel concise and actionable.
  const reasonArr = buildIntelVerdictList(record);

  // Parse the reason array into modern premium cards
  let formattedReason = "";
  if (reasonArr.length > 0) {
    const SPINNER_SVG = `
      <div style="position: relative; width: 14px; height: 14px; display: flex; align-items: center; justify-content: center;">
        <div style="position: absolute; width: 6px; height: 6px; background: currentColor; border-radius: 50%; animation: tl-pulse-core 1.5s ease-in-out infinite;"></div>
        <div style="position: absolute; width: 14px; height: 14px; border: 1.5px solid currentColor; border-radius: 50%; animation: tl-pulse-ring 1.5s cubic-bezier(0.215, 0.61, 0.355, 1) infinite; opacity: 0;"></div>
      </div>
      <style>
        @keyframes tl-pulse-core { 0% { transform: scale(0.8); opacity: 0.6; } 50% { transform: scale(1); opacity: 1; } 100% { transform: scale(0.8); opacity: 0.6; } }
        @keyframes tl-pulse-ring { 0% { transform: scale(0.5); opacity: 0.8; border-width: 1.5px; } 100% { transform: scale(1.6); opacity: 0; border-width: 0px; } }
      </style>
    `;

    formattedReason = `<div class="vr-grid">
      ${reasonArr.map(r => {
        const isSpinning = r.status === "pending";
        const mod = isSpinning ? "pending" : r.status === "danger" ? "danger" : r.status === "warn" ? "warn" : "safe";
        const isOverall = false; // Overall Verdict no longer spans full width — sits next to Shannon Entropy
        return `
        <div class="vr-card vr-card--${mod}${isOverall ? ' vr-card--full' : ''}">
          <div class="vr-card-head">
            <span class="vr-dot vr-dot--${mod}">${isSpinning ? SPINNER_SVG : ''}</span>
            <span class="vr-title">${r.title}</span>
          </div>
          <p class="vr-desc">${r.desc}</p>
        </div>
      `}).join("")}
      </div>
      
      <div class="ha-intel-row">
        ${renderHaIntelligenceCard(record)}
        ${renderFuzzyMatchCard(record)}
      </div>
    `;
  } else {
    const vtStatusRaw = record.reputation?.status || "idle";
    const hashStatusRaw = record.fileHashStatus || "idle";
    const ipStatusRaw = record.providerReports?.ipReputation?.status || "idle";

    const isOsintComplete = vtStatusRaw === "complete" || vtStatusRaw === "error";
    const isNetworkComplete = ipStatusRaw === "complete" || ipStatusRaw === "error";
    const isHashComplete = hashStatusRaw === "complete" || hashStatusRaw === "error";

    // Beautiful High-Fidelity Audit Dashboard
    const nodeStyle = (done, hasError) => done
      ? `style="border: 2px solid ${hasError ? 'var(--danger)' : 'var(--good)'}; background: ${hasError ? 'var(--danger-bg)' : 'var(--good-bg)'}; color: ${hasError ? 'var(--danger)' : 'var(--good)'}; box-shadow: 0 0 0 3px ${hasError ? 'rgba(220,38,38,0.12)' : 'rgba(22,163,74,0.12)'}; animation: none;"`
      : "";
    const osintError = vtStatusRaw === "error";
    const networkError = ipStatusRaw === "error";
    const hashError = hashStatusRaw === "error";
    formattedReason = `
    <div class="audit-dashboard">
      <div class="audit-core"></div>
      <div class="audit-nodes">
        <div class="audit-node" ${nodeStyle(isOsintComplete, osintError)}>
          <div class="${isOsintComplete ? '' : 'audit-node-pulse'}"></div>
          ${isOsintComplete ? (osintError ? '✗' : '✓') : 'VirusTotal'}
        </div>
        <div class="audit-node" ${nodeStyle(isNetworkComplete, networkError)}>
          <div class="${isNetworkComplete ? '' : 'audit-node-pulse'}"></div>
          ${isNetworkComplete ? (networkError ? '✗' : '✓') : 'Network'}
        </div>
        <div class="audit-node" ${nodeStyle(isHashComplete, hashError)}>
          <div class="${isHashComplete ? '' : 'audit-node-pulse'}"></div>
          ${isHashComplete ? (hashError ? '✗' : '✓') : 'Memory'}
        </div>
      </div>
      <div class="audit-status-text">
        ThreatLens Neural Engine is performing a <br/> deep security audit of the target...
      </div>

      <div class="security-notice-alert" style="width: 100%;">
        <div class="icon">!</div>
        <div class="content">
          <strong>Security Notice</strong>
          Verify host legitimacy. Interception is active to prevent unverified script execution. Do not execute untrusted binaries.
        </div>
      </div>
    </div>`;
  }

  let verdictCopy = formattedReason;
  let titleClass = "intel-verdict checking";
  let stateName = "scanning";

  // Control action group visibility — only show after scan is complete
  if (isBlocked || indicator === "Checking") {
    actionGroup.style.display = "none";
  } else {
    actionGroup.style.display = "flex";
    
    if (allowBtn) {
      const newAllowBtn = allowBtn.cloneNode(true);
      allowBtn.replaceWith(newAllowBtn);
      newAllowBtn.disabled = busyAction !== "";
      newAllowBtn.addEventListener("click", () => {
        if (busyAction) return;
        void runDownloadAction(record.downloadId, "allow");
      });
      newAllowBtn.textContent = busyAction === "allow" ? "Releasing..." : "Allow File";
    }

    if (blockBtn) {
      const newBlockBtn = blockBtn.cloneNode(true);
      blockBtn.replaceWith(newBlockBtn);
      newBlockBtn.disabled = busyAction !== "";
      newBlockBtn.addEventListener("click", () => {
        if (busyAction) return;
        void runDownloadAction(record.downloadId, "block");
      });
      newBlockBtn.textContent = busyAction === "block" ? "Blocking..." : "Block & Remove";
    }
  }

  if (isBlocked) {
    const isManualBlock = record.status === "blocked_user";
    const blockReasonText = isManualBlock ? "Manually blocked by user during review." : (record.reason || "Blocked by a ThreatLens security rule.");

    stateClass = "mascot-state-stop";
    mascotColor = "var(--danger)";
    verdictTitle = "Download Blocked";
    
    verdictCopy = `
      <div class="intel-reason-list" style="margin-top: 8px; display: flex; flex-direction: column; gap: 6px;">
        <div style="background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 12px; padding: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.01); display: flex; align-items: flex-start; gap: 10px;">
          <div style="width: 18px; height: 18px; border-radius: 50%; background: #fef2f2; color: #ef4444; font-weight: 800; display: flex; align-items: center; justify-content: center; flex-shrink: 0; border: 1px solid currentColor;">
             <span class="tl-reason-check" style="font-size: 9px; font-style: normal;">!</span>
          </div>
          <span style="font-size: 11.5px; line-height: 1.4; color: var(--text);">${escapeHtml(blockReasonText)}</span>
        </div>
        
        <div class="security-notice-alert" style="margin: 4px 0;">
          <div class="icon">!</div>
          <div class="content">
            <strong>Security Notice</strong>
            This download was intercepted and securely erased before reaching your disk.
          </div>
        </div>

        <div class="action-row action-row-compact" style="margin-top: 6px;">
          <button class="action-button action-button-primary" data-dismiss-blocked="true">Dismiss Alert</button>
          <button class="action-button action-button-ghost" data-section-jump="rules">Edit Rules →</button>
        </div>


      </div>
    `;

    titleClass = "intel-verdict danger";
    stateName = "danger";
  } else if (indicator === "Malicious") {
    stateClass = "mascot-state-stop";
    mascotColor = "var(--danger)";
    verdictTitle = "Malicious";
    titleClass = "intel-verdict danger";
    stateName = "danger";
  } else if (isChecking) {
    stateClass = "mascot-state-search";
    mascotColor = "var(--info)";
    verdictTitle = "Scanning Target...";
    titleClass = "intel-verdict checking";
    stateName = "scanning";
    
    verdictCopy = formattedReason;
  } else if (indicator === "Suspicious" || indicator === "Elevated") {
    stateClass = "mascot-state-search";
    mascotColor = "var(--warn)";
    verdictTitle = "Suspicious";
    titleClass = "intel-verdict unknown";
    stateName = "unknown";
  } else if (indicator === "Clean" || indicator === "Reviewed") {
    stateClass = "mascot-state-safe";
    mascotColor = "var(--good)";
    verdictTitle = "Clean";
    titleClass = "intel-verdict safe";
    verdictCopy = formattedReason;
    stateName = "safe";
  } else {
    // Fallback or Unknown
    stateClass = "mascot-state-search";
    mascotColor = "var(--info)";
    verdictTitle = (indicator === "Unknown" && isScanDone) ? "Unknown" : (indicator === "Unknown" ? "Unknown Status" : "Scanning Target...");
    titleClass = "intel-verdict checking";
    stateName = "scanning";
  }

  // Cache mascot SVG — only regenerate when state or color actually changes
  const mascotKey = `${stateName}:${mascotColor}`;
  if (_lastMascotState !== mascotKey) {
    _lastMascotState = mascotKey;
    _lastMascotHtml = getMascotSvg(mascotColor, stateName);
  }

  container.className = `mascot-container ${stateClass}`;
  container.innerHTML = _lastMascotHtml;
  title.textContent = verdictTitle;
  title.className = titleClass;

  const subtitle = document.getElementById("intel-verdict-subtitle");
  if (subtitle) {
    const isThreat = indicator === "Malicious" || (record.reputation?.stats?.malicious || 0) > 0;
    const isSuspicious = indicator === "Elevated" || indicator === "Blocked";
    
    if (isThreat || isSuspicious) {
      subtitle.style.display = "block";
      subtitle.textContent = "Decision Required: We recommend canceling this download immediately. If this source is verified, proceed with absolute caution and re-verify the origin URL.";
      subtitle.style.color = isThreat ? "var(--danger)" : "var(--warn)";
    } else {
      subtitle.style.display = "none";
    }
  }
  
  copyFallback.style.display = "none";
  copyBox.style.display = "block";
  
  const ageElement = document.getElementById("intel-verdict-age");
  updateDOM(copyText, verdictCopy);
  if (ageElement) {
    updateDOM(ageElement, ageStr);
  }

  // Bind any section-jump buttons that were rendered inside the reason cards
  copyText.querySelectorAll("[data-section-jump]").forEach((btn) => {
    btn.addEventListener("click", () => {
      showSection(btn.dataset.sectionJump);
    });
  });

  copyText.querySelectorAll("[data-dismiss-blocked]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await storageManager.removePendingDownload(record.downloadId);
      await render();
    });
  });

  copyText.querySelectorAll("[data-quick-rule]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const listType = btn.dataset.quickRule;
      const domain   = btn.dataset.quickDomain;
      if (!domain) return;
      try {
        await storageManager.addRule(listType, "domains", domain);
        addedQuickRules.add(`${listType}:${domain}`);
        btn.textContent = "✓ Added";
        btn.disabled = true;
      } catch {
        addedQuickRules.add(`${listType}:${domain}`);
        btn.textContent = "Already exists";
        btn.disabled = true;
      }
    });
  });

  detailsBtn.textContent = "Details";
  detailsBtn.dataset.sectionJump = "review";
  bindSectionJumps(detailsBtn);

  // Advanced Scan / Hashing Logic — smooth progress bar, no flickering text
  if (fileHashDisplay && fileHashValue) {
    if (isBlocked) {
      fileHashDisplay.style.display = "none";
    } else {
      fileHashDisplay.style.display = "block";
    if (record.fileHashStatus === "loading" || record.fileHashStatus === "idle") {
      // Parse numeric progress (e.g. "42%" → 42, "3.1 MB" → indeterminate)
      const rawProgress = record.fileHashProgress || "";
      const pctMatch = rawProgress.match(/^(\d+)%$/);
      const pct = pctMatch ? parseInt(pctMatch[1], 10) : null;
      const barWidth = pct !== null ? `${pct}%` : "40%";
      const barAnim = pct !== null ? "none" : "tl-progress-indeterminate 1.4s ease-in-out infinite";
      const label = pct !== null ? `${pct}%` : (rawProgress || "");

      fileHashValue.innerHTML = `
        <span style="display:flex; flex-direction:column; gap:5px; width:100%;">
          <span style="display:flex; align-items:center; gap:6px; font-size:11px; color:var(--text-soft);">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="3" stroke-linecap="round" style="flex-shrink:0; animation:tl-spin 1.2s linear infinite;"><path d="M12 2A10 10 0 0 1 22 12"/></svg>
            Generating fingerprint${label ? ` · ${label}` : ""}
          </span>
          <span style="display:block; height:4px; background:var(--border); border-radius:999px; overflow:hidden; width:100%;">
            <span style="display:block; height:100%; width:${barWidth}; background:var(--info); border-radius:999px; transition:width 0.4s ease; animation:${barAnim};"></span>
          </span>
        </span>`;
    } else if (record.resumeStrategy === "pause_after_suggest") {
      fileHashValue.innerHTML = `<span style="color:var(--text-soft);font-size:11px;line-height:1.4;display:block;margin-top:2px;">This is a secure one-time token. The download is auto-released in the background to prevent expiration, but it cannot be executed without your permission.</span>`;
    } else if (record.fileHashStatus === "error" || (!record.fileHash && record.fileHashStatus !== "skipped" && record.fileHashStatus !== "skipped_blob")) {
      fileHashValue.textContent = "Extraction unavailable (file exceeded limits or access restricted).";
    } else if (record.fileHashStatus === "skipped_blob") {
      fileHashValue.textContent = "Skipped (Memory Blob)";
    } else {
      const displayHash = (typeof record.fileHash === "object" && record.fileHash !== null)
        ? (record.fileHash.hash || "N/A")
        : (record.fileHash || "N/A");
      const displayTlsh = String(record.tlshHash || "").trim();
      
      fileHashValue.textContent = displayHash;
      
      // Populate Verdict Pills
      const hashVerdictsEl = document.getElementById("intel-hash-verdicts");
      if (hashVerdictsEl) {
        let pills = "";
        const vtFileVerdict = getVirusTotalFileReport(record)?.verdict;
        if (vtFileVerdict) {
          const color = vtFileVerdict === "malicious" ? "var(--danger)" : vtFileVerdict === "suspicious" ? "var(--warn)" : vtFileVerdict === "clean" ? "var(--good)" : "var(--info)";
          pills += `<span style="font-size: 8.5px; font-weight: 800; background: ${color}20; color: ${color}; padding: 2px 6px; border-radius: 4px; border: 1px solid ${color}40; text-transform: uppercase;">VT: ${vtFileVerdict}</span>`;
        }
        
        const haVerdict = record.reputation?.hybridAnalysis?.result?.verdict;
        if (haVerdict) {
          const haColor = haVerdict === "malicious" ? "var(--danger)" : haVerdict === "suspicious" ? "var(--warn)" : haVerdict === "no specific threat" ? "var(--good)" : "var(--info)";
          pills += `<span style="font-size: 8.5px; font-weight: 800; background: ${haColor}20; color: ${haColor}; padding: 2px 6px; border-radius: 4px; border: 1px solid ${haColor}40; text-transform: uppercase;">HA: ${haVerdict}</span>`;
        }
        hashVerdictsEl.innerHTML = pills;
      }

      const tlshVerdictsEl = document.getElementById("intel-tlsh-verdicts");
      if (tlshVerdictsEl) {
        let pills = "";
        const haVerdict = record.reputation?.hybridAnalysis?.result?.verdict;
        if (haVerdict) {
          const haColor = haVerdict === "malicious" ? "var(--danger)" : haVerdict === "suspicious" ? "var(--warn)" : haVerdict === "no specific threat" ? "var(--good)" : "var(--info)";
          pills += `<span style="font-size: 8.5px; font-weight: 800; background: ${haColor}20; color: ${haColor}; padding: 2px 6px; border-radius: 4px; border: 1px solid ${haColor}40; text-transform: uppercase;">HA: ${haVerdict}</span>`;
        }
        tlshVerdictsEl.innerHTML = pills;
      }

      const copyHashBtn = document.getElementById("intel-btn-copy-hash");
      if (copyHashBtn && displayHash && displayHash !== "N/A") {
        copyHashBtn.onclick = () => {
          navigator.clipboard.writeText(displayHash);
          copyHashBtn.textContent = "Copied!";
          setTimeout(() => copyHashBtn.textContent = "Copy", 2000);
        };
      }

      const tlshContainer = document.getElementById("intel-tlsh-hash-container");
      const tlshValue = document.getElementById("intel-tlsh-hash-value");
      const copyTlshBtn = document.getElementById("intel-btn-copy-tlsh");
      
      if (displayTlsh && tlshContainer && tlshValue) {
        tlshContainer.style.display = "flex";
        tlshContainer.style.borderTop = "1px solid var(--border-soft)";
        tlshValue.textContent = displayTlsh;
        if (copyTlshBtn) {
          copyTlshBtn.onclick = () => {
            navigator.clipboard.writeText(displayTlsh);
            copyTlshBtn.textContent = "Copied!";
            setTimeout(() => copyTlshBtn.textContent = "Copy", 2000);
          };
        }
      } else if (tlshContainer) {
        tlshContainer.style.display = "none";
      }
    }
    }
  }

  if (advancedScanContainer) {
    advancedScanContainer.style.display = "none";
  }

  // Trust / Never-Trust domain buttons have been removed.
}

function bindSectionJumps(btn) {
  // Clear old listener
  const newBtn = btn.cloneNode(true);
  btn.replaceWith(newBtn);
  newBtn.addEventListener("click", () => {
    showSection(newBtn.dataset.sectionJump);
  });
}

// Build a compact scan chip button for the review tab action row
function buildScanBtn({ label, done, busy, action, isDownload }) {
  const iconSpin = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="animation:tl-spin 1s linear infinite;flex-shrink:0"><path d="M12 2A10 10 0 0 1 22 12"/></svg>`;
  const iconDone = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
  const iconIdle = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`;
  const icon = busy ? iconSpin : done ? iconDone : iconIdle;
  const text = busy ? "Running\u2026" : label;
  const attr = isDownload ? `data-download-action="${action}"` : `data-provider-action="${action}"`;
  return `<button class="rv-scan-btn" ${done || busy ? "disabled" : ""} ${attr}>${icon} ${text}</button>`;
}

function renderCurrentReview(record, blockedRecord, vtConfig) {
  // ── Blocked by rule / user ─────────────────────────────
  if (!record && blockedRecord) {
    renderBlockedReview(blockedRecord);
    return;
  }

  // ── Nothing pending ────────────────────────────────────
  if (!record) {
    reviewShell.innerHTML = `
      <div class="review-empty">
        <p class="eyebrow eyebrow-ready">Ready</p>
        <h2 class="empty-title">No download is waiting right now.</h2>
        <p class="empty-copy">When ThreatLens intercepts a new download, the decision, source details, and scan results will appear here.</p>
      </div>
    `;
    return;
  }

  const reputation = record.reputation || {};
  const urlscan = record.providerReports?.urlscan || {};
  const hasVirusTotalKey = Boolean(String(vtConfig?.apiKey || "").trim());
  const insightCta = getInsightCta(activeInsightTab, reputation, urlscan, hasVirusTotalKey);
  const downloadFacts = getDownloadFacts(record);

  const reviewTitleClass = (() => {
    const verdict = reputation.verdict;
    const status = reputation.status;
    if (status === "loading" || status === "queued") return "review-title-checking";
    if (verdict === "malicious") return "review-title-danger";
    if (verdict === "suspicious") return "review-title-warn";
    if (verdict === "clean") return "review-title-safe";
    return "";
  })();

  reviewShell.innerHTML = `
    <div class="rv-file-header">
      <div class="rv-file-icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
      </div>
      <div class="rv-file-info">
        <div class="rv-file-eyebrow">Intercepted Download</div>
        <h2 class="review-title ${reviewTitleClass}" id="review-filename" title="${escapeAttribute(record.fileName)}">${escapeHtml(record.fileName)}</h2>
        <span class="filename-toggle" id="filename-toggle">Show full ▾</span>
      </div>
      <span class="risk-pill ${getToneClass(record)}">${escapeHtml(getRiskLabel(record))}</span>
    </div>

    <div class="rv-facts">
      <div class="rv-fact">
        <span class="rv-fact-icon">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        </span>
        <div class="rv-fact-body">
          <span class="rv-fact-label">Source</span>
          <span class="rv-fact-value" title="${escapeAttribute(record.sourceDisplay)}">${escapeHtml(truncateSourceDisplay(record.sourceDisplay))}</span>
          <span class="rv-fact-sub copy-on-click" data-copy-url="${escapeAttribute(record.sourceUrl || '')}" title="Click to copy">${escapeHtml(record.sourceUrl ? truncateUrlForDisplay(record.sourceUrl) : 'Unavailable')}</span>
        </div>
      </div>
      <div class="rv-fact-sep"></div>
      <div class="rv-fact">
        <span class="rv-fact-icon">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="8 17 12 21 16 17"/><line x1="12" y1="3" x2="12" y2="21"/></svg>
        </span>
        <div class="rv-fact-body">
          <span class="rv-fact-label">File</span>
          <span class="rv-fact-value" title="${escapeAttribute(downloadFacts.primary)}">${escapeHtml(downloadFacts.primary)}</span>
          <span class="rv-fact-sub">${escapeHtml(downloadFacts.secondary)}</span>
        </div>
      </div>
    </div>

    <nav class="scan-tabs" aria-label="Scan result tabs">
      <button class="scan-tab ${activeInsightTab === "summary" ? "is-active" : ""}" type="button" data-insight-tab="summary">Summary</button>
      <button class="scan-tab ${activeInsightTab === "file-info" ? "is-active" : ""}" type="button" data-insight-tab="file-info">File Info</button>
      <button class="scan-tab ${activeInsightTab === "pe-structure" ? "is-active" : ""}" type="button" data-insight-tab="pe-structure">PE Struct</button>
      <button class="scan-tab ${activeInsightTab === "virustotal" ? "is-active" : ""}" type="button" data-insight-tab="virustotal">VirusTotal</button>
      <button class="scan-tab ${activeInsightTab === "urlscan" ? "is-active" : ""}" type="button" data-insight-tab="urlscan">urlscan.io</button>
      <button class="scan-tab ${activeInsightTab === "domain-info" ? "is-active" : ""}" type="button" data-insight-tab="domain-info">Domain</button>
    </nav>

    <section class="insight-panel">
      ${renderInsightPanel(record, hasVirusTotalKey)}
    </section>

    <div class="rv-actions">
      <div class="rv-scan-row">
        ${buildScanBtn({ label: 'VirusTotal', done: record.reputation?.status === 'complete', busy: isOsintBusy(record), action: 'check-reputation', isDownload: true })}
        ${buildScanBtn({ label: 'urlscan.io', done: record.providerReports?.urlscan?.status === 'complete', busy: isUrlscanBusy(record), action: 'urlscan', isProvider: true })}
        <div style="display: flex; gap: 4px;">
          <select id="sandbox-env-select" style="padding: 0 8px; border-radius: 6px; background: var(--card-bg); border: 1px solid var(--border); color: var(--text-soft); font-size: 11px; font-weight: 500; cursor: pointer; outline: none; transition: all 0.2s;" ${getDisabledState()}>
            <option value="160">Windows 10</option>
            <option value="120">Windows 7 (64-bit)</option>
            <option value="430">macOS</option>
            <option value="330">Linux (Ubuntu)</option>
            <option value="200">Android</option>
          </select>
          ${buildScanBtn({ label: 'Sandbox', done: record.reputation?.hybridAnalysis?.status === 'complete', busy: isSandboxBusy(record), action: 'sandbox-scan', isDownload: true })}
        </div>
        ${insightCta ? (insightCta.url ? `<button class="rv-scan-btn" data-open-report="${escapeAttribute(insightCta.url)}" ${getDisabledState()}><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>${escapeHtml(insightCta.label)}</button>` : `<button class="rv-scan-btn" data-section-jump="${escapeAttribute(insightCta.section)}" ${getDisabledState()}>${escapeHtml(insightCta.label)}</button>`) : ""}
      </div>
      <div class="rv-decision-row">
        <button class="rv-btn-allow" data-download-action="allow" ${getDisabledState()}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          ${busyAction === "allow" ? "Releasing…" : "Allow File"}
        </button>
        <button class="rv-btn-block" data-download-action="block" ${getDisabledState()}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          ${busyAction === "block" ? "Blocking…" : "Block & Remove"}
        </button>
      </div>
    </div>
  `;

  // Filename "Show full / Show less" toggle
  const filenameEl = reviewShell.querySelector("#review-filename");
  const toggleEl   = reviewShell.querySelector("#filename-toggle");
  if (filenameEl && toggleEl) {
    // Hide toggle if the text isn't actually clamped
    if (filenameEl.scrollHeight <= filenameEl.clientHeight + 2) {
      toggleEl.style.display = "none";
    }
    toggleEl.addEventListener("click", () => {
      const expanded = filenameEl.classList.toggle("is-expanded");
      toggleEl.textContent = expanded ? "Show less ▴" : "Show full ▾";
    });
  }

  reviewShell.querySelectorAll("[data-download-action]").forEach((button) => {
    button.addEventListener("click", () => {
      void runDownloadAction(record.downloadId, button.dataset.downloadAction);
    });
  });


  reviewShell.querySelectorAll("[data-provider-action]").forEach((button) => {
    button.addEventListener("click", () => {
      void runProviderAction(record.downloadId, button.dataset.providerAction);
    });
  });

  reviewShell.querySelectorAll("[data-open-report]").forEach((button) => {
    button.addEventListener("click", async () => {
      const targetUrl = button.dataset.openReport;
      if (!targetUrl) {
        return;
      }

      await chrome.tabs.create({
        url: targetUrl,
        active: true
      });
    });
  });

  reviewShell.querySelectorAll("[data-section-jump]").forEach((button) => {
    button.addEventListener("click", () => {
      showSection(button.dataset.sectionJump);
    });
  });

  reviewShell.querySelectorAll("[data-insight-tab]").forEach((button) => {
    button.addEventListener("click", (e) => {
      e.stopPropagation();
      activeInsightTab = button.dataset.insightTab;
      // Localized sub-tab render: only replace the insight panel + provider buttons,
      // NOT the entire review shell. This avoids destroying/re-creating ~50 DOM nodes.
      const insightMount = reviewShell.querySelector(".insight-panel");
      if (insightMount) {
        const hasVirusTotalKey = Boolean(String(vtConfig?.apiKey || "").trim());
        insightMount.innerHTML = renderInsightPanel(record, hasVirusTotalKey);
      }
      // Update active tab styling
      reviewShell.querySelectorAll(".scan-tab").forEach((tab) => {
        tab.classList.toggle("is-active", tab.dataset.insightTab === activeInsightTab);
      });
    });
  });

  // Quick domain rule buttons
  reviewShell.querySelectorAll("[data-quick-rule]").forEach((button) => {
    button.addEventListener("click", async () => {
      const listType = button.dataset.quickRule;
      const domain   = button.dataset.quickDomain;
      if (!domain) return;
      try {
        await storageManager.addRule(listType, "domains", domain);
        addedQuickRules.add(`${listType}:${domain}`);
        button.textContent = "✓ Added";
        button.disabled = true;
      } catch {
        addedQuickRules.add(`${listType}:${domain}`);
        button.textContent = "Already exists";
        button.disabled = true;
      }
    });
  });

  // Click-to-copy URL
  reviewShell.querySelectorAll("[data-copy-url]").forEach((el) => {
    el.addEventListener("click", () => {
      copyToClipboard(el.dataset.copyUrl, el);
    });
  });
}

/**
 * Renders the blocked-download info panel.
 * Shows what was blocked, why, and a dismiss button.
 */
function renderBlockedReview(record) {
  const byRule   = record.status === "blocked_rule";
  const matchVal = record.ruleMatch?.value || "";
  const matchType = record.ruleMatch?.typeLabel || "rule";
  const downloadFacts = getDownloadFacts(record);

  reviewShell.innerHTML = `
    <div class="review-top">
      <div>
        <p class="eyebrow">Download Blocked</p>
        <h2 class="review-title review-title-danger">${escapeHtml(record.fileName)}</h2>
        <p class="review-copy">${escapeHtml(summarizeReasonText(record.reason) || "This download was blocked by ThreatLens.")}</p>
      </div>
      <span class="risk-pill tone-critical">Blocked</span>
    </div>

    <div class="meta-grid">
      <section class="meta-item">
        <span class="label">Source</span>
        <strong>${escapeHtml(record.sourceDisplay || record.sourceHostname || "Unknown")}</strong>
        <p class="meta-copy">${escapeHtml(record.sourceUrl || "Unavailable")}</p>
      </section>
      <section class="meta-item">
        <span class="label">Download</span>
        <strong>${escapeHtml(downloadFacts.primary)}</strong>
        <p class="meta-copy">${escapeHtml(downloadFacts.secondary)}</p>
      </section>
    </div>

    <div class="insight-panel">
      <div class="provider-head">
        <div>
          <span class="label">Block Reason</span>
          <strong class="provider-title provider-title-alert">
            ${byRule ? `Matched your ${escapeHtml(matchType)} blocklist rule` : "Blocked by your manual decision"}
          </strong>
        </div>
        <span class="provider-state state-error">Blocked</span>
      </div>
      <div class="detail-list">
        ${matchVal ? `
          <div class="detail-row">
            <span>Matched rule</span>
            <strong class="value-danger">${escapeHtml(matchVal)}</strong>
          </div>
        ` : ""}
        <div class="detail-row">
          <span>Decision</span>
          <strong class="value-danger">${byRule ? "Auto-blocked" : "User-blocked"}</strong>
        </div>

        <div class="detail-row">
          <span>File removed</span>
          <strong class="value-safe">Yes — no data was written to disk</strong>
        </div>
      </div>
    </div>

    <div class="action-row action-row-compact">
      <button class="action-button action-button-primary" id="blocked-dismiss-btn">Dismiss</button>
      <button class="action-button action-button-ghost" id="blocked-rules-btn">Edit Rules</button>
    </div>


  `;

  reviewShell.querySelector("#blocked-dismiss-btn")?.addEventListener("click", async () => {
    await storageManager.removePendingDownload(record.downloadId);
    await render();
  });

  reviewShell.querySelector("#blocked-rules-btn")?.addEventListener("click", () => {
    showSection("rules");
  });

  reviewShell.querySelector("#blocked-trust-btn")?.addEventListener("click", async (e) => {
    const domain = e.currentTarget.dataset.quickDomain;
    if (!domain) return;
    try {
      await storageManager.addRule("allowlist", "domains", domain);
      e.currentTarget.textContent = "✓ Added";
      e.currentTarget.disabled = true;
    } catch {
      e.currentTarget.textContent = "Already exists";
      e.currentTarget.disabled = true;
    }
  });
}

function renderInsightPanel(record, hasVirusTotalKey) {
  switch (activeInsightTab) {
    case "file-info":
      return renderFileInfoPanel(record);
    case "pe-structure":
      return renderPeStructurePanel(record);
    case "virustotal":
      return renderVirusTotalPanel(record, hasVirusTotalKey);
    case "urlscan":
      return renderUrlscanPanel(record.providerReports?.urlscan || {});
    case "domain-info":
      return renderDomainInfoPanel(record);
    default:
      return renderSummaryPanel(record);
  }
}

function renderFileInfoPanel(record) {
  const hashValue = (typeof record.fileHash === "object" && record.fileHash !== null) 
    ? (record.fileHash.hash || "") 
    : String(record.fileHash || "").trim();
  const tlshHash = String(record.tlshHash || "").trim();

  const magicMime = record.magicMime || "Unknown";

  return `
    <div class="provider-head">
      <div>
        <span class="label">Analysis Type</span>
        <strong class="provider-title">Static File Intelligence</strong>
      </div>
      <span class="provider-state ${hashValue ? 'state-ready' : 'state-waiting'}">${hashValue ? 'Complete' : 'Pending'}</span>
    </div>
    
    <div class="detail-list" style="margin-top: 16px;">
      <div class="detail-row">
        <span>SHA-256 Checksum</span>
        <strong style="font-family: monospace; font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(hashValue || 'N/A')}">
          ${escapeHtml(hashValue || "N/A")}
        </strong>
      </div>
      <div class="detail-row">
        <span>Fuzzy Hash (TLSH-style)</span>
        <strong style="font-family: monospace; font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(tlshHash || 'N/A')}">
          ${escapeHtml(tlshHash || "N/A")}
        </strong>
      </div>
      <div class="detail-row">
        <span>Magic Bytes</span>
        <strong>${escapeHtml(magicMime)}</strong>
      </div>
    </div>
  `;
}

function renderPeStructurePanel(record) {
  const peSections = Array.isArray(record.peSections) ? record.peSections : [];
  const entropy = record.fileEntropy ? parseFloat(record.fileEntropy) : null;
  const vtFileReport = getVirusTotalFileReport(record) || {};
  const sigInfo = vtFileReport.details?.signatureInfo;
  const peAnomalies = Array.isArray(record.peAnomalies) ? record.peAnomalies.filter(Boolean) : [];

  let sigDetails = "";
  if (sigInfo) {
    const isSigned = String(sigInfo.verified || "").toLowerCase().includes("signed");
    const signers = sigInfo.signers ? (Array.isArray(sigInfo.signers) ? sigInfo.signers.join(", ") : String(sigInfo.signers)) : "";
    
    if (isSigned) {
      sigDetails = `
        <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
          <div style="background: #dcfce7; color: #166534; border-radius: 50%; width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; font-size: 14px; flex-shrink: 0;">✓</div>
          <div style="min-width: 0; overflow: hidden;">
            <strong style="display: block; font-size: 12px; color: #166534;">Verified Signature</strong>
            <span style="font-size: 11px; color: #14532d; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeAttribute(signers)}">${escapeHtml(signers)}</span>
          </div>
        </div>`;
    } else {
      sigDetails = `
        <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
          <div style="background: #fee2e2; color: #991b1b; border-radius: 50%; width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; font-size: 14px; flex-shrink: 0;">⚠</div>
          <div style="min-width: 0;">
            <strong style="display: block; font-size: 12px; color: #991b1b;">Unsigned Binary</strong>
            <span style="font-size: 11px; color: #7f1d1d; display: block;">No publisher verified</span>
          </div>
        </div>`;
    }
  } else {
    sigDetails = '<strong style="font-size: 12px; color: #64748b;">Not Available / Unchecked</strong>';
  }

  let sectionsHtml = "";
  if (peSections.length > 0) {
    sectionsHtml = peSections.map(s => {
      const sizeBytes = s.rawSize || 0;
      const sizeStr = formatBytes(sizeBytes);
      const name = escapeHtml(s.name || "unnamed");
      const lowerName = name.toLowerCase();
      
      let tooltip = "";
      if (lowerName.includes(".text") || lowerName.includes("code")) tooltip = "Executable Code";
      else if (lowerName.includes(".rdata")) tooltip = "Read-Only Data";
      else if (lowerName.includes(".data")) tooltip = "Global Variables";
      else if (lowerName.includes(".rsrc")) tooltip = "App Resources";
      else if (lowerName.includes(".reloc")) tooltip = "Relocation Info";
      
      const tooltipHtml = tooltip ? `<span style="font-size: 10px; color: #94a3b8; font-weight: 400; margin-left: 8px;">${tooltip}</span>` : "";
      const isSusResource = lowerName.includes(".rsrc") && sizeBytes > 5000000; // > 5MB rsrc
      
      return `
        <div style="display: flex; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid #f1f5f9; min-width: 0;">
          <div style="display: flex; align-items: baseline; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            <span style="font-family: monospace; font-size: 12px; font-weight: 600; color: ${isSusResource ? '#b45309' : '#334155'};">${name}</span>
            ${tooltipHtml}
          </div>
          <strong style="font-size: 12px; color: ${isSusResource ? '#b45309' : '#0f172a'}; flex-shrink: 0; margin-left: 10px;">${sizeStr}</strong>
        </div>`;
    }).join("");
  } else {
    sectionsHtml = '<strong style="font-size: 12px; color: #64748b;">None parsed</strong>';
  }

  let anomaliesHtml = "";
  if (peAnomalies.length > 0) {
    anomaliesHtml = peAnomalies.map(a => `<div style="display: flex; margin-bottom: 6px; min-width: 0;"><strong style="font-size: 12px; color: #ef4444; word-break: break-word;">⚠ ${escapeHtml(a)}</strong></div>`).join("");
  }

  const entropyVal = entropy !== null ? entropy : 0;
  const entropyPct = Math.min((entropyVal / 8) * 100, 100);
  const isHighEntropy = entropyVal > 7.2;
  const entropyColor = isHighEntropy ? 'var(--danger)' : 'var(--info)';

  return `
    <div class="provider-head">
      <div>
        <span class="label">Deep Analysis</span>
        <strong class="provider-title">Executable Structure (PE)</strong>
      </div>
      <span class="provider-state ${peSections.length > 0 ? 'state-ready' : 'state-waiting'}">${peSections.length > 0 ? 'Parsed' : 'Pending'}</span>
    </div>
    
    <div style="margin-top: 16px; display: flex; flex-direction: column; gap: 16px; min-width: 0; overflow: hidden;">
      
      <div style="display: grid; grid-template-columns: 1fr; gap: 12px;">
        <div>
          <div style="font-size: 10px; font-weight: 700; color: #1e293b; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em;">Shannon Entropy</div>
          <div style="padding: 14px; background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.03); height: calc(100% - 22px); box-sizing: border-box; display: flex; flex-direction: column; justify-content: center;">
            <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 8px;">
              <strong style="font-size: 18px; color: ${entropyColor}; line-height: 1;">${entropyVal !== null ? entropyVal.toFixed(2) : 'N/A'}</strong>
              <span style="font-size: 11px; font-weight: 600; color: ${isHighEntropy ? '#991b1b' : '#334155'};">${isHighEntropy ? 'Packed/Encrypted' : 'Normal Code'}</span>
            </div>
            <div style="height: 6px; background: #f1f5f9; border-radius: 3px; overflow: hidden; width: 100%;">
              <div style="height: 100%; width: ${entropyPct}%; background: ${entropyColor}; border-radius: 3px; transition: width 0.5s ease;"></div>
            </div>
          </div>
        </div>
      </div>

      <div>
        <div style="font-size: 10px; font-weight: 700; color: #1e293b; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em;">Digital Signature</div>
        <div style="padding: 14px; background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
          ${sigDetails}
        </div>
      </div>

      <div>
        <div style="font-size: 10px; font-weight: 700; color: #1e293b; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em;">Sections Breakdown</div>
        <div style="padding: 10px 16px; background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
          ${sectionsHtml}
        </div>
      </div>
      
      ${peAnomalies.length > 0 ? `
      <div>
        <div style="font-size: 10px; font-weight: 700; color: #ef4444; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em;">Structural Anomalies</div>
        <div style="padding: 12px 16px; background: #fef2f2; border: 1px solid #fca5a5; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
          ${anomaliesHtml}
        </div>
      </div>` : ""}

    </div>
  `;
}

function renderSummaryPanel(record) {
  const stateLabel = getSummaryState(record);
  const stateClass = stateLabel === "Scanning" ? "state-scanning"
    : stateLabel === "Waiting" ? "state-waiting"
    : "state-ready";

  const reasonText = (() => {
    if (!record.reason) return "Waiting for analytical engine…";
    if (Array.isArray(record.reason)) {
      const highFidelity = record.reason.filter(r =>
        !r.includes("↻") && !r.includes("Interception") && !r.includes("Initializing") && !r.includes("Evaluating")
      );
      if (highFidelity.length > 0) return escapeHtml(stripReasonMarkup(highFidelity[highFidelity.length - 1]));
      return escapeHtml(stripReasonMarkup(record.reason[record.reason.length - 1] || "Security audit in progress…"));
    }
    return escapeHtml(stripReasonMarkup(record.reason));
  })();

  return `
    <div class="intel-provider-card" style="gap:8px;">
      <div class="intel-provider-header">
        <div class="intel-provider-icon" style="background:#fff0f0;color:var(--danger);border-color:#fecaca;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </div>
        <div>
          <div class="intel-provider-label">Decision Summary</div>
          <div class="intel-provider-name">Download Intercepted</div>
        </div>
        <span class="provider-state ${stateClass}" style="margin-left:auto;flex-shrink:0;">${escapeHtml(stateLabel)}</span>
      </div>
      <div class="sum-rows">
        <div class="sum-row">
          <span class="sum-row-label">Reasoning</span>
          <span class="sum-row-value">${reasonText}</span>
        </div>
        <div class="sum-row">
          <span class="sum-row-label">Risk Profile</span>
          <span class="sum-row-value">${escapeHtml(getScanSummary(record))}</span>
        </div>
        <div class="sum-row" style="border-bottom:none;">
          <span class="sum-row-label">Status</span>
          <span class="sum-row-value value-safe">Quarantined — not on disk</span>
        </div>
      </div>
    </div>
  `;
}

function renderDomainInfoPanel(record) {
  const urlscan = record.providerReports?.urlscan || {};
  const ipRep = record.providerReports?.ipReputation || {};
  const domainAudit = record.domainAudit || {};

  const domainMetadata = record.domainMetadata || {};
  const effectiveCreationDate = domainMetadata.creationDate || null;
  const effectiveRegistrar = domainMetadata.registrar || "";
  const ipScanStatus = ipRep.scanStatus || ipRep.status || "idle";
  const domainAuditStatus = domainAudit.status || "idle";
  const isScanning = domainAuditStatus === "loading" || ipScanStatus === "loading" || ipScanStatus === "queued";
  const isLimited = domainAuditStatus === "error" || (ipRep.status === "error" && !ipRep.owner);

  const formatDomainDate = (unixTs) => {
    if (!unixTs) return "";
    try {
      return new Date(unixTs * 1000).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
    } catch {
      return "";
    }
  };

  const creationDateStr = formatDomainDate(effectiveCreationDate)
    || (isScanning ? "Fetching from RDAP..." : domainAuditStatus === "error" ? "RDAP Unavailable" : domainAuditStatus === "complete" ? "Not Exposed by RDAP" : "-");
  const updatedDateStr = formatDomainDate(domainMetadata.updatedDate)
    || (isScanning ? "Fetching from RDAP..." : domainAuditStatus === "complete" ? "Not Exposed by RDAP" : "-");
  const expiresDateStr = formatDomainDate(domainMetadata.expirationDate)
    || (isScanning ? "Fetching from RDAP..." : domainAuditStatus === "complete" ? "Not Exposed by RDAP" : "-");
  const registrarStr = effectiveRegistrar || (isScanning ? "Fetching from RDAP..." : domainAuditStatus === "error" ? "RDAP Unavailable" : "Not Exposed by RDAP");
  const registrantOwnerStr = domainMetadata.registrantName || (isScanning ? "Fetching from RDAP..." : domainAuditStatus === "complete" ? "Not Exposed by RDAP" : "-");
  const registrantCountryStr = domainMetadata.registrantCountry || (isScanning ? "Fetching from RDAP..." : domainAuditStatus === "complete" ? "Not Exposed by RDAP" : "-");
  const nameserversStr = Array.isArray(domainMetadata.nameservers) && domainMetadata.nameservers.length
    ? domainMetadata.nameservers.join(", ")
    : (isScanning ? "Fetching from RDAP..." : domainAuditStatus === "complete" ? "Not Exposed by RDAP" : "-");
  const rdapDomainStr = domainMetadata.queriedDomain || (isScanning ? "Resolving..." : domainAuditStatus === "complete" ? "Not Returned" : "-");

  const ipAddressStr = urlscan.pageIp || ipRep.ip || (isScanning ? "Resolving..." : isLimited ? "Unavailable" : "Unknown");
  
  const countryCode = String(ipRep.country || "").trim().toUpperCase();
  const flagEmoji = /^[A-Z]{2}$/.test(countryCode)
    ? countryCode.replace(/./g, (char) => String.fromCodePoint(char.charCodeAt(0) + 127397))
    : "";
  const ownerStr = ipRep.owner
    ? `${escapeHtml(ipRep.owner)} ${flagEmoji}`
    : (isScanning ? "Checking Network Owner..." : isLimited ? "Network Reputation Unavailable" : (ipAddressStr !== "Unknown" ? "Owner Not Exposed" : "-"));
  const asnStr = ipRep.asn ? `AS${escapeHtml(ipRep.asn)}` : (isScanning ? "Resolving..." : isLimited ? "Unavailable" : "Not Exposed");
  const serverCountryStr = ipRep.country ? `${escapeHtml(ipRep.country)} ${flagEmoji}` : (isScanning ? "Resolving..." : isLimited ? "Unavailable" : "Not Exposed");
  
  const ipMalicious = ipRep.stats?.malicious || 0;
  const ipSuspicious = ipRep.stats?.suspicious || 0;
  let ipThreatUI = "";
  if (ipScanStatus === "complete") {
    if (ipMalicious > 0) {
      ipThreatUI = `<span style="color:var(--danger); font-weight: 600;">${ipMalicious} Vendors Flagged Malicious</span>`;
    } else if (ipSuspicious > 0) {
      ipThreatUI = `<span style="color:var(--warn); font-weight: 600;">${ipSuspicious} Vendors Flagged Suspicious</span>`;
    } else {
      ipThreatUI = `<span style="color:var(--good); font-weight: 600;">Safe (0 Vendor Flags)</span>`;
    }
  } else if (ipScanStatus === "not_configured") {
    ipThreatUI = `<span style="color:var(--warn); font-weight: 600;">API Key Required for IP Scan</span>`;
  } else if (ipScanStatus === "unsupported") {
    ipThreatUI = `<span style="color:var(--warn); font-weight: 600;">Provider Does Not Support This IP</span>`;
  } else if (ipScanStatus === "error") {
    ipThreatUI = `<span style="color:var(--danger); font-weight: 600;">Network Reputation Unavailable</span>`;
  } else if (ipScanStatus === "loading" || ipScanStatus === "queued") {
    ipThreatUI = `<span style="color:var(--info);">Scanning IP...</span>`;
  } else if (ipAddressStr !== "Unknown" && ipAddressStr !== "Unavailable") {
    ipThreatUI = `<span style="color:var(--warn); font-weight: 600;">Scan Not Started</span>`;
  } else {
    ipThreatUI = `-`;
  }

  const stateLabel = isLimited ? "Limited" : (isScanning ? "Scouting" : "Analyzed");
  const stateClass = isLimited ? "state-error" : (isScanning ? "state-scanning" : "state-ready");

  return `
    <div class="provider-head">
      <div>
        <span class="label">REPUTATION DOMAIN INFO</span>
        <strong class="provider-title">RDAP Registry Metadata</strong>
      </div>
      <span class="provider-state ${stateClass}">${stateLabel}</span>
    </div>
    <div class="detail-list" style="gap: 12px;">
      <div class="detail-row">
        <span>Registered On</span>
        <strong style="color: ${domainMetadata.isNewDomain ? 'var(--danger)' : 'var(--text)'};">${creationDateStr}</strong>
      </div>
      <div class="detail-row">
        <span>Updated On</span>
        <strong>${escapeHtml(updatedDateStr)}</strong>
      </div>
      <div class="detail-row">
        <span>Expires On</span>
        <strong>${escapeHtml(expiresDateStr)}</strong>
      </div>
      <div class="detail-row">
        <span>Registrar</span>
        <strong>${escapeHtml(registrarStr)}</strong>
      </div>
      <div class="detail-row">
        <span>Registrant</span>
        <strong>${escapeHtml(registrantOwnerStr)}</strong>
      </div>
      <div class="detail-row">
        <span>Registrant Country</span>
        <strong>${escapeHtml(registrantCountryStr)}</strong>
      </div>
      <div class="detail-row">
        <span>Name Servers</span>
        <strong>${escapeHtml(nameserversStr)}</strong>
      </div>
      <div class="detail-row">
        <span>RDAP Domain</span>
        <strong>${escapeHtml(rdapDomainStr)}</strong>
      </div>
      <div class="detail-row" style="border-top: 1px solid var(--border); padding-top: 12px;">
        <span>Server IP Address</span>
        <strong>${escapeHtml(ipAddressStr)}</strong>
      </div>
      <div class="detail-row">
        <span>Network ASN Owner</span>
        <strong>${ownerStr}</strong>
      </div>
      <div class="detail-row">
        <span>ASN Number</span>
        <strong>${asnStr}</strong>
      </div>
      <div class="detail-row">
        <span>Server Country</span>
        <strong>${serverCountryStr}</strong>
      </div>
      <div class="detail-row">
        <span>VirusTotal IP Scan</span>
        <strong>${ipThreatUI}</strong>
      </div>
    </div>
  `;
}

function renderVirusTotalPanel(record, hasVirusTotalKey) {
  const reputation = record.reputation || {};
  const stateLabel = getVirusTotalState(reputation);
  const stateClass = stateLabel === "Ready" ? "state-ready"
    : stateLabel === "Searching" || stateLabel === "Queued" ? "state-scanning"
    : stateLabel === "Retry" || stateLabel === "Error" ? "state-error"
    : "state-waiting";

  return `
    <div class="provider-head">
      <div>
        <span class="label">Provider</span>
        <strong class="provider-title provider-title-vt">VirusTotal</strong>
      </div>
      <span class="provider-state ${stateClass}">${escapeHtml(stateLabel)}</span>
    </div>
    <p class="provider-summary">${escapeHtml(reputation.summary || "No VirusTotal result is available yet.")}</p>
    ${renderEngineStats(reputation.stats || {})}
    ${renderVirusTotalDetails(record, reputation.details || null)}
    <p class="provider-note">${escapeHtml(getVirusTotalHint(reputation, hasVirusTotalKey))}</p>
  `;
}

function renderVirusTotalDetails(record, details) {
  if (!details) return "";

  const rows = [];
  
  if (details.categories && Object.keys(details.categories).length > 0) {
    const cats = Object.entries(details.categories).map(([vendor, cat]) => {
      return `<div class="detail-chip"><strong>${escapeHtml(vendor)}:</strong>&nbsp;${escapeHtml(cat)}</div>`;
    }).slice(0, 4);
    
    rows.push(`
      <div class="vt-section">
        <span class="label">Categories</span>
        <div class="detail-chip-row">${cats.join("")}</div>
      </div>
    `);
  }

  const formatUnix = (timestamp) => {
    if (!timestamp) return "";
    return formatTimestamp(new Date(timestamp * 1000).toISOString());
  };

  const dates = [
     details.firstSubmissionDate ? `<span>First Submission: <strong>${escapeHtml(formatUnix(details.firstSubmissionDate))}</strong></span>` : "",
     details.lastSubmissionDate ? `<span>Last Submission: <strong>${escapeHtml(formatUnix(details.lastSubmissionDate))}</strong></span>` : "",
     details.lastAnalysisDate ? `<span>Last Analysis: <strong>${escapeHtml(formatUnix(details.lastAnalysisDate))}</strong></span>` : ""
  ].filter(Boolean);

  if (dates.length > 0) {
    rows.push(`
      <div class="vt-section vt-history">
        <span class="label">Analysis History</span>
        <div class="vt-history-list">
          ${dates.join("")}
        </div>
      </div>
    `);
  }

  // Domain Registry Block for Review Tab
  rows.push(`
    <div class="vt-section vt-domain" style="margin-top: 12px; padding: 12px; background: rgba(0,0,0,0.03); border-radius: 6px;">
      <span class="label" style="display:block; margin-bottom: 8px;">Domain Registry Information</span>
      <div class="vt-history-list">
        <span>Creation Date: <strong style="color: ${(record?.domainMetadata?.isNewDomain || details.isNewDomain) ? 'var(--danger)' : 'inherit'};">${(record?.domainMetadata?.creationDate || details.domainCreationDate) ? escapeHtml(formatUnix(record?.domainMetadata?.creationDate || details.domainCreationDate)) : "Unknown or Data Unavailable"}</strong></span>
        <span>Registrar: <strong>${(record?.domainMetadata?.registrar || details.domainRegistrar) ? escapeHtml(record?.domainMetadata?.registrar || details.domainRegistrar) : "Unknown"}</strong></span>
        ${details.isNewDomain ? '<span style="color:var(--danger); font-size: 11px; margin-top:4px; display:block;">⚠ This domain was registered very recently.</span>' : ''}
      </div>
    </div>
  `);

  return rows.length ? `<div class="vt-details-panel">${rows.join("")}</div>` : "";
}

function renderUrlscanPanel(urlscan) {
  const stateLabel = getUrlscanState(urlscan);
  const stateClass = stateLabel === "Ready" || stateLabel === "No Match" ? "state-ready"
    : stateLabel === "Scanning" ? "state-scanning"
    : stateLabel === "Retry" ? "state-error"
    : "state-waiting";

  return `
    <div class="provider-head">
      <div>
        <span class="label">Provider</span>
        <strong class="provider-title provider-title-urlscan">urlscan.io</strong>
      </div>
      <span class="provider-state ${stateClass}">${escapeHtml(stateLabel)}</span>
    </div>
    <div style="margin-top: 12px; margin-bottom: 16px;">
      <p style="font-size: 13px; font-weight: 500; line-height: 1.5; color: var(--text);">${escapeHtml(urlscan.summary || "No urlscan.io result is available yet.")}</p>
    </div>
    ${renderUrlscanDetails(urlscan)}
    <p class="provider-note" style="margin-top: 14px;">${escapeHtml(getUrlscanHint(urlscan))}</p>
  `;
}

function renderPendingList(pending, currentDownloadId) {
  pendingCountCopy.textContent = pending.length ? `${pending.length} waiting` : "No downloads waiting";
  btnClearQueue.style.display = pending.length > 0 ? "flex" : "none";

  if (!pending.length) {
    if (updateDOM(pendingList, `
      <div class="queue-empty">
        <p class="empty-title">Queue is empty.</p>
        <p class="empty-copy">ThreatLens will list new intercepted downloads here as soon as they need a decision.</p>
      </div>
    `)) {
      // no listeners to bind
    }
    return;
  }

  const htmlString = pending
    .map((record) => `
      <button type="button" class="queue-item ${record.downloadId === currentDownloadId ? "is-active" : ""}" data-select-download="${record.downloadId}">
        <div class="queue-head">
          <div>
            <span class="label">${escapeHtml(getRiskLabel(record))}</span>
            <strong>${escapeHtml(record.fileName)}</strong>
          </div>
          <span class="panel-note">${escapeHtml(formatTimestamp(record.updatedAt))}</span>
        </div>
        <p class="queue-copy">${escapeHtml(record.sourceDisplay)}</p>
      </button>
    `)
    .join("");

  if (updateDOM(pendingList, htmlString)) {
    pendingList.querySelectorAll("[data-select-download]").forEach((button) => {
      button.addEventListener("click", () => {
        selectedDownloadId = Number(button.dataset.selectDownload);
        void render();
      });
    });
  }
}

function renderRuleGroups(listType, collection) {
  const mount = document.querySelector(`[data-rule-groups="${listType}"]`);
  const ruleTypes = listType === "blocklist"
    ? ["domains", "urls", "fileTypes", "hashes"]
    : ["domains", "urls", "fileTypes"];

  const htmlString = ruleTypes
    .map((ruleType) => {
      const entries = collection[ruleType] || [];
      const isHash = ruleType === "hashes";
      return `
        <section class="rule-group">
          <h3>${humanizeRuleType(ruleType)}</h3>
          ${
            entries.length
              ? `<div class="chip-list">
                  ${entries
                    .map((entry) => {
                        const displayLabel = isHash
                          ? escapeHtml(`${entry.slice(0, 8)}…${entry.slice(-6)}`)
                          : ruleType === "urls"
                            ? truncateUrlForDisplay(entry)
                            : escapeHtml(entry);
                        return `
                        <span class="chip chip-${ruleType}" title="${escapeAttribute(entry)}">
                          <span class="chip-label${isHash ? ' chip-label-mono' : ''}">${displayLabel}</span>
                        </span>
                        `;
                      }
                    )
                    .join("")}
                </div>`
              : `<p class="empty-copy">No ${humanizeRuleType(ruleType).toLowerCase()} rules set by policy.</p>`
          }
        </section>
      `;
    })
    .join("");

  updateDOM(mount, htmlString);
}


/**
 * Truncates a long URL for display inside a chip.
 * Shows: hostname + first N chars of path. Full URL visible on hover (title attr).
 * e.g. https://export-download.canva.com/5kwDo/DAHGwlSkwDo...?X-Amz-Algorithm=...
 *   → export-download.canva.com/5kwDo/DAHGwlSkwDo…
 */
function truncateUrlForDisplay(rawUrl) {
  const MAX_LEN = 48;
  if (!rawUrl) return '';
  if (rawUrl.startsWith("data:")) {
    const mime = rawUrl.split(";")[0].replace("data:", "") || "data";
    return escapeHtml("[Data URL: " + mime + "]");
  }
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname;
    const path = parsed.pathname;
    const short = `${host}${path}`;
    if (short.length > MAX_LEN) {
      return escapeHtml(`${short.slice(0, MAX_LEN - 1)}\u2026`);
    }
    return escapeHtml(short);
  } catch {
    // Not a parseable URL — just truncate the raw string
    if (rawUrl.length > MAX_LEN) {
      return escapeHtml(`${rawUrl.slice(0, MAX_LEN - 1)}\u2026`);
    }
    return escapeHtml(rawUrl);
  }
}

function renderSettings(settings) {
  const merged = {
    ...DEFAULT_CONFIG.settings,
    ...settings
  };

  generalSettingInputs.forEach((input) => {
    input.checked = Boolean(merged[input.dataset.setting]);
  });
}

function renderVirusTotal(vtConfig) {
  vtKeyInput.value = vtConfig.apiKey || "";
  vtKeyMask.textContent = vtConfig.apiKey
    ? `Saved key: ${maskSecret(vtConfig.apiKey)}`
    : "Not configured. ThreatLens keeps OSINT checks manual until you add a key.";

  vtSettingInputs.forEach((input) => {
    input.checked = Boolean(vtConfig[input.dataset.vtSetting]);
  });
}

function renderHybridAnalysis(haConfig) {
  haConfig = haConfig || {};
  haKeyInput.value = haConfig.apiKey || "";
  haKeyMask.textContent = haConfig.apiKey
    ? `Saved key: ${maskSecret(haConfig.apiKey)}`
    : "Not configured. ThreatLens will not query sandbox reports.";

  haSettingInputs.forEach((input) => {
    input.checked = Boolean(haConfig[input.dataset.haSetting]);
  });
}

function renderSandboxTab(record) {
  if (!sandboxContentContainer) return;

  const sandboxJob = record?.sandboxJob || {};
  const jobStatus = sandboxJob.status;
  const intelResult = record?.providerReports?.hybridAnalysis;
  const intelStatus = intelResult?.status;
  
  // If we have an existing report via intelligence lookup and no active sandbox job, show it
  const isExistingReport = (jobStatus === "existing_report") || (!jobStatus && intelStatus === "complete");
  // If we have a completed job, show it. Fallback to intelResult if it exists.
  const result = sandboxJob.result || intelResult;
  const isComplete = jobStatus === "completed" || isExistingReport;

  // Render settings toggle function
  const renderSettingsToggle = () => `
    <article class="panel-card" style="text-align: left; margin-bottom: 16px;">
      <div class="panel-head" style="margin-bottom: 12px;">
        <div>
          <p class="eyebrow">Settings</p>
          <h2>Sandbox Configuration</h2>
        </div>
      </div>
      <label class="toggle-card" style="margin: 0;">
        <div>
          <strong>Auto-Submit Suspicious Files</strong>
          <p>Automatically submit files flagged as malicious to Hybrid Analysis.</p>
        </div>
        <input type="checkbox" data-ha-setting="autoSubmitMalicious">
      </label>
    </article>
  `;

  const bindSettingsToggle = () => {
    const toggle = sandboxContentContainer.querySelector('[data-ha-setting="autoSubmitMalicious"]');
    if (toggle && _configCache) {
      toggle.checked = Boolean(_configCache.integrations?.hybridAnalysis?.autoSubmitMalicious);
      toggle.addEventListener("change", async () => {
        await storageManager.updateHybridAnalysis({ autoSubmitMalicious: toggle.checked });
        await render();
      });
    }
  };

  // State 1: No API Key
  const haKey = _configCache?.integrations?.hybridAnalysis?.apiKey;
  if (!haKey) {
    const html = `
      <div class="empty-state" style="margin-top: 20px; text-align: center;">
        ${renderSettingsToggle()}
        <div style="background: var(--card-inner); border: 1px dashed var(--border); border-radius: 12px; padding: 40px 20px;">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: var(--warn); margin-bottom: 12px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          <h3 style="font-size: 14px; font-weight: 700; color: var(--text); margin-bottom: 6px;">API Key Required</h3>
          <p style="font-size: 12px; color: var(--text-soft); line-height: 1.5; max-width: 260px; margin: 0 auto;">Configure your Hybrid Analysis API key in Settings to enable sandbox detonation and deep behavioral intelligence.</p>
        </div>
      </div>
    `;
    updateDOM(sandboxContentContainer, html);
    bindSettingsToggle();
    return;
  }

  // State 2: Idle (No job, no existing report)
  if (!jobStatus && !isExistingReport) {
    const html = `
      <div class="empty-state" style="margin-top: 20px; text-align: center;">
        ${renderSettingsToggle()}
        <div style="background: var(--card-inner); border: 1px dashed var(--border); border-radius: 12px; padding: 40px 20px;">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: var(--text-muted); margin-bottom: 12px;"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
          <h3 style="font-size: 14px; font-weight: 700; color: var(--text); margin-bottom: 6px;">Awaiting Sandbox Data</h3>
          <p style="font-size: 12px; color: var(--text-soft); line-height: 1.5; max-width: 260px; margin: 0 auto;">Select a file in the Review tab and click "Run Sandbox Analysis" to detonate it and view behavioral reports here.</p>
        </div>
      </div>
    `;
    updateDOM(sandboxContentContainer, html);
    bindSettingsToggle();
    return;
  }

  // State 3: Active Job (Loading states)
  if (!isComplete && jobStatus !== "failed" && jobStatus !== "timeout") {
    let message = "Submitting file for analysis...";
    if (jobStatus === "queued") message = "Waiting in sandbox queue...";
    else if (jobStatus === "running") message = "Detonating file in secure environment...";
    else if (jobStatus === "processing") message = "Generating behavioral report...";

    const progressValue = jobStatus === "submitting" ? 10 : jobStatus === "queued" ? 30 : jobStatus === "running" ? 60 : jobStatus === "processing" ? 90 : 100;

    const isLargeFile = record?.fileSize > 50 * 1024 * 1024;
    const sizeWarningHtml = isLargeFile ? `
      <div style="background: var(--warn-bg); border: 1px solid var(--warn-border); border-radius: 8px; padding: 12px 16px; margin-top: 12px; display: flex; gap: 12px; align-items: flex-start; text-align: left;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--warn); flex-shrink: 0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        <div>
          <strong style="font-size: 12px; color: var(--warn); display: block; margin-bottom: 2px;">Large File Detected</strong>
          <span style="font-size: 11px; color: var(--text-soft); line-height: 1.4; display: block;">This file is quite large. Uploading and detonating it in the secure environment may take several minutes. Please be patient.</span>
        </div>
      </div>
    ` : "";

    const html = `
      <div style="margin-top: 20px;">
        <article class="panel-card" style="margin-bottom: 16px; overflow: hidden; position: relative;">

          <!-- Animated detonation header -->
          <div style="
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 4px 0 16px;
            border-bottom: 1px solid var(--border-soft);
            margin-bottom: 14px;
          ">
            <!-- Pulsing radar icon -->
            <div style="position: relative; width: 52px; height: 52px; flex-shrink: 0;">
              <div class="tl-sandbox-ring tl-sandbox-ring-1"></div>
              <div class="tl-sandbox-ring tl-sandbox-ring-2"></div>
              <div class="tl-sandbox-ring tl-sandbox-ring-3"></div>
              <div style="
                position: absolute; inset: 0;
                display: flex; align-items: center; justify-content: center;
                background: var(--info-bg);
                border: 1.5px solid var(--info-border);
                border-radius: 14px;
                z-index: 4;
              ">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
            </div>

            <!-- Labels -->
            <div style="flex: 1; min-width: 0;">
              <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-label); margin-bottom: 3px;">Sandbox Detonation</div>
              <div style="font-size: 14px; font-weight: 800; color: var(--text); letter-spacing: -0.01em;">${message}</div>
            </div>

            <!-- Stage pill -->
            <span style="
              flex-shrink: 0;
              font-size: 10px; font-weight: 800;
              letter-spacing: 0.08em; text-transform: uppercase;
              padding: 4px 9px; border-radius: 6px;
              background: var(--info-bg); color: var(--info);
              border: 1px solid var(--info-border);
            ">${jobStatus || "init"}</span>
          </div>

          <!-- Step pipeline -->
          <div style="display: flex; align-items: flex-start; gap: 0; margin-bottom: 16px;">
            ${[
              { id: "submitting", label: "Upload",   icon: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12" },
              { id: "queued",     label: "Queue",    icon: "M3 12h18M3 6h18M3 18h18" },
              { id: "running",    label: "Detonate", icon: "M13 2L3 14h9l-1 8 10-12h-9l1-8z" },
              { id: "processing", label: "Report",   icon: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8" }
            ].map((step, i) => {
              const order = ["submitting","queued","running","processing"];
              const currentIdx = order.indexOf(jobStatus);
              const stepIdx = order.indexOf(step.id);
              const isDone = stepIdx < currentIdx;
              const isActive = stepIdx === currentIdx;
              const isPending = stepIdx > currentIdx;
              return `
                <div style="flex: 1; display: flex; flex-direction: column; align-items: center; gap: 6px; position: relative;">
                  ${i < 3 ? `<div style="
                    position: absolute; top: 14px; left: 50%; width: 100%;
                    height: 2px;
                    background: ${isDone ? 'var(--info)' : 'var(--border)'};
                    transition: background 0.4s ease;
                    z-index: 0;
                  "></div>` : ""}
                  <div style="
                    width: 28px; height: 28px; border-radius: 50%; position: relative; z-index: 1;
                    display: flex; align-items: center; justify-content: center;
                    background: ${isDone ? 'var(--info)' : isActive ? 'var(--info-bg)' : 'var(--card-inner)'};
                    border: 2px solid ${isDone ? 'var(--info)' : isActive ? 'var(--info)' : 'var(--border)'};
                    ${isActive ? 'animation: tl-sandbox-step-pulse 1.4s ease-in-out infinite;' : ''}
                  ">
                    ${isDone
                      ? `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`
                      : `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="${isActive ? 'var(--info)' : 'var(--text-label)'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${step.icon}"/></svg>`
                    }
                  </div>
                  <span style="font-size: 9.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: ${isActive ? 'var(--info)' : isDone ? 'var(--text)' : 'var(--text-label)'};">${step.label}</span>
                </div>
              `;
            }).join("")}
          </div>

          <!-- Progress bar -->
          <div style="
            height: 4px; background: var(--border); border-radius: 4px; overflow: hidden;
          ">
            <div style="
              height: 100%; border-radius: 4px;
              background: linear-gradient(90deg, var(--info), var(--brand-mid));
              box-shadow: 0 0 8px rgba(37,99,235,0.35);
              width: ${progressValue}%;
              transition: width 0.8s cubic-bezier(0.4,0,0.2,1);
            "></div>
          </div>

          ${sizeWarningHtml}
        </article>

        <!-- Animated Terminal Scanner (replaces empty skeletons) -->
        <article class="panel-card" style="margin-top: 16px; padding: 16px; border: 1px solid var(--border-soft); background: var(--card-inner);">
          <div style="display: flex; flex-direction: column; gap: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
            <div style="display: flex; align-items: center; justify-content: space-between; font-size: 11px;">
              <span style="color: var(--text-soft); display: flex; align-items: center; gap: 6px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                Virtual Machine
              </span>
              <span style="font-weight: 500; color: var(--text-muted);">${jobStatus === "submitting" || jobStatus === "queued" ? "Provisioning..." : "Active"}</span>
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; font-size: 11px;">
              <span style="color: var(--text-soft); display: flex; align-items: center; gap: 6px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path><path d="M2 12h20"></path></svg>
                Network Telemetry
              </span>
              <span style="font-weight: 500; color: var(--text-muted);">${jobStatus === "processing" ? "Captured" : "Intercepting..."}</span>
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; font-size: 11px;">
              <span style="color: var(--text-soft); display: flex; align-items: center; gap: 6px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M8 11h8"></path><path d="M8 15h8"></path></svg>
                Behavioral Trace
              </span>
              <span style="font-weight: 500; color: var(--text-muted);">${jobStatus === "processing" ? "Analyzing..." : "Pending"}</span>
            </div>
            
            <div style="width: 100%; background: var(--border-soft); border-radius: 999px; height: 4px; margin-top: 8px; overflow: hidden;">
              <div style="
                height: 100%;
                background: var(--info);
                border-radius: 999px;
                width: 40%;
                animation: scan-bounce 2s ease-in-out infinite;
              "></div>
            </div>
            <style>
              @keyframes scan-bounce {
                0% { transform: translateX(-100%); }
                50% { transform: translateX(250%); }
                100% { transform: translateX(-100%); }
              }
            </style>
          </div>
        </article>
      </div>
    `;
    updateDOM(sandboxContentContainer, html);
    return;
  }

  // State 4: Error State
  if (jobStatus === "failed" || jobStatus === "timeout") {
    const html = `
      <div class="empty-state" style="margin-top: 20px; text-align: center;">
        ${renderSettingsToggle()}
        <div style="background: var(--danger-bg); border: 1px solid var(--danger-border); border-radius: 12px; padding: 40px 20px;">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: var(--danger); margin-bottom: 12px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
          <h3 style="font-size: 14px; font-weight: 700; color: var(--danger); margin-bottom: 6px;">Sandbox Analysis ${jobStatus === "timeout" ? "Timed Out" : "Failed"}</h3>
          <p style="font-size: 12px; color: var(--danger); line-height: 1.5; max-width: 260px; margin: 0 auto; opacity: 0.8;">${escapeHtml(sandboxJob.errorMessage || "An unknown error occurred during detonation.")}</p>
        </div>
        ${sandboxJob.errorCode || sandboxJob.errorMessage ? `
        <div style="background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 12px; padding: 16px; margin-top: 16px; text-align: left;">
          <h4 style="font-size: 12px; font-weight: 700; color: var(--text); margin-bottom: 8px;">API Response Diagnostics</h4>
          <div style="font-size: 11px; color: var(--text-soft); font-family: monospace; background: var(--bg); padding: 12px; border-radius: 6px; border: 1px solid var(--border); overflow-x: auto;">
            <strong style="color: var(--text);">Error Code:</strong> ${escapeHtml(sandboxJob.errorCode || "unknown_error")}<br>
            <strong style="color: var(--text); margin-top: 6px; display: inline-block;">Message:</strong> ${escapeHtml(sandboxJob.errorMessage || "No additional message.")}<br>
          </div>
        </div>
        ` : ''}
      </div>
    `;
    updateDOM(sandboxContentContainer, html);
    bindSettingsToggle();
    return;
  }

  // State 5: Complete (Render Dashboard)
  if (isComplete && result) {
    const isMalicious = result.verdict === "malicious";
    const isSuspicious = result.verdict === "suspicious";
    const isClean = result.verdict === "clean" || result.verdict === "no specific threat";
    
    let ringColor = "var(--text-soft)";
    if (isMalicious) ringColor = "var(--danger)";
    else if (isSuspicious) ringColor = "var(--warn)";
    else if (isClean) ringColor = "var(--good)";

    // Calculate ring offset (circumference = 2 * pi * 44 = ~276.46)
    const circumference = 276.46;
    // Prefer sandboxJob.result score (real detonation) over intel lookup score (may be 0)
    const hasSandboxScore = sandboxJob?.result?.threat_score != null && sandboxJob.result.threat_score > 0;
    const score = hasSandboxScore
      ? sandboxJob.result.threat_score
      : (result.threat_score || 0);
    // If this is an intel-only cached lookup with score 0, flag it
    const isScoreUnknown = !hasSandboxScore && score === 0 && isExistingReport;
    const dashoffset = isScoreUnknown ? circumference : (circumference - (score / 100) * circumference);

    // Env selector shared by re-run button
    const envSelectorHtml = `
      <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 10px;">
        <select id="sandbox-tab-env-select" style="flex: 1; min-width: 140px; border: 1.5px solid var(--border); border-radius: 8px; padding: 7px 10px; font-size: 12px; font-weight: 600; background: var(--card); color: var(--text); cursor: pointer; outline: none; font-family: var(--font);">
          <option value="160" selected>Windows 10 64-bit</option>
          <option value="120">Windows 7 32-bit</option>
          <option value="110">Windows 7 64-bit</option>
          <option value="430">macOS</option>
          <option value="330">Linux (Ubuntu)</option>
          <option value="200">Android</option>
        </select>
        <button type="button" class="rv-scan-btn" data-sandbox-rerun="true" style="white-space: nowrap; flex-shrink: 0; font-weight: 700; padding: 7px 14px; border-radius: 8px; background: var(--info-bg); color: var(--info); border: 1.5px solid var(--info-border);">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          Re-run Sandbox
        </button>
      </div>
    `;

    // Build MITRE html
    const mitreHtml = (result.mitre_attcks || []).slice(0, 8).map(m => `
      <span class="mitre-technique-badge">
        <span class="mitre-technique-id">${escapeHtml(m.technique)}</span>
        <span style="max-width: 150px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(m.tactic)}</span>
      </span>
    `).join("");

    // Build process tree html
    const processHtml = (result.processes || []).slice(0, 10).map((p, i) => {
      const isCmd = p.name?.toLowerCase().includes("cmd.exe") || p.name?.toLowerCase().includes("powershell");
      return `
      <div style="display: flex; gap: 10px; margin-bottom: 8px; padding: 10px 12px; background: var(--card-inner); border: 1px solid var(--border-soft); border-radius: 8px; box-shadow: 0 1px 2px rgba(0,0,0,0.02); min-width: 0;">
        <div style="color: var(--brand-mid); opacity: 0.5; font-size: 14px; font-weight: 800; margin-top: 2px; flex-shrink: 0;">${i === 0 ? '●' : '↳'}</div>
        <div style="flex: 1; min-width: 0;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px; min-width: 0;">
            <span style="font-size: 10px; font-weight: 800; color: #fff; background: ${isCmd ? 'var(--danger)' : 'var(--brand-mid)'}; padding: 3px 6px; border-radius: 4px; letter-spacing: 0.05em; flex-shrink: 0;">PID ${p.pid || 'N/A'}</span>
            <span style="font-size: 13px; font-weight: 700; color: ${isCmd ? 'var(--danger)' : 'var(--text)'}; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; display: block; min-width: 0; flex: 1;">${escapeHtml(p.name)}</span>
          </div>
          ${p.command_line ? `<div style="font-size: 11px; font-family: monospace; color: var(--text-soft); background: var(--bg); border: 1px solid var(--border); padding: 6px 8px; border-radius: 4px; word-wrap: break-word; word-break: break-all;">${escapeHtml(p.command_line)}</div>` : ''}
          ${p.injected ? `<span style="font-size: 10px; font-weight: 800; color: var(--danger); background: var(--danger-bg); border: 1px solid var(--danger-border); padding: 3px 6px; border-radius: 4px; margin-top: 6px; display: inline-block;">⚠️ INJECTED THREAD</span>` : ''}
        </div>
      </div>
    `}).join("") || '<p class="sandbox-analyst-notes">No significant process execution recorded.</p>';

    // Build network html
    const networkDomains = result.network_activity?.domains || result.iocs?.domains || [];
    const networkIPs = result.network_activity?.contacted_ips || result.iocs?.ip_addresses || [];
    const networkUrls = result.network_activity?.contacted_urls || result.iocs?.urls || [];
    
    let networkHtml = "";
    if (networkDomains.length > 0 || networkIPs.length > 0 || networkUrls.length > 0) {
      networkHtml += networkDomains.slice(0, 5).map(d => `<tr><td>Domain</td><td><span class="ioc-badge">${escapeHtml(d)}</span></td></tr>`).join("");
      networkHtml += networkIPs.slice(0, 5).map(ip => `<tr><td>IP</td><td><span class="ioc-badge">${escapeHtml(ip?.address || ip)}</span></td></tr>`).join("");
      networkHtml += networkUrls.slice(0, 5).map(u => `<tr><td>URL</td><td><span class="ioc-badge">${escapeHtml(u?.url || u).substring(0, 40) + '...'}</span></td></tr>`).join("");
    } else {
      networkHtml = '<tr><td colspan="2" style="color: var(--text-soft); padding: 12px 16px;">No significant network activity recorded.</td></tr>';
    }

    // Build behavioral indicators HTML
    const behavioralHtml = (result.behavioral_indicators || []).slice(0, 10).map(indicator => `
      <div style="font-size: 11px; padding: 6px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px;">
        <span style="color: var(--danger); margin-right: 6px;">⚠️</span>
        ${escapeHtml(indicator)}
      </div>
    `).join("") || '<p class="sandbox-analyst-notes">No explicit behavioral indicators matched.</p>';

    // Build extracted files HTML
    const extractedFilesHtml = (result.extracted_files || []).slice(0, 8).map(file => `
      <div style="display: flex; flex-direction: column; padding: 8px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px;">
        <strong style="font-size: 11px; color: var(--text);">${escapeHtml(file.name || 'Unknown')}</strong>
        <span style="font-size: 10px; color: var(--text-soft); margin-top: 2px;">Type: ${escapeHtml(file.type || 'Unknown')} | Size: ${file.size ? (file.size / 1024).toFixed(1) + ' KB' : 'N/A'}</span>
      </div>
    `).join("") || '<p class="sandbox-analyst-notes">No files dropped or extracted.</p>';

    // Build scanners HTML
    const scannersHtml = (result.scanners || []).filter(s => s.status && s.status !== 'clean' && s.status !== 'whitelisted').slice(0, 8).map(scanner => `
      <span class="mitre-technique-badge" style="background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger);">
        <span style="font-weight: 800; margin-right: 4px;">${escapeHtml(scanner.name)}</span>
        <span>${escapeHtml(scanner.status)}</span>
      </span>
    `).join("") || '<p class="sandbox-analyst-notes">No AV detections reported from scanners.</p>';

    const html = `
      <div class="sandbox-dashboard">
        ${isExistingReport ? `
          <div class="sandbox-job-status" style="padding: 8px 12px; flex-direction: column; align-items: flex-start; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--brand-mid); flex-shrink: 0;"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              <div style="font-size: 11px; color: var(--text);">
                ${isScoreUnknown
                  ? 'Showing cached intelligence lookup. <strong>Threat score unavailable</strong> — run sandbox detonation for accurate scoring.'
                  : 'Showing cached analysis report from Hybrid Analysis.'}
              </div>
            </div>
            ${envSelectorHtml}
          </div>
        ` : `
          <div style="padding: 8px 12px; margin-bottom: 8px;">
            ${envSelectorHtml}
          </div>
        `}
        
        <div class="sandbox-top-grid">
          <!-- Threat Score -->
          <article class="panel-card" style="padding: 0;">
            <div class="threat-score-ring-container">
              <div class="threat-score-ring">
                <svg>
                  <circle class="threat-score-ring-bg" cx="50" cy="50" r="44"></circle>
                  <circle class="threat-score-ring-fill" cx="50" cy="50" r="44" style="stroke: ${ringColor}; stroke-dasharray: ${circumference}; stroke-dashoffset: ${dashoffset};"></circle>
                </svg>
                <div class="threat-score-ring-text">
                  <div class="threat-score-ring-value" style="color: ${ringColor};">${isScoreUnknown ? '?' : score}</div>
                  <div class="threat-score-ring-label">${isScoreUnknown ? 'N/A' : 'SCORE'}</div>
                </div>
              </div>
            </div>
            <div class="sandbox-verdict-footer">
              <span class="sandbox-verdict-pill sandbox-verdict-pill--${isMalicious ? 'danger' : isSuspicious ? 'warn' : isClean ? 'good' : 'neutral'}">
                ${escapeHtml(result.verdict || 'Unknown').toUpperCase()}
              </span>
            </div>
          </article>

          <!-- Core details -->
          <article class="panel-card">
            <div class="panel-head" style="margin-bottom: 8px;">
              <div>
                <p class="eyebrow">CrowdStrike Falcon</p>
                <h2>File Identity</h2>
              </div>
            </div>
            
            <div class="sandbox-file-detail-row">
              <span class="sandbox-file-detail-label">File Type</span>
              <span class="sandbox-file-detail-value">${(() => {
                let displayFileType = result.file_metadata?.type || result.file_type || record.mimeType;
                if (!displayFileType || displayFileType === "application/octet-stream") {
                  const ext = record.fileName?.split('.').pop()?.toUpperCase() || "";
                  displayFileType = ext ? ext + " File" : "Unknown";
                }
                return escapeHtml(displayFileType);
              })()}</span>
            </div>
            <div class="sandbox-file-detail-row">
              <span class="sandbox-file-detail-label">MD5</span>
              <span class="sandbox-file-detail-value">${result.md5 ? `<button class="copy-hash-btn" data-copy="${escapeHtml(result.md5)}">Copy</button>` : ''} ${escapeHtml(result.md5 ? result.md5.substring(0, 16) + '...' : 'N/A')}</span>
            </div>
            <div class="sandbox-file-detail-row">
              <span class="sandbox-file-detail-label">Analysis ID</span>
              <span class="sandbox-file-detail-value">${escapeHtml(result.job_id || result.id || 'N/A')}</span>
            </div>
            <div class="sandbox-file-detail-row">
              <span class="sandbox-file-detail-label">Environment</span>
              <span class="sandbox-file-detail-value" style="font-weight: 600;">${escapeHtml(result.environment_desc || result.environment_id || 'Unknown OS / Architecture')}</span>
            </div>
            ${result.analysis_start_time ? `
            <div class="sandbox-file-detail-row">
              <span class="sandbox-file-detail-label">Analysis Time</span>
              <span class="sandbox-file-detail-value">${escapeHtml(new Date(result.analysis_start_time).toLocaleString())}</span>
            </div>` : ''}
          </article>
        </div>

        <!-- MITRE Matrix -->
        <article class="panel-card sandbox-card" style="padding: 0;">
          <div class="sandbox-card-header">
            <div>
              <span class="sandbox-card-eyebrow">Behavioral Indicators</span>
              <span style="color: var(--brand-mid); font-weight: 800;">MITRE ATT&CK Matrix</span>
            </div>
            <svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
          <div class="sandbox-card-body">
            <div class="mitre-techniques">
              ${mitreHtml || '<p class="sandbox-analyst-notes">No MITRE ATT&CK techniques observed.</p>'}
            </div>
          </div>
        </article>

        <!-- Process Tree -->
        <article class="panel-card sandbox-card" style="padding: 0;">
          <div class="sandbox-card-header">
            <div>
              <span class="sandbox-card-eyebrow">Execution Flow</span>
              <span style="color: var(--brand); font-weight: 800;">Process Tree</span>
            </div>
            <svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
          <div class="sandbox-card-body">
            <div class="process-tree">
              ${processHtml}
            </div>
          </div>
        </article>

        <!-- Network IOCs -->
        <article class="panel-card sandbox-card" style="padding: 0;">
          <div class="sandbox-card-header">
            <div>
              <span class="sandbox-card-eyebrow">Indicators of Compromise</span>
              <span style="color: var(--danger); font-weight: 800;">Network Activity</span>
            </div>
            <svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
          <div class="sandbox-card-body">
            ${networkHtml ? `
              <div class="ioc-table-wrapper">
                <table class="ioc-table">
                  <thead><tr><th>Type</th><th>Indicator</th></tr></thead>
                  <tbody>${networkHtml}</tbody>
                </table>
              </div>
            ` : '<p class="sandbox-analyst-notes">No suspicious network activity recorded.</p>'}
          </div>
        </article>

        <!-- Behavioral Indicators -->
        <article class="panel-card sandbox-card" style="padding: 0;">
          <div class="sandbox-card-header">
            <div>
              <span class="sandbox-card-eyebrow">Behavioral Analysis</span>
              <span style="color: var(--warn); font-weight: 800;">Signatures & Heuristics</span>
            </div>
            <svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
          <div class="sandbox-card-body">
            <div style="display: flex; flex-direction: column;">
              ${behavioralHtml}
            </div>
          </div>
        </article>

        <!-- Extracted Files -->
        <article class="panel-card sandbox-card" style="padding: 0;">
          <div class="sandbox-card-header">
            <div>
              <span class="sandbox-card-eyebrow">Forensics</span>
              <span style="color: var(--info); font-weight: 800;">Extracted & Dropped Files</span>
            </div>
            <svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
          <div class="sandbox-card-body">
            <div style="display: flex; flex-direction: column;">
              ${extractedFilesHtml}
            </div>
          </div>
        </article>

        <!-- Scanners -->
        <article class="panel-card sandbox-card" style="padding: 0;">
          <div class="sandbox-card-header">
            <div>
              <span class="sandbox-card-eyebrow">Detection Engines</span>
              <span style="color: var(--good); font-weight: 800;">Antivirus Scanners</span>
            </div>
            <svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
          <div class="sandbox-card-body">
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
              ${scannersHtml}
            </div>
          </div>
        </article>

      </div>
    `;
    updateDOM(sandboxContentContainer, html);

    // Bind copy buttons
    const container = sandboxContentContainer;
    container.querySelectorAll('.copy-hash-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const text = btn.dataset.copy;
        copyToClipboard(text, btn);
        btn.classList.add('is-copied');
        setTimeout(() => btn.classList.remove('is-copied'), 1500);
      });
    });

    // Bind re-run sandbox button — reads from the sandbox tab's own selector
    container.querySelectorAll('[data-sandbox-rerun]').forEach(btn => {
      btn.addEventListener('click', () => {
        void runDownloadAction(record.downloadId, "sandbox-scan");
      });
    });

    container.querySelectorAll('.sandbox-card-header').forEach(header => {
      header.addEventListener('click', () => {
        header.parentElement.classList.toggle('is-collapsed');
      });
    });
  }
}

// Helper to render HA Intel Card on Intel Tab
function renderHaIntelligenceCard(record) {
  // Source priority:
  // 1. Completed sandbox detonation — always has the real threat_score
  // 2. Intelligence lookup (hash DB query) — may have score 0 if overview-only
  const sandboxResult = (record?.sandboxJob?.status === "completed" && record?.sandboxJob?.result)
    ? record.sandboxJob.result : null;

  let intelResult = record?.providerReports?.hybridAnalysis;

  // If we have a sandbox detonation, merge its score into intelResult so the
  // correct number is always shown regardless of which data path populated the card
  if (sandboxResult) {
    intelResult = {
      status: "complete",
      provider: "Hybrid Analysis",
      ...intelResult,          // keep intel tags/MITRE if they exist
      ...sandboxResult,        // detonation data takes precedence
    };
  }

  if (!intelResult || intelResult.status === "loading") {
    return `
      <article class="intel-provider-card">
        <div class="intel-provider-header">
          <div class="intel-provider-icon intel-provider-icon--falcon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
          </div>
          <div>
            <div class="intel-provider-label">CrowdStrike Falcon</div>
            <div class="intel-provider-name">Hybrid Analysis</div>
          </div>
        </div>
        <div class="intel-provider-loading">
          <svg class="tl-reason-spinner-svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="2.5" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
          <span>Querying databases…</span>
        </div>
      </article>
    `;
  }

  if (intelResult.status === "error") {
    return `
      <article class="intel-provider-card">
        <div class="intel-provider-header">
          <div class="intel-provider-icon intel-provider-icon--falcon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
          </div>
          <div>
            <div class="intel-provider-label">CrowdStrike Falcon</div>
            <div class="intel-provider-name">Hybrid Analysis</div>
          </div>
        </div>
        <div class="intel-provider-state intel-provider-state--warn">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          ${escapeHtml(intelResult.errorMessage || 'Lookup failed')}
        </div>
      </article>
    `;
  }

  if (intelResult.verdict === "not_found") {
    return `
      <article class="intel-provider-card">
        <div class="intel-provider-header">
          <div class="intel-provider-icon intel-provider-icon--falcon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
          </div>
          <div>
            <div class="intel-provider-label">CrowdStrike Falcon</div>
            <div class="intel-provider-name">Hybrid Analysis</div>
          </div>
          <span class="intel-verdict-chip intel-verdict-chip--neutral">Not found</span>
        </div>
        <p class="intel-provider-note">No prior analysis found. Detonate this file in a sandbox to get a full behavioral report and accurate threat score.</p>
        <button type="button" class="rv-scan-btn" data-section-jump="sandbox" style="width: 100%; justify-content: center; margin-top: 4px; background: var(--info-bg); color: var(--info); border-color: var(--info-border); font-weight: 700; padding: 8px;">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Run Sandbox Analysis
        </button>
      </article>
    `;
  }

  // Determine the best score to display.
  // sandboxResult.threat_score is always authoritative (from real detonation).
  // intelResult.threat_score may be 0 from the overview-only DB lookup.
  const score = sandboxResult?.threat_score || intelResult.threat_score || 0;
  const hasRealScore = sandboxResult != null;    // detonation = definitive score
  const isIntelOnly = !sandboxResult;            // intel lookup only = no detonation score

  let chipClass = "intel-verdict-chip--good";
  let scoreClass = "intel-score--good";
  const verdictStr = (intelResult.verdict || "").toLowerCase();
  if (verdictStr === "malicious" || score >= 50) { chipClass = "intel-verdict-chip--danger"; scoreClass = "intel-score--danger"; }
  else if (verdictStr === "suspicious" || score >= 20) { chipClass = "intel-verdict-chip--warn"; scoreClass = "intel-score--warn"; }

  const tags = [
    ...(intelResult.mitre_attcks || []).slice(0, 2).map(m => m.technique),
    ...(intelResult.tags || []).slice(0, 2)
  ].filter(Boolean);

  // If we only have an intel lookup (no detonation), the score is unreliable.
  // Show the verdict + tags + a prompt to detonate for the real score.
  const scoreHtml = isIntelOnly && score === 0
    ? `<div style="margin: 4px 0 2px;">
        <p class="intel-provider-note" style="font-size: 10.5px;">Score unavailable from DB lookup — run sandbox detonation for the full threat score.</p>
        <button type="button" class="rv-scan-btn" data-section-jump="sandbox" style="width: 100%; justify-content: center; margin-top: 6px; background: var(--info-bg); color: var(--info); border-color: var(--info-border); font-weight: 700; padding: 7px; font-size: 11px;">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Get Real Score
        </button>
      </div>`
    : `<div class="intel-score-row">
        <div class="intel-score ${scoreClass}">
          <span class="intel-score-value">${score}</span>
          <span class="intel-score-denom">/100</span>
        </div>
        <div class="intel-score-bar-track">
          <div class="intel-score-bar ${scoreClass}" style="width: ${score}%;"></div>
        </div>
        ${hasRealScore ? '<span style="font-size: 9px; color: var(--text-label); font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; flex-shrink: 0;">Detonation</span>' : ''}
      </div>`;

  return `
    <article class="intel-provider-card">
      <div class="intel-provider-header">
        <div class="intel-provider-icon intel-provider-icon--falcon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <div>
          <div class="intel-provider-label">CrowdStrike Falcon</div>
          <div class="intel-provider-name">Hybrid Analysis</div>
        </div>
        <span class="intel-verdict-chip ${chipClass}">${escapeHtml(intelResult.verdict || 'unknown').toUpperCase()}</span>
      </div>
      ${scoreHtml}
      ${tags.length ? `<div class="intel-tag-row">${tags.map(t => `<span class="intel-tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
    </article>
  `;
}

// Helper to render Fuzzy Match Card on Intel Tab
function renderFuzzyMatchCard(record) {
  const tlshResult = record?.providerReports?.tlshLookup;

  if (!tlshResult || tlshResult.status === "loading" || record.fileHashStatus === "loading" || record.fileHashStatus === "idle") {
    return `
      <article class="intel-provider-card">
        <div class="intel-provider-header">
          <div class="intel-provider-icon intel-provider-icon--fuzzy">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
          </div>
          <div>
            <div class="intel-provider-label">TLSH Fingerprint</div>
            <div class="intel-provider-name">Similarity Indicators</div>
          </div>
        </div>
        <div class="intel-provider-loading">
          <svg class="tl-reason-spinner-svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="2.5" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
          <span>Computing fuzzy hash…</span>
        </div>
      </article>
    `;
  }

  if (tlshResult.status === "skipped_insufficient_data" || tlshResult.status === "error") {
    return `
      <article class="intel-provider-card">
        <div class="intel-provider-header">
          <div class="intel-provider-icon intel-provider-icon--fuzzy">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
          </div>
          <div>
            <div class="intel-provider-label">TLSH Fingerprint</div>
            <div class="intel-provider-name">Similarity Indicators</div>
          </div>
        </div>
        <div class="intel-provider-state intel-provider-state--neutral">
          ${tlshResult.status === "error" ? "Lookup failed" : "File too small for fuzzy match"}
        </div>
      </article>
    `;
  }

  if (tlshResult.matchCount === 0) {
    return `
      <article class="intel-provider-card">
        <div class="intel-provider-header">
          <div class="intel-provider-icon intel-provider-icon--fuzzy">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
          </div>
          <div>
            <div class="intel-provider-label">TLSH Fingerprint</div>
            <div class="intel-provider-name">Similarity Indicators</div>
          </div>
          <span class="intel-verdict-chip intel-verdict-chip--good">No matches</span>
        </div>
        <p class="intel-provider-note">No known malware clusters share this file's fuzzy hash fingerprint.</p>
      </article>
    `;
  }

  // Has matches
  return `
    <article class="intel-provider-card">
      <div class="intel-provider-header">
        <div class="intel-provider-icon intel-provider-icon--fuzzy">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
        </div>
        <div>
          <div class="intel-provider-label">TLSH Fingerprint</div>
          <div class="intel-provider-name">Similarity Indicators</div>
        </div>
        <span class="intel-verdict-chip intel-verdict-chip--danger">${tlshResult.matchCount} match${tlshResult.matchCount !== 1 ? 'es' : ''}</span>
      </div>
      <div class="intel-match-list">
        ${(tlshResult.results || []).slice(0, 3).map(m => {
          const cls = m.verdict === 'malicious' ? 'intel-match-row--danger' : m.verdict === 'suspicious' ? 'intel-match-row--warn' : 'intel-match-row--good';
          return `
            <div class="intel-match-row ${cls}">
              <span class="intel-match-hash">${escapeHtml(m.sha256 ? m.sha256.substring(0, 14) + '…' : 'Unknown')}</span>
              <span class="intel-match-verdict">${escapeHtml(m.verdict || 'unknown')}</span>
            </div>`;
        }).join("")}
      </div>
    </article>
  `;
}

function renderActivitySummary(stats) {
  const newText = stats.lastEventAt
    ? `ThreatLens last recorded activity on ${formatTimestamp(stats.lastEventAt)}. You can reset this history to start a fresh monitoring session.`
    : "No ThreatLens activity has been recorded yet.";
    
  if (activitySummary.textContent !== newText) {
    activitySummary.textContent = newText;
  }
}

async function runDownloadAction(downloadId, action) {
  let envId = null;
  if (action === "check-reputation") {
    activeInsightTab = "virustotal";
  } else if (action === "sandbox-scan") {
    // Check sandbox tab's own selector first (more specific), fall back to review tab's
    const tabSelect = document.getElementById("sandbox-tab-env-select");
    const reviewSelect = document.getElementById("sandbox-env-select");
    const envSelect = tabSelect || reviewSelect;
    envId = envSelect ? parseInt(envSelect.value, 10) : 160;
    showSection("sandbox");
  }

  busyAction = action;
  let response = null;
  let errorMessage = "";

  try {
    await render();

    let messageType = "threatlens:download-action";
    if (action === "sandbox-scan") messageType = "threatlens:sandbox-scan";
    
    const payload = {
      type: messageType,
      downloadId,
      action
    };
    if (envId) payload.envId = envId;

    response = await chrome.runtime.sendMessage(payload);

    if (!response?.ok) {
      errorMessage = response?.error || "ThreatLens could not complete that action.";
      return;
    }

    if (action === "allow") {
      // Allow: close popup so the user can watch the download proceed
      attemptSurfaceClose();
    } else if (action === "block") {
      // Block: jump to Review tab so user can see the blocked result briefly
      showSection("review");
    }
  } catch (error) {
    errorMessage = error?.message || "ThreatLens could not complete that action.";
  } finally {
    busyAction = "";
    if (action !== "allow" || !response?.ok) {
      try {
        await render();
        if (errorMessage) {
          heroCopy.textContent = errorMessage;
        }
      } catch (error) {
        console.error("[ThreatLens] Popup render recovery failed:", error);
      }
    }
  }
}

async function runProviderAction(downloadId, provider) {
  activeInsightTab = provider === "urlscan" ? "urlscan" : "virustotal";
  busyAction = provider;
  let response = null;
  let errorMessage = "";

  try {
    await render();

    response = await chrome.runtime.sendMessage({
      type: "threatlens:open-provider",
      downloadId,
      provider
    });

    if (!response?.ok) {
      errorMessage = response?.error || "ThreatLens could not run that provider lookup.";
      return;
    }
  } catch (error) {
    errorMessage = error?.message || "ThreatLens could not run that provider lookup.";
  } finally {
    busyAction = "";
    try {
      await render();
      if (errorMessage) {
        heroCopy.textContent = errorMessage;
      }
    } catch (error) {
      console.error("[ThreatLens] Popup render recovery failed:", error);
    }
  }
}

function handleStorageChanged(changes, areaName) {
  if (areaName !== "local") return;

  const hasConfig = Boolean(changes["threatlens.config"]);
  const hasStats = Boolean(changes["threatlens.stats"]);
  const hasPending = Object.keys(changes).some((key) => key.startsWith("threatlens.pending."));

  if (!hasConfig && !hasStats && !hasPending) return;

  // If only pending data changed, skip re-fetching config and stats
  _pendingChangedOnly = hasPending && !hasConfig && !hasStats;
  scheduleRender();
}

function renderEngineStats(stats) {
  // Always show the grid if we have stats, even if they are all zero.
  // This provides a clear "Safe" indicator for the user.
  if (!stats || Object.keys(stats).length === 0) {
    return `<p class="provider-note">Engine counts will appear here after OSINT Research returns a result.</p>`;
  }

  return `
    <div class="intel-grid">
      <div class="stat-box stat-malicious"><span>Malicious</span><strong>${stats.malicious || 0}</strong></div>
      <div class="stat-box stat-suspicious"><span>Suspicious</span><strong>${stats.suspicious || 0}</strong></div>
      <div class="stat-box stat-harmless"><span>Harmless</span><strong>${stats.harmless || 0}</strong></div>
      <div class="stat-box stat-undetected"><span>Undetected</span><strong>${stats.undetected || 0}</strong></div>
    </div>
  `;
}

function renderUrlscanDetails(urlscan) {
  if (!urlscan.pageDomain && typeof urlscan.score !== "number") return "";

  const isMalicious = urlscan.score > 0;
  const scoreColor = isMalicious ? "var(--danger)" : "var(--good)";
  const scoreBg = isMalicious ? "#fef2f2" : "#f0fdf4";
  const scoreBorder = isMalicious ? "#fca5a5" : "#bbf7d0";

  let cardsHtml = "";
  
  if (typeof urlscan.score === "number") {
    cardsHtml += `
      <div style="background: ${scoreBg}; border: 1px solid ${scoreBorder}; padding: 14px; border-radius: 10px; display: flex; flex-direction: column; align-items: center; justify-content: center; min-width: 80px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
        <span style="font-size: 10px; font-weight: 700; color: ${scoreColor}; text-transform: uppercase;">Score</span>
        <strong style="font-size: 24px; line-height: 1.1; color: ${scoreColor}; margin-top: 4px;">${urlscan.score}</strong>
      </div>
    `;
  }

  let infoRows = "";
  if (urlscan.pageDomain) {
    infoRows += `<div style="display: flex; justify-content: space-between; padding: 5px 0;"><span style="color: var(--text-soft); font-size: 11px; font-weight: 600;">Domain</span><strong style="font-size: 12px; color: var(--text);">${escapeHtml(urlscan.pageDomain)}</strong></div>`;
  }
  if (urlscan.pageCountry) {
    infoRows += `<div style="display: flex; justify-content: space-between; padding: 5px 0;"><span style="color: var(--text-soft); font-size: 11px; font-weight: 600;">Country</span><strong style="font-size: 12px; color: var(--text);">${escapeHtml(urlscan.pageCountry)}</strong></div>`;
  }
  if (urlscan.pageIp) {
    infoRows += `<div style="display: flex; justify-content: space-between; padding: 5px 0;"><span style="color: var(--text-soft); font-size: 11px; font-weight: 600;">Server IP</span><strong style="font-size: 12px; color: var(--text);">${escapeHtml(urlscan.pageIp)}</strong></div>`;
  }
  if (urlscan.scannedAt) {
    infoRows += `<div style="display: flex; justify-content: space-between; padding: 5px 0;"><span style="color: var(--text-soft); font-size: 11px; font-weight: 600;">Scanned</span><strong style="font-size: 12px; color: var(--text);">${escapeHtml(formatTimestamp(urlscan.scannedAt))}</strong></div>`;
  }

  if (infoRows) {
    cardsHtml += `
      <div style="background: #fff; border: 1px solid var(--border); padding: 12px 16px; border-radius: 10px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
        ${infoRows}
      </div>
    `;
  }

  let brandsHtml = "";
  if (Array.isArray(urlscan.brands) && urlscan.brands.length > 0) {
    brandsHtml = `
      <div style="margin-top: 16px; padding: 14px; background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
        <span style="font-size: 10px; font-weight: 700; color: var(--danger); text-transform: uppercase;">Targeted Brands</span>
        <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px;">
          ${urlscan.brands.map(brand => `<span style="background: #fef2f2; color: var(--danger); border: 1px solid #fca5a5; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600;">${escapeHtml(brand)}</span>`).join("")}
        </div>
      </div>
    `;
  }

  return `
    <div style="display: flex; gap: 12px; align-items: stretch;">
      ${cardsHtml}
    </div>
    ${brandsHtml}
  `;
}

function getInsightCta(activeTab, reputation, urlscan, hasVirusTotalKey) {
  if (activeTab === "virustotal") {
    if (reputation.reportUrl) {
      return {
        label: "Open OSINT report",
        url: reputation.reportUrl
      };
    }
    if (reputation.analysisUrl) {
      return {
        label: "Open OSINT analysis",
        url: reputation.analysisUrl
      };
    }
    if (!hasVirusTotalKey) {
      return {
        label: "Add API key",
        section: "settings"
      };
    }
    return null;
  }

  if (activeTab === "urlscan") {
    if (urlscan.reportUrl) {
      return {
        label: "Open urlscan result",
        url: urlscan.reportUrl
      };
    }
    if (urlscan.searchUrl) {
      return {
        label: "Open urlscan search",
        url: urlscan.searchUrl
      };
    }
    return null;
  }

  if (reputation.reportUrl) {
    return {
      label: "Open VirusTotal report",
      url: reputation.reportUrl
    };
  }

  if (reputation.analysisUrl) {
    return {
      label: "Open VirusTotal analysis",
      url: reputation.analysisUrl
    };
  }

  if (urlscan.reportUrl) {
    return {
      label: "Open urlscan result",
      url: urlscan.reportUrl
    };
  }

  if (!hasVirusTotalKey) {
    return {
      label: "Add API key",
      section: "settings"
    };
  }

  return null;
}

function getReviewCopy(record) {
  if (isVirusTotalPending(record.reputation)) {
    return "ThreatLens is performing OSINT Research while the original download stays intercepted.";
  }
  if (record.providerReports?.urlscan?.status === "loading") {
    return "ThreatLens is scanning this URL with urlscan.io while the original download stays intercepted.";
  }
  return "ThreatLens intercepted this download until you allow or block it.";
}

function getSummaryState(record) {
  if (isVirusTotalPending(record.reputation) || record.providerReports?.urlscan?.status === "loading") {
    return "Scanning";
  }
  if (record.reputation?.status === "complete" || record.providerReports?.urlscan?.status === "complete") {
    return "Ready";
  }
  return "Waiting";
}

function getScanSummary(record) {
  const reputation = record.reputation || {};
  const urlscan = record.providerReports?.urlscan || {};

  if (isVirusTotalPending(reputation) || urlscan.status === "loading") {
    return "A scan is in progress.";
  }

  if (reputation.reportUrl || reputation.analysisUrl || reputation.verdict === "clean" || reputation.verdict === "malicious" || reputation.verdict === "suspicious") {
    if (urlscan.reportUrl || urlscan.status === "complete" || urlscan.status === "empty") {
      return "VirusTotal and urlscan.io both have scan status available.";
    }
    return "VirusTotal has status available.";
  }

  if (urlscan.reportUrl || urlscan.status === "complete" || urlscan.status === "empty") {
    return "urlscan.io has status available.";
  }

  return "No provider scan has been run yet.";
}

function getScanStatusClass(record) {
  const reputation = record.reputation || {};
  const urlscan = record.providerReports?.urlscan || {};
  if (isVirusTotalPending(reputation) || urlscan.status === "loading") return "value-warn";
  if (reputation.verdict === "malicious") return "value-danger";
  if (reputation.verdict === "suspicious") return "value-warn";
  if (reputation.verdict === "clean") return "value-safe";
  if (reputation.reportUrl || urlscan.reportUrl) return "value-safe";
  return "";
}

function getDownloadFacts(record) {
  const extension = record.extension || "No extension";
  const size = record.totalBytes > 0
    ? formatBytes(record.totalBytes)
    : record.bytesReceived > 0
      ? `${formatBytes(record.bytesReceived)} received`
      : "Size unknown";
  const mode = record.saveAsRequested ? "Save As flow" : "Direct download";

  return {
    primary: `${extension} • ${size}`,
    secondary: mode
  };
}

function getVirusTotalHint(reputation, hasVirusTotalKey) {
  if (!hasVirusTotalKey) {
    return "Add an OSINT API key in Settings if you want inline OSINT Research every time.";
  }
  if (isVirusTotalPending(reputation)) {
    return "ThreatLens will keep the download intercepted until OSINT Research responds or you make a decision.";
  }
  if (reputation.reportUrl || reputation.analysisUrl) {
    return "You can keep working inside ThreatLens or open the OSINT Report page for the full intelligence.";
  }

  return "Use Run OSINT Research whenever you want to refresh the OSINT result.";
}

function scheduleAutomaticScan(record, vtConfig) {
  if (!record || busyAction) return;

  // Clean up error counters for downloads that are no longer active
  pruneAutomaticScanRequests();

  if (!shouldEnsureAutomaticScan(record, vtConfig)) return;

  // Use a STABLE key: only downloadId + whether VT key is present.
  // Previously the key encoded scan statuses, so every status transition
  // (idle→loading→error) generated a new key and bypassed the TTL dedup,
  // causing a new API request on every render cycle.
  const hasVt = Boolean(String(vtConfig?.apiKey || "").trim());
  const requestKey = `${record.downloadId}:${hasVt ? "vt" : "no-vt"}`;

  const lastRequestedAt = automaticScanRequests.get(requestKey) || 0;
  if (Date.now() - lastRequestedAt < AUTOMATIC_SCAN_REQUEST_TTL_MS) {
    return; // Still within cooldown — do not fire again
  }

  automaticScanRequests.set(requestKey, Date.now());

  void chrome.runtime.sendMessage({
    type: "threatlens:ensure-automatic-scan",
    downloadId: record.downloadId
  }).then((response) => {
    if (!response?.ok) {
      // Message failed — remove the timestamp so the next render can retry
      automaticScanRequests.delete(requestKey);
    } else {
      // Track that a scan was successfully dispatched; reset error counts
      scanErrorCounts.delete(record.downloadId);
    }
  }).catch(() => {
    automaticScanRequests.delete(requestKey);
  });
}

function pruneAutomaticScanRequests() {
  const now = Date.now();
  for (const [key, requestedAt] of automaticScanRequests.entries()) {
    if (now - requestedAt > AUTOMATIC_SCAN_REQUEST_TTL_MS * 6) {
      automaticScanRequests.delete(key);
    }
  }
  // Also prune error counts for downloads that are no longer in storage
  // (they'll be cleaned up naturally when the download is removed)
}

function shouldEnsureAutomaticScan(record, vtConfig) {
  if (!record || (record.status !== "awaiting_user" && record.status !== "checking_reputation")) {
    return false;
  }

  const hasVirusTotalKey = Boolean(String(vtConfig?.apiKey || "").trim());
  const vtUrlReport = getVirusTotalUrlReport(record) || {};
  const vtFileReport = getVirusTotalFileReport(record) || {};
  const urlscan = record.providerReports?.urlscan || {};
  const ipReputation = record.providerReports?.ipReputation || {};
  const domainAudit = record.domainAudit || {};
  const hashReference = record.updatedAt || record.createdAt;

  const errs = scanErrorCounts.get(record.downloadId) || {};

  // ── Transition-based error counting ────────────────────────────────────
  const prevStatuses = lastSeenStatuses.get(record.downloadId) || {};
  const currentVtUrlStatus = vtUrlReport.status || "idle";
  const currentVtFileStatus = vtFileReport.status || "idle";
  const currentUrlscanStatus = urlscan.status || "idle";
  const currentIpStatus = ipReputation.status || "idle";
  const currentDomainStatus = domainAudit.status || "idle";

  let updatedErrs = { ...errs };
  let hasUpdates = false;

  const checkTransition = (key, currentStatus) => {
    if (currentStatus === "error" && prevStatuses[key] !== "error") {
      updatedErrs[key] = (updatedErrs[key] || 0) + 1;
      hasUpdates = true;
    }
  };

  checkTransition("vtUrl", currentVtUrlStatus);
  checkTransition("vtFile", currentVtFileStatus);
  checkTransition("urlscan", currentUrlscanStatus);
  checkTransition("ipRep", currentIpStatus);
  checkTransition("domain", currentDomainStatus);

  if (hasUpdates) {
    scanErrorCounts.set(record.downloadId, updatedErrs);
  }

  lastSeenStatuses.set(record.downloadId, {
    vtUrl: currentVtUrlStatus,
    vtFile: currentVtFileStatus,
    urlscan: currentUrlscanStatus,
    ipRep: currentIpStatus,
    domain: currentDomainStatus
  });

  const freshErrs = scanErrorCounts.get(record.downloadId) || {};

  // checkNeeds: only trigger a scan if it's in a state that genuinely needs work.
  // 'loading' is NEVER a trigger — it means the background worker is actively running.
  // 'queued' is NEVER a trigger — VirusTotal is processing and background is polling.
  // 'complete' is NEVER a trigger — the scan finished successfully.
  // Only 'idle', 'not_configured', 'unsupported', or capped 'error' trigger a new scan.
  const checkNeeds = (report, errKey) => {
    const status = report.status || "idle";
    return (
      status === "idle" ||
      status === "not_configured" ||
      status === "unsupported" ||
      (status === "error" && (freshErrs[errKey] || 0) < MAX_AUTO_RETRY) ||
      (status === "loading" && isPopupScanStale(report.checkedAt))
    );
  };

  const needsVtUrl = hasVirusTotalKey && checkNeeds(vtUrlReport, "vtUrl");
  const needsVtFile = hasVirusTotalKey && record.fileHash && record.fileHashStatus === "complete" && checkNeeds(vtFileReport, "vtFile");
  const needsUrlscan = checkNeeds(urlscan, "urlscan");
  
  // Hash: only trigger if truly idle or missing. Never re-trigger loading or complete unless stale.
  const needsHash = (
    !record.fileHashStatus ||
    record.fileHashStatus === "idle" ||
    (record.fileHashStatus === "loading" && isPopupScanStale(hashReference))
  );

  // IP + Domain: trigger once (idle/missing) or retry errors if tracked. Never re-trigger loading unless stale.
  const needsIp = !ipReputation.status || ipReputation.status === "idle" ||
    (ipReputation.status === "error" && (freshErrs.ipRep || 0) < MAX_AUTO_RETRY) ||
    (ipReputation.status === "loading" && isPopupScanStale(ipReputation.checkedAt));

  const needsDomain = !record.domainMetadata && (!domainAudit.status || domainAudit.status === "idle" ||
    (domainAudit.status === "error" && (freshErrs.domain || 0) < MAX_AUTO_RETRY) ||
    (domainAudit.status === "loading" && isPopupScanStale(domainAudit.checkedAt)));

  return needsVtUrl || needsVtFile || needsUrlscan || needsHash || needsIp || needsDomain;
}

function isPopupScanStale(timestamp) {
  if (!timestamp) {
    return true;
  }

  const parsed = new Date(timestamp).getTime();
  return !Number.isFinite(parsed) || Date.now() - parsed > POPUP_SCAN_STALE_MS;
}

function getUrlscanHint(urlscan) {
  if (urlscan.status === "loading") {
    return "ThreatLens is waiting for urlscan.io and will keep the result inside this tab.";
  }
  if (urlscan.reportUrl) {
    return "The inline summary is ready, and you can open the public urlscan.io result if you want the full page.";
  }
  if (urlscan.status === "complete" || urlscan.status === "empty") {
    return "ThreatLens kept the urlscan.io search inside the popup instead of sending you to raw JSON.";
  }
  if (urlscan.status === "error") {
    return "urlscan.io could not be reached for this request.";
  }
  return "Run urlscan.io when you want a second opinion on the URL.";
}

function getVirusTotalState(reputation) {
  switch (reputation.status) {
    case "loading":
      return "Searching";
    case "queued":
      return "Queued";
    case "not_configured":
      return "Setup";
    case "error":
      return "Retry";
    case "complete":
      return "Ready";
    default:
      if (reputation.reportUrl || reputation.analysisUrl || reputation.verdict === "clean" || reputation.verdict === "malicious" || reputation.verdict === "suspicious") {
        return "Ready";
      }
      return "Idle";
  }
}

function getUrlscanState(urlscan) {
  switch (urlscan.status) {
    case "loading":
      return "Scanning";
    case "complete":
      return "Ready";
    case "empty":
      return "No Match";
    case "error":
      return "Retry";
    default:
      return "Idle";
  }
}

function isOsintBusy(record) {
  return busyAction === "check-reputation" || busyAction === "virustotal" || isVirusTotalPending(record?.reputation);
}

function isUrlscanBusy(record) {
  return busyAction === "urlscan" || record?.providerReports?.urlscan?.status === "loading";
}

function isSandboxBusy(record) {
  return busyAction === "sandbox-scan" || record?.reputation?.hybridAnalysis?.status === "loading";
}

function getToneClassFromIndicator(indicator) {
  const i = String(indicator || "").toLowerCase();
  if (i === "analyzing" || i === "checking") return "tone-checking";
  if (i === "malicious" || i === "blocked") return "tone-critical";
  if (i === "elevated" || i === "suspicious") return "tone-warning";
  if (i === "reviewed" || i === "clean" || i === "trusted") return "tone-good";
  return "tone-neutral";
}

function getToneClass(record) {
  // Use live indicator — not stored riskIndicator
  return getToneClassFromIndicator(computeLiveIndicator(record));
}

function getDisabledState() {
  return busyAction ? "disabled" : "";
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!value) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size >= 10 || unitIndex === 0 ? Math.round(size) : size.toFixed(1)} ${units[unitIndex]}`;
}

function attemptSurfaceClose() {
  try {
    window.close();
  } catch {
    // Ignore. Full-page extension contexts cannot always close themselves.
  }
}

/**
 * Computes the risk indicator fresh from live record fields at render time.
 * Never reads record.riskIndicator from storage — that value is written by
 * background workers at different points in time and may be stale (e.g. URL
 * scan writes "Reviewed" before hash scan writes "Malicious").
 */
function computeLiveIndicator(record) {
  if (!record) return "Unknown";
  
  const reputation = record.reputation || {};
  const urlscan = record.providerReports?.urlscan || {};
  const ipRep = record.providerReports?.ipReputation || {};
  const vtStatus = reputation.status || "idle";
  const hashStatus = record.fileHashStatus || "idle";

  const stats = reputation.stats || {};
  const vtMalicious = Number(stats.malicious || 0);
  const vtSuspicious = Number(stats.suspicious || 0);
  const totalVtEngines = Object.values(stats).reduce((s, v) => s + Number(v || 0), 0);
  const urlscanMalicious = urlscan.verdict === "malicious";
  const urlscanScore = Number(urlscan.score || 0);
  const ipMalicious = Number(ipRep?.stats?.malicious || 0);
  const isNewDomain = record.domainMetadata?.isNewDomain === true;

  const peAnomalies = Array.isArray(record.peAnomalies) ? record.peAnomalies.filter(Boolean) : [];
  const peAnomalyDetails = Array.isArray(record.peAnomalyDetails) ? record.peAnomalyDetails : [];
  const hasHighSeverityPeAnomaly = peAnomalyDetails.some((anomaly) => anomaly?.severity === "high") ||
    peAnomalies.some((anomaly) => /packer|protector|upx|themida|aspack|mpress|vmp|enigma|packed/i.test(String(anomaly)));

  // Definitive threat signals — show immediately regardless of other pending scans
  if (record.isDriveBy || hasHighSeverityPeAnomaly || vtMalicious >= 1 || urlscanMalicious || ipMalicious >= 2) {
    return "Malicious";
  }
  if (vtSuspicious >= 1 || urlscanScore >= 50 || isNewDomain || peAnomalies.length > 0) {
    return "Elevated";
  }

  // If any scan is still running, stay in Checking — don't show "Reviewed/Clean"
  // prematurely (hash scan may still find a malicious result)
  const vtLoading = vtStatus === "loading" || vtStatus === "queued";
  // Only treat "loading" as active — "idle" is the initial state before any
  // hash operation starts and must NOT block the indicator from resolving.
  const hashLoading = hashStatus === "loading";
  const urlscanLoading = urlscan.status === "loading";
  // When VT is complete and hash is complete (or errored/skipped), accept the
  // result. The hash-VT upgrade is best-effort; if VT returned 404 for the hash
  // and fell back to the URL report, that IS the final result.
  if (vtLoading || hashLoading || urlscanLoading) {
    return "Checking";
  }

  // All scans done and nothing flagged
  if (totalVtEngines > 0 || urlscan.status === "complete" || urlscan.status === "empty") {
    return "Reviewed";
  }

  if (vtStatus === "not_configured") {
    return "Unknown";
  }

  return "Checking";
}

function buildIntelVerdictList(record) {
  const reputation = record.reputation || {};
  const vtUrlReport = getVirusTotalUrlReport(record) || {};
  const vtFileReport = getVirusTotalFileReport(record) || {};
  const urlscan = record.providerReports?.urlscan || {};
  const ipRep = record.providerReports?.ipReputation || {};
  const domainAudit = record.domainAudit || {};

  return [
    ...getIntelHeuristicVerdicts(record),
    getIntelSourceVerdict(vtUrlReport, record),
    getIntelIpVerdict(urlscan, ipRep),
    getIntelHashVerdict(record, vtFileReport),
    getIntelFuzzyHashVerdict(record),
    getIntelHaIntelligenceVerdict(record),
    ...getIntelPeVerdicts(record),
    getIntelDomainVerdict(record, reputation, domainAudit),
    getIntelSignatureVerdict(record, vtFileReport),
    getIntelEntropyVerdict(record),
    getIntelOverallVerdict(record)
  ].filter(Boolean);
}

function getIntelHeuristicVerdicts(record) {
  const verdicts = [];
  if (record.isDriveBy) {
    verdicts.push({ title: "Attack Vector", desc: "Drive-by behavior detected; no trusted human click occurred within 2 seconds of download initiation.", status: "danger" });
  }
  return verdicts;
}

function getVirusTotalUrlReport(record) {
  const report = record?.providerReports?.virusTotalUrl;
  if (report) return report;
  const reputation = record?.reputation;
  if (reputation?.provider === "VirusTotal" && (reputation.lookupType === "url" || !reputation.lookupType)) {
    return reputation;
  }
  return null;
}

function getVirusTotalFileReport(record) {
  const report = record?.providerReports?.virusTotalFile;
  if (report) return report;
  const reputation = record?.reputation;
  if (reputation?.provider === "VirusTotal" && reputation.lookupType === "file") {
    return reputation;
  }
  return null;
}

function getIntelSourceVerdict(vtUrlReport, record) {
  const status = vtUrlReport.status || "idle";
  const stats = vtUrlReport.stats || {};
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const total = Object.values(stats).reduce((sum, value) => sum + Number(value || 0), 0);

  if (status === "loading" || status === "queued" || status === "idle") {
    return { title: "Source URL", desc: "Checking destination reputation across global vendors...", status: "pending" };
  }
  if (status === "not_configured") {
    return { title: "Source URL", desc: "VirusTotal key is not configured, so this verdict is limited.", status: "warn" };
  }
  if (status === "complete" && vtUrlReport.summary && vtUrlReport.summary.includes("too long")) {
    return { title: "Source URL", desc: "Global vendor consensus took too long; lookups continued with partial results.", status: "warn" };
  }
  if (status === "error") {
    return { title: "Source URL", desc: "Provider lookup was unavailable for this URL.", status: "warn" };
  }
  if (status === "complete") {
    if (malicious > 0) return { title: "Source URL", desc: `<strong>Malicious (${malicious}/${total || "?"} engines flagged).</strong>`, status: "danger" };
    if (suspicious > 0) return { title: "Source URL", desc: `<strong>Suspicious (${suspicious}/${total || "?"} engines flagged).</strong>`, status: "warn" };
    if (total > 0) {
      return { title: "Source URL", desc: `<strong>Reviewed clean (0/${total} malicious flags).</strong>`, status: "safe" };
    }
    return { title: "Source URL", desc: "URL scanned — no definitive threat intelligence flags found.", status: "safe" };
  }
  return { title: "Source URL", desc: "No definitive provider verdict is available yet.", status: "pending" };
}

function getIntelIpVerdict(urlscan, ipRep) {
  const ip = ipRep.ip || urlscan.pageIp || "";
  const owner = String(ipRep.owner || "").trim();
  const country = String(ipRep.country || "").trim();
  const countrySuffix = country ? ` (${country})` : "";
  const scanStatusRaw = ipRep.scanStatus || ipRep.status || "idle";
  const hasIpStats = ipRep.stats && Object.keys(ipRep.stats).length > 0;
  const scanStatus = hasIpStats ? "complete" : scanStatusRaw;
  const malicious = Number(ipRep.stats?.malicious || 0);
  const suspicious = Number(ipRep.stats?.suspicious || 0);

  if (scanStatus === "loading" || scanStatus === "queued" || scanStatus === "idle") {
    if (owner) return { title: "Server IP", desc: `${ip} owner identified as ${owner}${countrySuffix}. Network threat scan in progress...`, status: "safe" };
    return { title: "Server IP", desc: `${ip} resolved; ASN ownership lookup is in progress...`, status: "pending" };
  }
  if (owner && scanStatus === "complete") {
    if (malicious > 0) return { title: "Server IP", desc: `${ip} is owned by ${owner}${countrySuffix}; flagged malicious by ${malicious} engines.`, status: "danger" };
    if (suspicious > 0) return { title: "Server IP", desc: `${ip} is owned by ${owner}${countrySuffix}; flagged suspicious by ${suspicious} engines.`, status: "warn" };
    if (hasIpStats) return { title: "Server IP", desc: `${ip} is owned by ${owner}${countrySuffix}; no malicious flags detected.`, status: "safe" };
    return { title: "Server IP", desc: `${ip} is owned by ${owner}${countrySuffix}. Network infrastructure identified.`, status: "safe" };
  }
  if (owner && scanStatus === "not_configured") return { title: "Server IP", desc: `${ip} owner identified as ${owner}${countrySuffix}; scan needs API key.`, status: "warn" };
  if (owner && scanStatus === "unsupported") return { title: "Server IP", desc: `${ip} owner identified as ${owner}${countrySuffix}; provider does not support this scan.`, status: "warn" };
  if (owner && scanStatus === "error") return { title: "Server IP", desc: `${ip} owner identified as ${owner}${countrySuffix}; threat scan was unavailable.`, status: "warn" };
  if (scanStatus === "complete") {
    if (malicious > 0) return { title: "Server IP", desc: `${ip} is flagged malicious by ${malicious} engines; ASN owner is not public.`, status: "danger" };
    if (suspicious > 0) return { title: "Server IP", desc: `${ip} is flagged suspicious by ${suspicious} engines; ASN owner is not public.`, status: "warn" };
    if (hasIpStats) return { title: "Server IP", desc: `${ip} completed scan with no malicious flags; ASN owner is not public.`, status: "safe" };
    return { title: "Server IP", desc: `${ip} network infrastructure identified; ASN owner is not public.`, status: "safe" };
  }
  
  if (scanStatus === "error") return { title: "Server IP", desc: `${ip || 'Network'} lookup failed or was unavailable; ASN owner could not be identified.`, status: "warn" };
  return { title: "Server IP", desc: `${ip || 'Network'} infrastructure analysis unavailable.`, status: "warn" };
  if (scanStatus === "not_configured") return { title: "Server IP", desc: `${ip} resolved, but scan needs an API key.`, status: "warn" };
  if (scanStatus === "unsupported") return { title: "Server IP", desc: `${ip} resolved, but provider does not support this scan.`, status: "warn" };
  if (scanStatus === "error") return { title: "Server IP", desc: `${ip} resolved, but owner intelligence was unavailable.`, status: "warn" };
  return { title: "Server IP", desc: `${ip} resolved; awaiting additional network intelligence.`, status: "pending" };
}

function getIntelHashVerdict(record, vtFileReport) {
  const rawHash = record.fileHash;
  const hashValue = (typeof rawHash === "object" && rawHash !== null) ? (rawHash.hash || "") : String(rawHash || "").trim();
  const hashStatus = hashValue ? "complete" : (record.fileHashStatus || "idle");
  const stats = vtFileReport.stats || {};
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const totalEngines = Object.values(stats).reduce((s, v) => s + Number(v || 0), 0);
  const hasVtData = vtFileReport.status === "complete" || Object.keys(stats).length > 0;
  const vtStatus = hasVtData ? "complete" : (vtFileReport.status || "idle");

  if (hashStatus === "loading" || hashStatus === "idle") {
    const progress = record.fileHashProgress ? ` (${record.fileHashProgress})` : "";
    return { title: "SHA-256 Fingerprint", desc: `Generating and correlating file fingerprint${progress}...`, status: "pending" };
  }
  if (hashStatus === "skipped") return { title: "SHA-256 Fingerprint", desc: "Fingerprint generation was skipped for this file profile.", status: "safe" };
  if (hashStatus === "skipped_blob") return { title: "SHA-256 Fingerprint", desc: "File generated securely within isolated browser memory; physical disk extraction not required.", status: "safe" };
  if (hashStatus === "error") return { title: "SHA-256 Fingerprint", desc: "Extraction unavailable (file exceeded 500MB limit or access restricted).", status: "warn" };
  if (hashStatus === "complete" && hashValue) {
    if (vtStatus === "not_configured" || record.reputation?.status === "not_configured") return { title: "SHA-256 Fingerprint", desc: "Fingerprint generated — add a VirusTotal API key to check databases.", status: "warn" };
    if (vtStatus === "loading" || vtStatus === "queued" || vtStatus === "idle") return { title: "SHA-256 Fingerprint", desc: "Fingerprint generated. Cross-referencing with threat databases in background...", status: "safe" };
    if (vtStatus === "error") return { title: "SHA-256 Fingerprint", desc: "Fingerprint generated — VirusTotal scan encountered an error.", status: "warn" };
    if (vtStatus === "not_found") return { title: "SHA-256 Fingerprint", desc: "Fingerprint generated — not found in database (new or unknown file).", status: "safe" };
    if (vtStatus === "complete") {
      if (malicious > 0) return { title: "SHA-256 Fingerprint", desc: `Fingerprint flagged as Malicious by ${malicious} vendor(s).`, status: "danger" };
      if (suspicious > 0) return { title: "SHA-256 Fingerprint", desc: `Fingerprint flagged as Suspicious by ${suspicious} vendor(s).`, status: "warn" };
      if (totalEngines > 0) return { title: "SHA-256 Fingerprint", desc: `Fingerprint checked — 0/${totalEngines} vendors flagged this file.`, status: "safe" };
      return { title: "SHA-256 Fingerprint", desc: "Fingerprint generated — no definitive threat intelligence flags found.", status: "safe" };
    }
    return { title: "SHA-256 Fingerprint", desc: "Fingerprint generated. Cross-referencing with global threat databases...", status: "safe" };
  }
  const progress = record.fileHashProgress ? ` (${record.fileHashProgress})` : "";
  return { title: "SHA-256 Fingerprint", desc: `Downloading to secure sandbox and generating fingerprint${progress}...`, status: "pending" };
}

function getIntelHaIntelligenceVerdict(record) {
  const intelResult = record?.providerReports?.hybridAnalysis;
  if (!intelResult) {
    if (record.fileHashStatus === "loading" || record.fileHashStatus === "idle") {
      return { title: "Hybrid Analysis", desc: "Awaiting fingerprint to query CrowdStrike Falcon databases...", status: "pending" };
    }
    return null;
  }

  if (intelResult.status === "loading") {
    return { title: "Hybrid Analysis", desc: "Querying CrowdStrike Falcon databases for behavioral intelligence...", status: "pending" };
  }
  
  if (intelResult.status === "error") {
    return { title: "Hybrid Analysis", desc: "Could not retrieve intelligence report from provider.", status: "warn" };
  }

  if (intelResult.verdict === "not_found") {
    return { title: "Hybrid Analysis", desc: "No prior sandbox detonation report exists for this file signature.", status: "safe" };
  }

  if (intelResult.status === "complete") {
    const isBad = intelResult.verdict === "malicious" || intelResult.threat_score >= 70;
    const isWarn = intelResult.verdict === "suspicious" || intelResult.threat_score >= 40;
    const score = intelResult.threat_score || 0;
    
    if (isBad) return { title: "Hybrid Analysis", desc: `File previously detonated and flagged as Malicious (Threat Score: ${score}/100).`, status: "danger" };
    if (isWarn) return { title: "Hybrid Analysis", desc: `File previously detonated and flagged as Suspicious (Threat Score: ${score}/100).`, status: "warn" };
    return { title: "Hybrid Analysis", desc: `File previously detonated and reviewed Clean (Threat Score: ${score}/100).`, status: "safe" };
  }
  
  return null;
}

function getIntelFuzzyHashVerdict(record) {
  const tlshResult = record?.providerReports?.tlshLookup;
  
  if (tlshResult && tlshResult.status === "loading") {
    return { title: "Similarity Search", desc: "Searching for related malware clusters using fuzzy hash...", status: "pending" };
  }
  
  if (tlshResult && tlshResult.status === "complete") {
    const count = tlshResult.matchCount || 0;
    if (count > 0) {
      return { title: "Similarity Search", desc: `Found ${count} related file(s) with highly similar structural characteristics.`, status: "warn" };
    }
  }

  if (record.tlshHash) {
    return { title: "Fuzzy Hash (TLSH)", desc: `Locality-sensitive fingerprint generated for polymorphic malware correlation (${escapeHtml(record.tlshHash)}).`, status: "safe" };
  }
  if (!record.tlshHash && (record.fileHashStatus === "loading" || record.fileHashStatus === "idle")) {
    return { title: "Fuzzy Hash (TLSH)", desc: "Generating locality-sensitive fingerprint from byte stream...", status: "pending" };
  }
  return null;
}

function getIntelPeVerdicts(record) {
  const verdicts = [];
  const peAnomalies = Array.isArray(record.peAnomalies) ? record.peAnomalies.filter(Boolean) : [];
  const peSections = Array.isArray(record.peSections) ? record.peSections : [];
  
  const isExe = record.extension && ["exe", "msi", "dll", "app", "dmg", "pkg"].includes(record.extension.toLowerCase().replace(".", ""));
  if (!record.isPeFile && isExe && (record.fileHashStatus === "loading" || record.fileHashStatus === "idle")) {
    verdicts.push({ title: "PE Structure", desc: "Analyzing executable headers and sections...", status: "pending" });
    return verdicts;
  }
  
  if (!record.isPeFile) return verdicts;

  if (peAnomalies.length > 0) {
    verdicts.push({ title: "Structural Anomaly", desc: "File carries a highly anomalous internal structure (e.g., hidden data or packed code) often used by malware.", status: "danger" });
  } else if (peSections.length > 0) {
    verdicts.push({ title: "PE Structure", desc: "Normal code structure and standard section mapping detected.", status: "safe" });
  }
  return verdicts;
}

function getIntelDomainVerdict(record, reputation, domainAudit) {
  const domainMetadata = record.domainMetadata || {};
  const createdAt = domainMetadata.creationDate || null;
  const registrar = domainMetadata.registrar || "";
  const auditStatus = domainAudit.status || "idle";

  if (createdAt) {
    const ageInDays = Math.max(0, (Date.now() - (createdAt * 1000)) / (1000 * 60 * 60 * 24));
    const ageInYears = (ageInDays / 365).toFixed(1);
    if (ageInDays < 90) return { title: "Domain Maturity", desc: `Newly registered domain (${ageInYears} years)${registrar ? ` via ${registrar}` : ""}.`, status: "warn" };
    return { title: "Domain Maturity", desc: `Established domain (${ageInYears} years)${registrar ? ` via ${registrar}` : ""}.`, status: "safe" };
  }
  if (auditStatus === "error") return { title: "Domain Maturity", desc: "RDAP lookup unavailable, registration age could not be confirmed.", status: "warn" };
  if (auditStatus === "complete") return { title: "Domain Maturity", desc: "RDAP completed, but registration age is not publicly exposed.", status: "safe" };
  return { title: "Domain Maturity", desc: "Checking registration history and registrar validity...", status: "pending" };
}

function getIntelSignatureVerdict(record, vtFileReport) {
  const isExe = record.extension && ["exe", "msi", "dll", "app", "dmg", "pkg"].includes(record.extension.toLowerCase().replace(".", ""));
  const hashStatus = record.fileHashStatus || "idle";
  const vtStatus = vtFileReport?.status || "idle";

  if (isExe && (hashStatus === "loading" || hashStatus === "idle" || vtStatus === "loading" || vtStatus === "queued")) {
    return { title: "Digital Signature", desc: "Awaiting fingerprint to verify executable signature...", status: "pending" };
  }

  if (vtFileReport && vtFileReport.details && vtFileReport.details.signatureInfo) {
    const sigInfo = vtFileReport.details.signatureInfo;
    const isSigned = String(sigInfo.verified || "").toLowerCase().includes("signed");
    
    let signersArray = [];
    if (Array.isArray(sigInfo.signers)) signersArray = sigInfo.signers;
    else if (sigInfo.signers) signersArray = String(sigInfo.signers).split(";").map(s => s.trim());
    
    const primarySigner = signersArray.length > 0 ? signersArray[0] : "";
    if (!isSigned && record.extension && ["exe", "msi", "dll", "app", "dmg", "pkg"].includes(record.extension.toLowerCase().replace(".", ""))) {
      return { title: "Digital Signature", desc: "This executable is explicitly unsigned and lacks provenance.", status: "warn" };
    } else if (isSigned) {
      return { title: "Digital Signature", desc: primarySigner ? `Payload is digitally signed by ${primarySigner}.` : `Payload is digitally signed.`, status: "safe" };
    }
  } else if (record.extension && ["exe", "msi", "dll", "app", "dmg", "pkg"].includes(record.extension.toLowerCase().replace(".", ""))) {
    return { title: "Digital Signature", desc: "This executable is unsigned or its signature could not be verified.", status: "warn" };
  }
  return null;
}

function getIntelEntropyVerdict(record) {
  if (record.fileEntropy) {
    if (record.fileEntropy > 7.2) return { title: "Shannon Entropy", desc: `High structural entropy (${record.fileEntropy.toFixed(2)}). Possible packed or encrypted payload.`, status: "danger" };
    if (record.fileEntropy > 6.5) return { title: "Shannon Entropy", desc: `Elevated structural entropy (${record.fileEntropy.toFixed(2)}). File may be compressed.`, status: "warn" };
    return { title: "Shannon Entropy", desc: `Normal code structure detected (${record.fileEntropy.toFixed(2)}).`, status: "safe" };
  }
  const hashStatus = record.fileHashStatus || "idle";
  if (hashStatus === "loading" || hashStatus === "idle") return { title: "Shannon Entropy", desc: "Computing payload entropy...", status: "pending" };
  return null;
}

function getIntelOverallVerdict(record) {
  const indicator = computeLiveIndicator(record).toLowerCase();
  if (indicator === "checking") return { title: "Overall Verdict", desc: "Analysis is in progress; keep this download intercepted.", status: "pending" };
  if (indicator === "malicious") return { title: "Overall Verdict", desc: "High risk detected. Blocking is recommended.", status: "danger" };
  if (indicator === "elevated") return { title: "Overall Verdict", desc: "Elevated risk detected. Verify source before allowing.", status: "warn" };
  if (indicator === "reviewed" || indicator === "trusted") return { title: "Overall Verdict", desc: "Reviewed with no direct malware signal.", status: "safe" };
  return { title: "Overall Verdict", desc: "Insufficient evidence for a definitive recommendation yet.", status: "pending" };
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stripReasonMarkup(value) {
  return String(value || "").replace(/<[^>]*>/g, "");
}

function summarizeReasonText(reason) {
  if (!reason) {
    return "";
  }

  const entries = Array.isArray(reason) ? reason : [reason];
  const cleaned = entries
    .map((entry) => stripReasonMarkup(entry).replace(/\s+/g, " ").trim())
    .filter(Boolean);

  if (!cleaned.length) {
    return "";
  }

  return cleaned[cleaned.length - 1];
}

function isVirusTotalPending(reputation) {
  return reputation?.status === "loading" || reputation?.status === "queued";
}

function escapeAttribute(value) {
  return escapeHtml(value);
}

// ─── DIAGNOSTIC PANEL (remove before release) ───────────────────────────────
async function runDiagnostics() {
  const out = document.getElementById("diag-output");
  if (!out) return;

  const lines = [];

  // 1. Check chrome.storage.managed availability
  lines.push("=== chrome.storage.managed ===");
  if (!chrome.storage.managed) {
    lines.push("❌ chrome.storage.managed is NOT available");
  } else {
    lines.push("✅ chrome.storage.managed is available");
    try {
      const allManaged = await chrome.storage.managed.get(null);
      lines.push("RAW managed.get(null):");
      lines.push(JSON.stringify(allManaged, null, 2));

      const keyed = await chrome.storage.managed.get("threatlens.config");
      lines.push("\nmanaged.get('threatlens.config'):");
      lines.push(JSON.stringify(keyed, null, 2));
    } catch (e) {
      lines.push("❌ Error reading managed storage: " + e.message);
    }
  }

  // 2. Check what storageManager resolved as effective config
  lines.push("\n=== Resolved Config (storageManager.getConfig) ===");
  try {
    const cfg = await storageManager.getConfig();
    lines.push("allowlist.domains: " + JSON.stringify(cfg.allowlist?.domains));
    lines.push("allowlist.urls:    " + JSON.stringify(cfg.allowlist?.urls));
    lines.push("blocklist.domains: " + JSON.stringify(cfg.blocklist?.domains));
    lines.push("blocklist.urls:    " + JSON.stringify(cfg.blocklist?.urls));
  } catch (e) {
    lines.push("❌ Error: " + e.message);
  }

  // 3. chrome.storage.local raw
  lines.push("\n=== chrome.storage.local['threatlens.config'] ===");
  try {
    const local = await chrome.storage.local.get("threatlens.config");
    lines.push(JSON.stringify(local, null, 2));
  } catch (e) {
    lines.push("❌ " + e.message);
  }

  out.textContent = lines.join("\n");
}

// Wire up diagnostic panel — auto-run when About tab is clicked, and on refresh button
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("diag-refresh-btn")?.addEventListener("click", runDiagnostics);
  document.querySelectorAll(".tab-button").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.sectionTarget === "about") setTimeout(runDiagnostics, 100);
    });
  });
});
// ─── END DIAGNOSTIC PANEL ────────────────────────────────────────────────────
