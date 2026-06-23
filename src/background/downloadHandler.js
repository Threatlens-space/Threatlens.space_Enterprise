import { storageManager } from "../shared/storageManager.js";
import {
  buildDownloadRecord,
  createInitialReputationState,
  getSearchableUrl,
  getBestScanUrl,
  calculateFileHash,
  isHighRiskExtension,
  isEphemeralUrl
} from "../shared/utils.js";
import { evaluateDownload } from "./rulesEngine.js";
import { calculateUnifiedVerdict, openManualProvider, runVirusTotalLookup, pollVirusTotalResult, getStreamingReasons, fetchRdapDomain, runVirusTotalIpLookup, fetchRdapIp } from "./reputationService.js";
import {
  submitUrlForSandbox, fetchHybridAnalysisOverview,
  fetchHaOverview, fetchHaReport, submitFileForSandbox,
  pollSandboxState, searchSimilarTo, normalizeHaIntelligenceReport,
  normalizeTlshResults, deduplicateHaRequest, validateHash
} from "./hybridAnalysis.js";

const filenameHolds = new Map();
const cleanupTimers = new Map();
const pauseEnforcementTimers = new Map();
const pauseEnforcementMeta = new Map();
const enforcementInFlight = new Set();
const approvedReplayTokens = [];
const replayedDownloads = new Map();
const pendingReplaysByUrl = new Map();
/**
 * Tracks downloads that were quarantined via pause-and-hold (not cancel+erase).
 * These come from ephemeral URLs (blob:, signed CDN tokens) that cannot be
 * replayed — we must resume the original Chrome download instead.
 */
const heldEphemeralDownloads = new Map(); // downloadId → true
const activeScanWorkers = new Set();
let cachedConfig = null;
const DEBUG_LOG_KEY = "threatlens.debugLog";
const MAX_DEBUG_ENTRIES = 200;
const HUMAN_CLICK_WINDOW_MS = 2_000;
const CLICK_CONTEXT_TIMEOUT_MS = 500;
const CLICK_CONTEXT_MESSAGE = "threatlens:get-time-since-last-click";

// Static AI: Download velocity tracker
const recentDownloadTimestamps = [];
const downloadClickContextPromises = new Map();

// Batched diagnostic log buffer — flushed every 2 seconds to reduce storage IPC.
const _diagBuffer = [];
let _diagFlushTimer = null;

const AUDIT_WEBHOOK_URL = "https://script.google.com/macros/s/AKfycbz1wg9rKQHu89NbVkywcCUob8J8APkWZdmlr8atFfDKo4DOEwPRbY9s5oVBlFQXPIHb6A/exec";
let _cachedUserEmail = null;

// ---------------------------------------------------------------------------
// LIFECYCLE BINDING
// CRITICAL SECURITY FIX: Event listeners MUST be bound synchronously at the
// top level. If they are bound inside an async function after an 'await', the
// service worker will miss the very event that woke it up from sleep,
// resulting in a silent bypass / "auto-allow" of the download.
// ---------------------------------------------------------------------------
chrome.downloads.onDeterminingFilename.addListener(handleDeterminingFilename);
chrome.downloads.onCreated.addListener(handleDownloadCreated);
chrome.downloads.onChanged.addListener(handleDownloadChanged);
chrome.runtime.onMessage.addListener(handleRuntimeMessage);

export async function initializeDownloadHandler() {
  cachedConfig = await storageManager.getConfig();
  
  // Listen for config changes to keep the cache fresh
  chrome.storage.onChanged.addListener(async (changes, area) => {
    if (changes["threatlens.config"]) {
      cachedConfig = await storageManager.getConfig();
    }
  });
}

/**
 * Called automatically when the user saves a new VirusTotal API key.
 * Finds all pending downloads that haven't been scanned yet and kicks
 * off OSINT lookups for each — so the user never has to click manually.
 */
export async function triggerPendingScanOnKeyChange() {
  const config = await storageManager.getConfig();
  const hasKey = Boolean(String(config?.integrations?.virusTotal?.apiKey || "").trim());
  if (!hasKey) return;

  const pending = await storageManager.listPendingDownloads();
  const unscanned = pending.filter(
    (r) =>
      (r.status === "awaiting_user" || r.status === "checking_reputation") &&
      r.reputation?.status !== "complete" &&
      r.reputation?.status !== "loading"
  );

  console.log(`[ThreatLens] API key detected — auto-scanning ${unscanned.length} pending download(s)`);

  for (const record of unscanned) {
    void maybeAutoLookupReputation(record.downloadId, config);
  }
}

// Badge updates are handled centrally by the service-worker's syncActionState()
// via chrome.storage.onChanged. No duplicate updateBadge() needed here.

export async function recoverPendingDownloads() {
  const pendingDownloads = await storageManager.listPendingDownloads();
  if (pendingDownloads.length > 0) {
    console.log(`[ThreatLens] Recovered ${pendingDownloads.length} pending download(s) from previous session.`);
  }

  const ORPHAN_THRESHOLD_MS = 2 * 60 * 1000; // 2 minutes
  const now = Date.now();

  for (const record of pendingDownloads) {
    // Clean orphaned terminal records from previous sessions — these had their
    // in-memory cleanup timers wiped when the service worker restarted.
    const isTerminal = record.status === "allowed" || record.status === "blocked_rule" || record.status === "blocked_user";
    if (isTerminal) {
      const recordAge = now - new Date(record.updatedAt || record.createdAt).getTime();
      if (recordAge > ORPHAN_THRESHOLD_MS) {
        await storageManager.removePendingDownload(record.downloadId);
        console.log(`[ThreatLens] Cleaned orphaned ${record.status} record: ${record.downloadId}`);
      }
      continue;
    }

    const isPendingDecision =
      record.status === "awaiting_user" || record.status === "checking_reputation";

    if (!isPendingDecision) {
      continue;
    }

    if (record.originalCanceled || record.resumeStrategy === "replay") {
      continue;
    }

    if (!record.holdOriginalDownload) {
      await storageManager.patchPendingDownload(record.downloadId, {
        holdOriginalDownload: true,
        enforcementMode: "hold"
      });
      void logDownloadDiagnostic(record.downloadId, "recovered_missing_hold_state", {
        previousStatus: record.status
      }, "warn", true);
    }

    // Only arm pause enforcement if the download still exists and is in progress.
    // Recovered downloads from previous sessions may no longer exist in Chrome's
    // download manager — calling pause on a non-existent download throws
    // "Download must be in progress" and crashes the handler chain.
    const runtimeState = await getDownloadRuntimeState(record.downloadId);
    if (runtimeState && runtimeState.state === "in_progress" && !runtimeState.paused) {
      armPauseEnforcement(record.downloadId);
      void safePause(record.downloadId);
    } else if (!runtimeState) {
      // Download no longer exists in Chrome — mark as orphaned so RDAP/scans still run
      void logDownloadDiagnostic(record.downloadId, "recovered_download_missing_from_chrome", {
        previousStatus: record.status
      }, "warn", true);
    }
  }
}

/**
 * Iterates through all downloads that were interrupted during a service worker
 * restart and re-triggers their background analytical lookups.
 */
export async function resumeAutomaticScans() {
  const config = await storageManager.getConfig();
  const pending = await storageManager.listPendingDownloads();
  
  const interrupted = pending.filter(r => 
    r.status === "awaiting_user" || r.status === "checking_reputation"
  );

  if (interrupted.length > 0) {
    console.log(`[ThreatLens] Resuming scans for ${interrupted.length} interrupted download(s)`);
    for (const record of interrupted) {
      // Only reset states that are genuinely stuck in "loading" from a dead
      // service worker. NEVER touch "complete" or "error" — those are real
      // results that must survive restarts unchanged.
      const stalePatch = {};

      if (record.fileHashStatus === "loading") {
        stalePatch.fileHashStatus = "idle";
      }
      if (record.reputation?.status === "loading") {
        stalePatch.reputation = { ...record.reputation, status: "idle" };
      }
      if (record.providerReports?.urlscan?.status === "loading") {
        stalePatch.providerReports = {
          ...record.providerReports,
          urlscan: { ...record.providerReports.urlscan, status: "idle" }
        };
      }
      if (record.providerReports?.ipReputation?.status === "loading") {
        stalePatch.providerReports = {
          ...(stalePatch.providerReports || record.providerReports),
          ipReputation: { ...record.providerReports.ipReputation, status: "idle" }
        };
      }
      if (record.domainAudit?.status === "loading") {
        stalePatch.domainAudit = { status: "idle" };
      }

      if (record.providerReports?.hybridAnalysis?.status === "loading") {
        stalePatch.providerReports = {
          ...(stalePatch.providerReports || record.providerReports),
          hybridAnalysis: { ...record.providerReports.hybridAnalysis, status: "idle" }
        };
      }

      if (Object.keys(stalePatch).length > 0) {
        await storageManager.patchPendingDownload(record.downloadId, stalePatch);
      }

      // Re-read after patch so the retry guards see the updated state
      const freshRecord = await storageManager.getPendingDownload(record.downloadId);
      if (!freshRecord) continue;

      // Only resume if something is genuinely incomplete — if everything is
      // already complete, preserve the results and do nothing.
      const vtDone = freshRecord.reputation?.status === "complete" || freshRecord.reputation?.status === "error" || freshRecord.reputation?.status === "not_configured";
      const urlscanDone = freshRecord.providerReports?.urlscan?.status === "complete" || freshRecord.providerReports?.urlscan?.status === "empty" || freshRecord.providerReports?.urlscan?.status === "error";
      const hashDone = freshRecord.fileHashStatus === "complete" || freshRecord.fileHashStatus === "error";
      const ipDone = freshRecord.providerReports?.ipReputation?.status === "complete" || freshRecord.providerReports?.ipReputation?.status === "error" || freshRecord.providerReports?.ipReputation?.status === "not_configured";
      const domainDone = freshRecord.domainAudit?.status === "complete" || freshRecord.domainAudit?.status === "error" || Boolean(freshRecord.domainMetadata);

      if (vtDone && urlscanDone && hashDone && ipDone && domainDone) {
        console.log(`[ThreatLens] All scans complete for ${record.downloadId} — preserving results`);
        continue;
      }

      void maybeAutoLookupReputation(record.downloadId, config);
    }
  }

  // Resume any in-flight Hybrid Analysis sandbox polling jobs
  void resumeHaSandboxJobs();
}

function handleDeterminingFilename(downloadItem, suggest) {
  try {
    // If this is a replayed download, Chrome is asking us to finalize the filename
    // before opening the Save As dialog. We must call suggest() so it proceeds.
    if (replayedDownloads.has(downloadItem.id) || consumeApprovedReplay(downloadItem) || downloadItem.byExtensionId === chrome.runtime.id) {
      suggest();
      return true;
    }

    storeDownloadClickContextPromise(downloadItem);

    // Fast-path bypass for allowlisted or pause_after_suggest items to prevent unnecessary interception
    if (cachedConfig) {
      const evaluation = evaluateDownload(downloadItem, cachedConfig);
      if (evaluation.verdict === "allow") {
        suggest();
        return true;
      }
      if (evaluation.requiresPauseStrategy) {
        // Fix for one-time tokens: suggest() immediately to determine filename and prevent Chrome timeout,
        // then explicitly pause the download to hold it safely without dropping the network state prematurely.
        suggest();
        armPauseEnforcement(downloadItem.id);
        void safePause(downloadItem.id);
        void logDownloadDiagnostic(downloadItem.id, "filename_suggested_then_paused", {
          url: downloadItem.url
        }, "info", true);
        return true;
      }
    }

    filenameHolds.set(downloadItem.id, { suggest });
    void logDownloadDiagnostic(downloadItem.id, "filename_hold_registered", {
      url: downloadItem.url,
      finalUrl: downloadItem.finalUrl
    }, "info", true);
    armPauseEnforcement(downloadItem.id);
    void safePause(downloadItem.id);
    return true;
  } catch (error) {
    console.warn("[ThreatLens] Determining filename failed:", error);
    void logDownloadDiagnostic(downloadItem.id, "filename_hold_failed", {
      error: error?.message || String(error)
    }, "error", true);
    try {
      filenameHolds.set(downloadItem.id, { suggest });
      armPauseEnforcement(downloadItem.id);
      void safePause(downloadItem.id);
    } catch {
      // Keep safest-possible behavior even if we fail to store the hold.
    }
    return true;
  }
}

async function handleDownloadCreated(downloadItem) {
  try {
    console.log(`[ThreatLens] Intercepting download: ${downloadItem.id} (${downloadItem.url})`);

    // Static AI: Download Velocity Tracking
    const now = Date.now();
    recentDownloadTimestamps.push(now);
    // Remove timestamps older than 5 seconds
    while (recentDownloadTimestamps.length > 0 && now - recentDownloadTimestamps[0] > 5000) {
      recentDownloadTimestamps.shift();
    }

    if (downloadItem.byExtensionId === chrome.runtime.id) {
      const targetUrl = downloadItem.finalUrl || downloadItem.url;
      const originalRecord = pendingReplaysByUrl.get(getSearchableUrl(targetUrl));
      if (originalRecord) {
        replayedDownloads.set(downloadItem.id, originalRecord);
        pendingReplaysByUrl.delete(getSearchableUrl(targetUrl));
      }
      return;
    }

    if (consumeApprovedReplay(downloadItem)) {
      const targetUrl = downloadItem.finalUrl || downloadItem.url;
      const originalRecord = pendingReplaysByUrl.get(getSearchableUrl(targetUrl));
      if (originalRecord) {
        replayedDownloads.set(downloadItem.id, originalRecord);
        pendingReplaysByUrl.delete(getSearchableUrl(targetUrl));
      }
      return;
    }

    // 🔥 SECURITY FIX: Synchronously evaluate and pause. 
    // If the cache is empty (cold start), we MUST aggressively pause it 
    // BEFORE the `await` so small files don't complete and bypass the extension.
    if (cachedConfig) {
      const evalFast = evaluateDownload(downloadItem, cachedConfig);
      if (evalFast.verdict !== "allow" && !evalFast.requiresPauseStrategy) {
        armPauseEnforcement(downloadItem.id);
        chrome.downloads.pause(downloadItem.id, () => { void chrome.runtime.lastError; });
      }
    } else {
      armPauseEnforcement(downloadItem.id);
      chrome.downloads.pause(downloadItem.id, () => { void chrome.runtime.lastError; }); // Cold start: pause everything until config loads
    }

    const config = cachedConfig || await storageManager.getConfig();
    let evaluation = evaluateDownload(downloadItem, config);
    
    // Static AI: Velocity override
    // If >= 5 downloads within 5 seconds, override evaluation to block
    if (recentDownloadTimestamps.length >= 5) {
      evaluation = {
        verdict: "block",
        riskIndicator: "Malicious",
        reason: "Auto-blocked: Detected rapid, script-driven download behavior typical of malware droppers.",
        match: { typeLabel: "AI Velocity", value: "Rapid Downloads" },
        requiresPauseStrategy: false
      };
    }
    
    // If auto-allowed or requires pause_after_suggest, bypass the initial aggressive pause enforcement.
    // For pause_after_suggest, we handle the pause *after* suggest() in onDeterminingFilename to avoid deadlocking Chrome.
    if (evaluation.verdict !== "allow" && !evaluation.requiresPauseStrategy) {
      armPauseEnforcement(downloadItem.id);
      void safePause(downloadItem.id);
    }
    const clickContext = await getDownloadClickContext(downloadItem);
    const record = {
      ...buildDownloadRecord(downloadItem, evaluation),
      ...clickContext
    };
    const requiresUserDecision = evaluation.verdict === "prompt";
    const pendingRecord = requiresUserDecision
      ? {
          ...record,
          status: "awaiting_user",
          decision: null,
          decisionSource: null,
          holdOriginalDownload: true,
          enforcementMode: "hold"
        }
      : record;

    await storageManager.savePendingDownload(pendingRecord);
    await storageManager.incrementStats({
      downloadsChecked: 1
    });

    switch (evaluation.verdict) {
      case "allow": {
        await storageManager.incrementStats({ autoAllowed: 1 });
        heldEphemeralDownloads.delete(downloadItem.id);
        disarmPauseEnforcement(downloadItem.id);
        await storageManager.patchPendingDownload(downloadItem.id, {
          status: "allowed",
          decision: "allow",
          decisionSource: "rule",
          holdOriginalDownload: false
        });
        const allowedRecord = await storageManager.getPendingDownload(downloadItem.id);
        if (allowedRecord) {
          void publishAuditWebhook(allowedRecord, "auto_allow");
        }
        resolveFilenameHold(downloadItem.id);
        await safeResume(downloadItem.id);
        schedulePendingCleanup(downloadItem.id, 60_000);
        break;
      }
      case "block": {
        await storageManager.incrementStats({ autoBlocked: 1 });
        disarmPauseEnforcement(downloadItem.id);
        await quarantineOriginalDownload(downloadItem.id);
        const blockedRecord = await storageManager.patchPendingDownload(downloadItem.id, {
          status: "blocked_rule",
          decision: "block"
        });
        if (blockedRecord) {
          void publishAuditWebhook(blockedRecord, "auto_block");
          await displayBlockedWarning(blockedRecord);
          schedulePendingCleanup(downloadItem.id);
        }
        break;
      }
      default: {
        await storageManager.incrementStats({ prompted: 1 });

        const isEphemeral = (
          isEphemeralUrl(downloadItem.url) ||
          isEphemeralUrl(downloadItem.finalUrl)
        );

        disarmPauseEnforcement(downloadItem.id);
        heldEphemeralDownloads.delete(downloadItem.id);

        let statusPatch;
        if (evaluation.requiresPauseStrategy) {
          statusPatch = {
            status: "awaiting_user",
            isEphemeral,
            holdOriginalDownload: true,
            enforcementMode: "hold",
            originalCanceled: false,
            resumeStrategy: "pause_after_suggest"
          };
          void logDownloadDiagnostic(downloadItem.id, "prompt_paused_after_suggest", {
            isEphemeral,
            url: downloadItem.url,
            reason: "Detected strict one-time token URL, using safe pause_after_suggest strategy"
          }, "info", true);
        } else {
          await quarantineOriginalDownload(downloadItem.id);
          statusPatch = {
            status: "awaiting_user",
            isEphemeral,
            holdOriginalDownload: false,
            enforcementMode: "replay",
            originalCanceled: true,
            resumeStrategy: "replay"
          };
        }

        const awaitingRecord = await storageManager.patchPendingDownload(downloadItem.id, statusPatch);
        if (awaitingRecord) {
          if (!evaluation.requiresPauseStrategy) {
            void logDownloadDiagnostic(downloadItem.id, "prompt_quarantined_for_review", {
              isEphemeral,
              suggestedVerdict: evaluation.verdict,
              url: downloadItem.url,
              finalUrl: downloadItem.finalUrl
            }, "warn", true);
          }
          await promptForDecision(awaitingRecord);
          await maybeAutoLookupReputation(awaitingRecord.downloadId, config);
        }

        break;
      }
    }
  } catch (error) {
    console.error("[ThreatLens] Critical failure in download interception:", error);
    try {
      armPauseEnforcement(downloadItem.id);
      await safePause(downloadItem.id);
    } catch {
      // Prefer a stuck download over a silent auto-allow.
    }
  }
}

function storeDownloadClickContextPromise(downloadItem) {
  const promise = captureDownloadClickContext(downloadItem);
  downloadClickContextPromises.set(downloadItem.id, promise);
  void promise.finally(() => {
    setTimeout(() => {
      if (downloadClickContextPromises.get(downloadItem.id) === promise) {
        downloadClickContextPromises.delete(downloadItem.id);
      }
    }, 10_000);
  });
}

async function getDownloadClickContext(downloadItem) {
  if (downloadClickContextPromises.has(downloadItem.id)) {
    const context = await downloadClickContextPromises.get(downloadItem.id);
    downloadClickContextPromises.delete(downloadItem.id);
    return context;
  }

  return captureDownloadClickContext(downloadItem);
}

async function captureDownloadClickContext(downloadItem) {
  const checkedAt = Date.now();
  const unavailableContext = {
    isDriveBy: false,
    timeSinceLastClick: null,
    lastHumanClickAt: null,
    clickMonitorStatus: "unavailable",
    clickMonitorCheckedAt: new Date(checkedAt).toISOString()
  };

  try {
    const response = await withTimeout(queryClickMonitor(downloadItem), CLICK_CONTEXT_TIMEOUT_MS, null);
    if (!response?.ok) {
      return unavailableContext;
    }

    const timeSinceLastClick = Number.isFinite(response.timeSinceLastClick)
      ? response.timeSinceLastClick
      : null;
    const lastHumanClickAt = Number.isFinite(response.lastHumanClickAt)
      ? response.lastHumanClickAt
      : null;
    const hasRecentHumanClick = timeSinceLastClick !== null && timeSinceLastClick <= HUMAN_CLICK_WINDOW_MS;

    return {
      isDriveBy: !hasRecentHumanClick,
      timeSinceLastClick,
      lastHumanClickAt,
      clickMonitorStatus: "observed",
      clickMonitorCheckedAt: new Date(checkedAt).toISOString()
    };
  } catch {
    return unavailableContext;
  }
}

async function queryClickMonitor(downloadItem) {
  const candidateTabIds = await getClickMonitorCandidateTabIds(downloadItem);

  for (const tabId of candidateTabIds) {
    try {
      const response = await chrome.tabs.sendMessage(tabId, {
        type: CLICK_CONTEXT_MESSAGE
      });
      if (response?.ok) {
        return response;
      }
    } catch {
      // Some browser/system pages cannot receive content-script messages.
    }
  }

  return null;
}

async function getClickMonitorCandidateTabIds(downloadItem) {
  const tabIds = [];
  if (Number.isInteger(downloadItem?.tabId) && downloadItem.tabId >= 0) {
    tabIds.push(downloadItem.tabId);
  }

  try {
    const activeTabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const activeTabId = activeTabs?.[0]?.id;
    if (Number.isInteger(activeTabId) && !tabIds.includes(activeTabId)) {
      tabIds.push(activeTabId);
    }
  } catch {
    // If tabs.query is unavailable, the originating tab id above is still enough.
  }

  return tabIds;
}

function withTimeout(promise, timeoutMs, fallbackValue) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(fallbackValue), timeoutMs);
    Promise.resolve(promise)
      .then((value) => resolve(value))
      .catch(() => resolve(fallbackValue))
      .finally(() => clearTimeout(timer));
  });
}

async function handleDownloadChanged(delta) {
  const originalRecord = replayedDownloads.get(delta.id);

  // The 'filename' delta occurs when the native Save As dialog is completed.
  // We keep the ThreatLens prompt visible through the entire process and dismiss
  // it as soon as Chrome finalizes the filename or completes/fails the download.
  if (
    originalRecord &&
    (delta.filename || delta.state?.current === "interrupted" || delta.state?.current === "complete")
  ) {
    replayedDownloads.delete(delta.id);
    void finalizeAllowedReplay(originalRecord);
  }

  const record = await storageManager.getPendingDownload(delta.id);
  if (!record) {
    return;
  }

  if (record.status === "allowed" && delta.state?.current === "complete") {
    disarmPauseEnforcement(delta.id);
    await storageManager.removePendingDownload(delta.id);
    return;
  }

  if (record.status === "allowed" && delta.state?.current === "interrupted") {
    disarmPauseEnforcement(delta.id);
    await storageManager.removePendingDownload(delta.id);
    return;
  }

  if (
    record.holdOriginalDownload &&
    (record.status === "awaiting_user" || record.status === "checking_reputation") &&
    (delta.paused?.current === false || delta.state?.current === "in_progress")
  ) {
    armPauseEnforcement(delta.id);
    void safePause(delta.id);
  }

  if (delta.state?.current === "complete" && record.status !== "allowed") {
    disarmPauseEnforcement(delta.id);
    await removeFileIfPresent(delta.id);
    await eraseDownload(delta.id);
    const blockedRecord = await storageManager.patchPendingDownload(delta.id, {
      status: "blocked_rule",
      decision: "block",
      riskIndicator: "Malicious",
      reason: "ThreatLens removed a download that completed before approval."
    });

    if (blockedRecord) {
      await displayBlockedWarning(blockedRecord);
      schedulePendingCleanup(delta.id);
    }

    return;
  }
}

function handleRuntimeMessage(message, _sender, sendResponse) {
  if (!message?.type) {
    return false;
  }

  if (message.type === "threatlens:download-action") {
    void handleUserAction(message.downloadId, message.action)
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === "threatlens:open-provider") {
    void handleProviderOpen(message.downloadId, message.provider)
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }


  if (message.type === "threatlens:advanced-scan") {
    void handleAdvancedScan(message.downloadId)
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === "threatlens:sandbox-scan") {
    void handleSandboxScan(message.downloadId, message.envId)
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  // Sent by prompt.js to ensure scans resume when the review window is open.
  // Without this handler, the message falls through unhandled, prompt.js treats
  // the undefined response as a failure, and retries on every render (busy loop).
  if (message.type === "threatlens:ensure-automatic-scan") {
    void (async () => {
      try {
        const config = cachedConfig || await storageManager.getConfig();
        await maybeAutoLookupReputation(message.downloadId, config);
        sendResponse({ ok: true });
      } catch (error) {
        sendResponse({ ok: false, error: error.message });
      }
    })();
    return true;
  }

  return false;
}

async function handleSandboxScan(downloadId, explicitEnvId = null) {
  const config = await storageManager.getConfig();
  const haKey = String(config.integrations?.hybridAnalysis?.apiKey || "").trim();
  if (!haKey) {
    throw new Error("Hybrid Analysis API key is not configured. Add it in Settings → Hybrid Analysis.");
  }

  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) {
    throw new Error("Download record not found.");
  }

  // Prevent duplicate sandbox jobs
  if (record.sandboxJob && ["submitting", "queued", "running", "processing"].includes(record.sandboxJob.status)) {
    return { status: record.sandboxJob.status };
  }

  // Create initial sandbox job state
  const sandboxJob = {
    status: "submitting",
    jobId: null,
    sha256: null,
    environmentId: 120,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    apiCallCount: 0,
    rateLimitHitCount: 0,
    pollCount: 0,
    pollIntervalMs: 5000,
    errorCode: null,
    errorMessage: null,
    result: null
  };

  await storageManager.patchPendingDownload(downloadId, { sandboxJob });

  try {
    // We do NOT check for an existing overview here.
    // This is a manual user action ("Run Sandbox Analysis"), so we respect the user's
    // explicit intent to force a VM detonation and submit the file/URL directly.

    // Step 2: Submit file for sandbox analysis
    const urlsToTry = [record.finalUrl, record.originalUrl, record.sourceUrl].filter(Boolean);
    const uniqueUrls = [...new Set(urlsToTry)].filter(u => u && !u.startsWith("blob:") && !u.startsWith("data:"));

    if (uniqueUrls.length === 0) {
      sandboxJob.status = "failed";
      sandboxJob.errorCode = "no_submittable_url";
      sandboxJob.errorMessage = "No downloadable URL available for sandbox submission (blob/data URLs cannot be re-fetched).";
      sandboxJob.updatedAt = new Date().toISOString();
      await storageManager.patchPendingDownload(downloadId, { sandboxJob });
      throw new Error(sandboxJob.errorMessage);
    }

    // Attempt to fetch the file binary
    let fileBlob = null;
    for (const u of uniqueUrls) {
      try {
        const resp = await fetch(u, { credentials: "omit", redirect: "follow" });
        if (resp.ok) {
          fileBlob = await resp.blob();
          break;
        }
      } catch { /* try next URL */ }
    }

    if (!fileBlob) {
      // Fallback: submit URL instead of file
      try {
        const urlToScan = getBestScanUrl(record);
        const urlResult = await submitUrlForSandbox(urlToScan, haKey);
        if (urlResult) {
          const jobId = urlResult.job_id || urlResult.id || urlResult.sha256;
          sandboxJob.status = "queued";
          sandboxJob.jobId = jobId;
          sandboxJob.updatedAt = new Date().toISOString();
          await storageManager.patchPendingDownload(downloadId, { sandboxJob });
          void startPollingEngine(downloadId, jobId, haKey);
          return { status: "queued", jobId };
        }
      } catch (urlErr) {
        console.warn("[ThreatLens HA] URL submission fallback failed:", urlErr.message);
      }
      sandboxJob.status = "failed";
      sandboxJob.errorCode = "file_unavailable";
      sandboxJob.errorMessage = "Could not download the file for sandbox submission (CORS or access restriction).";
      sandboxJob.updatedAt = new Date().toISOString();
      await storageManager.patchPendingDownload(downloadId, { sandboxJob });
      throw new Error(sandboxJob.errorMessage);
    }

    // Determine environment based on file type or explicit user selection
    const determineEnvironmentId = (fileName) => {
      if (explicitEnvId) return explicitEnvId; // User override
      if (!fileName) return 160; // Default Windows 10 64-bit
      const ext = fileName.split('.').pop().toLowerCase();
      switch (ext) {
        case 'dmg':
        case 'pkg':
        case 'app':
        case 'ipa':
          return 430; // macOS
        case 'apk':
          return 200; // Android
        case 'elf':
        case 'deb':
        case 'rpm':
        case 'sh':
          return 330; // Linux
        default:
          return 160; // Default Windows 10 64-bit
      }
    };

    const envId = determineEnvironmentId(record.fileName);

    // Submit the file
    sandboxJob.apiCallCount++;
    const submission = await submitFileForSandbox(
      fileBlob, record.fileName || "unknown", envId, haKey
    );

    if (!submission.ok) {
      sandboxJob.status = "failed";
      sandboxJob.errorCode = submission.errorCode || "submission_error";
      sandboxJob.errorMessage = submission.message || "Sandbox submission failed.";
      sandboxJob.updatedAt = new Date().toISOString();
      await storageManager.patchPendingDownload(downloadId, { sandboxJob });
      throw new Error(sandboxJob.errorMessage);
    }

    const jobId = submission.data?.job_id || submission.data?.id || submission.data?.sha256;
    sandboxJob.status = "queued";
    sandboxJob.jobId = jobId;
    sandboxJob.sha256 = submission.data?.sha256 || ((typeof record.fileHash === "object" && record.fileHash !== null) ? (record.fileHash.hash || "") : String(record.fileHash || ""));
    sandboxJob.updatedAt = new Date().toISOString();
    await storageManager.patchPendingDownload(downloadId, { sandboxJob });

    // Step 3: Start polling engine
    void startPollingEngine(downloadId, jobId, haKey);
    return { status: "queued", jobId };

  } catch (error) {
    // Only update if not already set
    const latest = await storageManager.getPendingDownload(downloadId);
    if (latest && latest.sandboxJob?.status === "submitting") {
      await storageManager.patchPendingDownload(downloadId, {
        sandboxJob: {
          ...latest.sandboxJob,
          status: "failed",
          errorCode: "submission_error",
          errorMessage: error.message,
          updatedAt: new Date().toISOString()
        }
      });
    }
    throw error;
  }
}

/**
 * Exponential-backoff polling engine for sandbox job completion.
 * Polls /report/{jobId}/state until completed, timeout, or max polls.
 */
async function startPollingEngine(downloadId, jobId, apiKey) {
  const workerKey = `ha-poll-${downloadId}`;
  if (activeScanWorkers.has(workerKey)) return;
  activeScanWorkers.add(workerKey);

  const MAX_POLLS = 100;
  const MAX_DURATION_MS = 30 * 60 * 1000; // 30 minutes
  const RATE_LIMIT_PAUSE_MS = 60_000;
  const startTime = Date.now();

  try {
    let interval = 5000; // Start at 5s

    for (let poll = 0; poll < MAX_POLLS; poll++) {
      // Wait before polling
      await new Promise(r => setTimeout(r, interval));

      // Check if record still exists
      const record = await storageManager.getPendingDownload(downloadId);
      if (!record) {
        console.log(`[ThreatLens HA] Record ${downloadId} removed — stopping poll.`);
        return;
      }

      // Check timeout
      if (Date.now() - startTime > MAX_DURATION_MS) {
        await storageManager.patchPendingDownload(downloadId, {
          sandboxJob: {
            ...record.sandboxJob,
            status: "timeout",
            errorMessage: "Sandbox analysis timed out after 10 minutes.",
            updatedAt: new Date().toISOString()
          }
        });
        return;
      }

      // Check API call cap
      const currentCount = record.sandboxJob?.apiCallCount || 0;
      if (currentCount >= 50) {
        await storageManager.patchPendingDownload(downloadId, {
          sandboxJob: {
            ...record.sandboxJob,
            status: "timeout",
            errorMessage: "Maximum API call limit (50) reached for this job.",
            updatedAt: new Date().toISOString()
          }
        });
        return;
      }

      // Poll the state
      const stateResult = await pollSandboxState(jobId, apiKey);

      // Handle rate limit
      if (stateResult.status === 429) {
        const rateCount = (record.sandboxJob?.rateLimitHitCount || 0) + 1;
        await storageManager.patchPendingDownload(downloadId, {
          sandboxJob: {
            ...record.sandboxJob,
            rateLimitHitCount: rateCount,
            apiCallCount: currentCount + 1,
            updatedAt: new Date().toISOString()
          }
        });
        console.warn(`[ThreatLens HA] Rate limited — pausing polling for 60s (hit #${rateCount}).`);
        await new Promise(r => setTimeout(r, RATE_LIMIT_PAUSE_MS));
        continue;
      }

      if (!stateResult.ok) {
        // Non-fatal error — increment counter and continue
        await storageManager.patchPendingDownload(downloadId, {
          sandboxJob: {
            ...record.sandboxJob,
            apiCallCount: currentCount + 1,
            updatedAt: new Date().toISOString()
          }
        });
        interval = Math.min(interval * 2, 15000); // Cap at 15s to keep SW alive
        continue;
      }

      // Map HA state to our lifecycle
      const haState = String(stateResult.data?.state || stateResult.data?.status || "").toLowerCase();
      let mappedStatus = record.sandboxJob?.status || "queued";
      if (haState.includes("queue") || haState.includes("pending")) mappedStatus = "queued";
      else if (haState.includes("running") || haState.includes("in_progress")) mappedStatus = "running";
      else if (haState.includes("process")) mappedStatus = "processing";
      else if (haState.includes("success") || haState.includes("complete") || haState.includes("done")) mappedStatus = "completed";
      else if (haState.includes("error") || haState.includes("fail")) {
        const providerError = stateResult.data?.error || stateResult.data?.error_message || "Sandbox analysis failed on the provider side.";
        await storageManager.patchPendingDownload(downloadId, {
          sandboxJob: {
            ...record.sandboxJob,
            status: "failed",
            errorCode: "analysis_failed",
            errorMessage: providerError,
            apiCallCount: currentCount + 1,
            pollCount: poll + 1,
            updatedAt: new Date().toISOString()
          }
        });
        return;
      }

      // If completed, fetch the full report FIRST, then patch both status and result
      if (mappedStatus === "completed") {
        let finalResult = null;
        let reportRetries = 12; // Wait up to 60 seconds
        
        while (reportRetries > 0) {
          try {
            const report = await fetchHaReport(jobId, apiKey);
            if (report.ok) {
              finalResult = normalizeHaIntelligenceReport(report.data);
              // HA sometimes returns an empty/dummy report immediately after completion.
              // If the verdict is still unknown or missing MD5, it's not fully populated yet.
              if (finalResult.verdict !== "unknown" && finalResult.file_metadata.md5 !== "") {
                break; // We got the real data!
              }
            }
          } catch (reportErr) {
            console.error("[ThreatLens HA] Failed to fetch completed report:", reportErr.message);
          }
          
          // Wait 5 seconds and try again
          reportRetries--;
          if (reportRetries > 0) {
            await new Promise(r => setTimeout(r, 5000));
          }
        }

        // If we exhausted retries and it's still dummy data, we just have to save it.
        await storageManager.patchPendingDownload(downloadId, {
          sandboxJob: {
            ...record.sandboxJob,
            status: "completed",
            result: finalResult,
            apiCallCount: currentCount + 2,
            pollCount: poll + 1,
            updatedAt: new Date().toISOString()
          }
        });
        return;
      }

      // If NOT completed, just patch the current intermediate status
      await storageManager.patchPendingDownload(downloadId, {
        sandboxJob: {
          ...record.sandboxJob,
          status: mappedStatus,
          apiCallCount: currentCount + 1,
          pollCount: poll + 1,
          updatedAt: new Date().toISOString()
        }
      });

      // Backoff for next poll, max 15s to keep service worker active
      interval = Math.min(interval * 2, 15000);
    }

    // Max polls reached without completion
    const finalRecord = await storageManager.getPendingDownload(downloadId);
    if (finalRecord && finalRecord.sandboxJob?.status !== "completed") {
      await storageManager.patchPendingDownload(downloadId, {
        sandboxJob: {
          ...finalRecord.sandboxJob,
          status: "timeout",
          errorMessage: `Maximum poll attempts (${MAX_POLLS}) reached without completion.`,
          updatedAt: new Date().toISOString()
        }
      });
    }
  } catch (error) {
    console.error("[ThreatLens HA] Polling engine error:", error.message);
    const errRecord = await storageManager.getPendingDownload(downloadId);
    if (errRecord) {
      await storageManager.patchPendingDownload(downloadId, {
        sandboxJob: {
          ...errRecord.sandboxJob,
          status: "failed",
          errorCode: "polling_error",
          errorMessage: error.message,
          updatedAt: new Date().toISOString()
        }
      });
    }
  } finally {
    activeScanWorkers.delete(workerKey);
  }
}

/**
 * Resumes any stuck sandbox polls. Called when the Service Worker wakes up.
 * This ensures that if Chrome kills the SW during a long sandbox detonation (e.g. 20+ mins),
 * we automatically resume polling when the SW is resurrected (like when the user opens the popup).
 */
export async function resumeSandboxPolls() {
  try {
    const records = await storageManager.listPendingDownloads();
    const config = await storageManager.getConfig();
    const haKey = config.integrations?.hybridAnalysis?.apiKey;
    if (!haKey) return;

    for (const record of Object.values(records)) {
      if (record.sandboxJob && ["queued", "running", "processing"].includes(record.sandboxJob.status)) {
        console.log(`[ThreatLens HA] Resuming interrupted sandbox poll for ${record.downloadId}`);
        void startPollingEngine(record.downloadId, record.sandboxJob.jobId, haKey);
      }
    }
  } catch (err) {
    console.error("[ThreatLens HA] Failed to resume sandbox polls:", err);
  }
}

// Automatically resume polls when this module is evaluated (SW startup)
resumeSandboxPolls();

/**
 * Resumes polling for any sandbox jobs that were in-flight when the
 * service worker was terminated (idle eviction, browser restart).
 */
async function resumeHaSandboxJobs() {
  try {
    const config = await storageManager.getConfig();
    const haKey = String(config.integrations?.hybridAnalysis?.apiKey || "").trim();
    if (!haKey) return;

    const pending = await storageManager.listPendingDownloads();
    for (const record of pending) {
      const job = record.sandboxJob;
      if (!job || !job.jobId) continue;
      if (["queued", "running", "processing"].includes(job.status)) {
        console.log(`[ThreatLens HA] Resuming polling for job ${job.jobId} (download ${record.downloadId})`);
        void startPollingEngine(record.downloadId, job.jobId, haKey);
      }
    }
  } catch (e) {
    console.warn("[ThreatLens HA] Failed to resume sandbox jobs:", e.message);
  }
}

/**
 * Runs the Hybrid Analysis intelligence lookup as a parallel background worker.
 * Fires after the hash worker completes. Fetches the HA overview + fuzzy hash
 * results and persists them to the Download_Record.
 */
async function runHaIntelligenceLookup(downloadId, config) {
  const workerKey = `ha-intel-${downloadId}`;
  if (activeScanWorkers.has(workerKey)) return;
  activeScanWorkers.add(workerKey);

  try {
    const haKey = String(config?.integrations?.hybridAnalysis?.apiKey || "").trim();
    if (!haKey) return;

    const record = await storageManager.getPendingDownload(downloadId);
    if (!record) return;

    // Need a file hash to look up
    const fileHash = (typeof record.fileHash === "object" && record.fileHash !== null)
      ? (record.fileHash.hash || "") : String(record.fileHash || "").trim();
    if (!fileHash || !validateHash(fileHash)) return;

    // Skip if already complete
    if (record.providerReports?.hybridAnalysis?.status === "complete") return;

    // Mark as loading
    await storageManager.patchPendingDownload(downloadId, {
      providerReports: {
        ...(record.providerReports || {}),
        hybridAnalysis: { status: "loading", provider: "Hybrid Analysis" }
      }
    });

    // Step 1: Fetch the overview (high-level verdict + related_reports list)
    const overviewResult = await deduplicateHaRequest(fileHash, async () => {
      return fetchHaOverview(fileHash, haKey);
    });

    const latestRecord = await storageManager.getPendingDownload(downloadId);
    if (!latestRecord) return;

    if (!overviewResult.ok && overviewResult.errorCode !== "not_found") {
      // Real error — persist it
      await storageManager.patchPendingDownload(downloadId, {
        providerReports: {
          ...(latestRecord.providerReports || {}),
          hybridAnalysis: {
            status: "error",
            provider: "Hybrid Analysis",
            errorCode: overviewResult.errorCode,
            errorMessage: overviewResult.message
          }
        }
      });
      return;
    }

    // Step 2: The overview endpoint does NOT contain behavioral data (no MD5,
    // no environment, no MITRE, no signatures, no processes). The real data
    // lives in individual report summaries. Check if related_reports exist
    // and fetch the best one.
    let reportData = null;
    const overviewData = overviewResult.ok ? overviewResult.data : null;

    // Track the best report entry from related_reports — it holds the real threat_score
    let bestReportMeta = null;

    if (overviewData && Array.isArray(overviewData.related_reports) && overviewData.related_reports.length > 0) {
      // Pick the best report: prefer malicious > suspicious > no specific threat,
      // then highest threat_score as tiebreaker
      const successReports = overviewData.related_reports
        .filter(r => r.state === "SUCCESS" && r.verdict)
        .sort((a, b) => {
          const verdictWeight = (v) => v === "malicious" ? 3 : v === "suspicious" ? 2 : 1;
          const vDiff = verdictWeight(b.verdict) - verdictWeight(a.verdict);
          if (vDiff !== 0) return vDiff;
          return Number(b.threat_score || 0) - Number(a.threat_score || 0);
        });

      bestReportMeta = successReports[0] || null;
      if (bestReportMeta && bestReportMeta.job_id) {
        try {
          const fullReport = await fetchHaReport(bestReportMeta.job_id, haKey);
          if (fullReport.ok && fullReport.data) {
            reportData = fullReport.data;
          }
        } catch (err) {
          console.warn("[ThreatLens HA] Failed to fetch related report:", err.message);
        }
      }
    } else if (overviewData && Array.isArray(overviewData.reports) && overviewData.reports.length > 0) {
      // Fallback: sometimes related_reports is empty but reports array has job_id strings
      const firstJobId = overviewData.reports[0];
      if (typeof firstJobId === "string") {
        try {
          const fullReport = await fetchHaReport(firstJobId, haKey);
          if (fullReport.ok && fullReport.data) {
            reportData = fullReport.data;
          }
        } catch (err) {
          console.warn("[ThreatLens HA] Failed to fetch report from reports array:", err.message);
        }
      }
    }

    // Step 3: Normalize — prefer the full report if we have it, fall back to overview.
    // The related_reports[n].threat_score is the authoritative score — the full report
    // data sometimes lacks it. Merge it in so normalizeHaIntelligenceReport picks it up.
    let haReport;
    if (reportData) {
      // Merge bestReportMeta.threat_score into reportData if reportData is missing it
      if (bestReportMeta && Number(bestReportMeta.threat_score || 0) > Number(reportData.threat_score || 0)) {
        reportData = { ...reportData, threat_score: bestReportMeta.threat_score };
      }
      haReport = normalizeHaIntelligenceReport(reportData);
    } else if (overviewData) {
      // Overview-only: merge best threat_score if available
      const mergedOverview = bestReportMeta && Number(bestReportMeta.threat_score || 0) > 0
        ? { ...overviewData, threat_score: bestReportMeta.threat_score, verdict: bestReportMeta.verdict || overviewData.verdict }
        : overviewData;
      haReport = normalizeHaIntelligenceReport(mergedOverview);
    } else {
      haReport = normalizeHaIntelligenceReport(null, "not_found");
    }

    // Persist the intelligence report
    const haProviderPatch = {
      status: "complete",
      provider: "Hybrid Analysis",
      ...haReport
    };

    let providerPatch = {
      ...(latestRecord.providerReports || {}),
      hybridAnalysis: haProviderPatch
    };

    // Step 4: Similarity search via SHA256 from the fileHash
    // (record.sha256 doesn't exist — the hash is stored in record.fileHash)
    const sha256Hash = (validateHash(fileHash) === "sha256") ? fileHash : "";
    if (sha256Hash && sha256Hash.length === 64) {
      try {
        const similarResult = await searchSimilarTo(sha256Hash, haKey);
        if (similarResult.ok && similarResult.data && Array.isArray(similarResult.data.result) && similarResult.data.result.length > 0) {
          providerPatch.tlshLookup = {
            status: "complete",
            results: normalizeTlshResults(similarResult.data.result),
            matchCount: similarResult.data.result.length
          };
        } else if (similarResult.ok) {
          providerPatch.tlshLookup = { status: "no_results", results: [], matchCount: 0 };
        } else {
          providerPatch.tlshLookup = { status: "error", results: [], matchCount: 0, errorMessage: similarResult.message };
        }
      } catch (simErr) {
        console.warn("[ThreatLens HA] Similarity search error:", simErr.message);
        providerPatch.tlshLookup = { status: "error", results: [], matchCount: 0, errorMessage: simErr.message };
      }
    } else {
      providerPatch.tlshLookup = { status: "skipped_insufficient_data", results: [], matchCount: 0 };
    }

    // Step 5: Derive TLS Verdict based on the TLSH matches
    const tlsHash = haReport.file_metadata?.tlsh;
    if (tlsHash) {
      if (providerPatch.tlshLookup && providerPatch.tlshLookup.status === "complete") {
        const results = providerPatch.tlshLookup.results || [];
        let totalMalicious = 0;
        results.forEach(item => {
           if (item.verdict === "malicious" || item.threat_score >= 90) totalMalicious++;
        });
        providerPatch.tlsVerdict = {
           status: "complete",
           hash: tlsHash,
           type: "tlsh",
           matches: results.length,
           malicious: totalMalicious,
           verdict: totalMalicious > 0 ? "malicious" : (results.length > 0 ? "clean" : "unknown")
        };
      } else if (providerPatch.tlshLookup && providerPatch.tlshLookup.status === "error") {
        providerPatch.tlsVerdict = { status: "error", errorMessage: providerPatch.tlshLookup.errorMessage || "HA API error" };
      } else if (providerPatch.tlshLookup && providerPatch.tlshLookup.status === "no_results") {
        providerPatch.tlsVerdict = { status: "complete", hash: tlsHash, type: "tlsh", matches: 0, malicious: 0, verdict: "unknown" };
      } else {
        providerPatch.tlsVerdict = { status: "not_configured" };
      }
    }

    await storageManager.patchPendingDownload(downloadId, {
      providerReports: providerPatch
    });

  } catch (error) {
    console.error("[ThreatLens HA] Intelligence lookup error:", error.message);
    const errRecord = await storageManager.getPendingDownload(downloadId);
    if (errRecord) {
      await storageManager.patchPendingDownload(downloadId, {
        providerReports: {
          ...(errRecord.providerReports || {}),
          hybridAnalysis: {
            status: "error",
            provider: "Hybrid Analysis",
            errorMessage: error.message
          }
        }
      });
    }
  } finally {
    activeScanWorkers.delete(workerKey);
  }
}

async function handleUserAction(downloadId, action) {
  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) {
    throw new Error("That download is no longer pending.");
  }

  switch (action) {
    case "allow": {
      // Optimistically update UI so it clears the warning immediately.
      const allowedRecord = await storageManager.patchPendingDownload(downloadId, {
        status: "allowed",
        decision: "allow",
        decisionSource: "user",
        holdOriginalDownload: false
      });
      if (allowedRecord) {
        void publishAuditWebhook(allowedRecord, "user_allow");
      }
      resolveFilenameHold(downloadId);

      if (record.originalCanceled || record.resumeStrategy === "replay") {
        const token = registerApprovedReplay(record);
        const sourceUrl = record.originalUrl || record.finalUrl || record.sourceUrl;
        if (sourceUrl) {
          pendingReplaysByUrl.set(getSearchableUrl(sourceUrl), record);
        }

        let replayDownloadId;
        try {
          replayDownloadId = await replayDeferredDownload(record);
          if (replayDownloadId) {
            replayedDownloads.set(replayDownloadId, record);
          }
          await storageManager.removePendingDownload(downloadId);
        } catch (error) {
          revokeApprovedReplay(token);
          if (sourceUrl) {
            pendingReplaysByUrl.delete(getSearchableUrl(sourceUrl));
          }
          throw error;
        }

        return { status: "allowed", replayDownloadId };
      }

      if (record.resumeStrategy === "pause" || record.resumeStrategy === "pause_after_suggest") {
        await safeResume(downloadId);
        return { status: "allowed" };
      }

      if (!record.holdOriginalDownload) {
        void logDownloadDiagnostic(downloadId, "allow_without_hold", {
          status: record.status,
          decision: record.decision,
          enforcementMode: record.enforcementMode || "none"
        }, "error", true);
        throw new Error("ThreatLens lost the hold on this download. Please retry the download so it can be re-intercepted safely.");
      }

      heldEphemeralDownloads.delete(downloadId);
      disarmPauseEnforcement(downloadId);
      await storageManager.incrementStats({ userAllowed: 1 });
      await safeResume(downloadId);
      // Cleanup after a short window — the resumed download fires its own
      // handleDownloadChanged events, which will remove it on completion.
      schedulePendingCleanup(downloadId, 60_000);
      return { status: "allowed" };
    }
    case "block": {
      if (record.originalCanceled || record.resumeStrategy === "replay") {
        heldEphemeralDownloads.delete(downloadId);
        disarmPauseEnforcement(downloadId);
      } else if (!record.holdOriginalDownload) {
        void logDownloadDiagnostic(downloadId, "block_without_hold", {
          status: record.status,
          decision: record.decision,
          enforcementMode: record.enforcementMode || "none"
        }, "error", true);
      } else if (record.resumeStrategy === "pause" || record.resumeStrategy === "pause_after_suggest") {
        await safeCancel(downloadId);
        await removeFileIfPresent(downloadId);
        await eraseDownload(downloadId);
      } else {
        heldEphemeralDownloads.delete(downloadId);
        disarmPauseEnforcement(downloadId);
        resolveFilenameHold(downloadId);
        await safeCancel(downloadId);
        await removeFileIfPresent(downloadId);
        await eraseDownload(downloadId);
      }
      await storageManager.incrementStats({ userBlocked: 1 });
      const blockedRecord = await storageManager.patchPendingDownload(downloadId, {
        status: "blocked_user",
        decision: "block",
        holdOriginalDownload: false,
        reason: "The user blocked this download."
      });
      if (blockedRecord) {
        void publishAuditWebhook(blockedRecord, "user_block");
        await displayBlockedWarning(blockedRecord);
      }
      // 3s delay so Review tab can briefly show the blocked state before cleanup
      schedulePendingCleanup(downloadId, 3_000);
      return { status: "blocked" };
    }
    case "trust-domain": {
      const domain = record.sourceHostname;
      if (domain && domain !== "Unknown source") {
        try {
          await storageManager.addRule("allowlist", "domains", domain);
        } catch (e) {
          console.warn("[ThreatLens] Rule exists or save failed:", e.message);
        }
      }
      return await handleUserAction(downloadId, "allow");
    }
    case "block-domain": {
      const domain = record.sourceHostname;
      if (domain && domain !== "Unknown source") {
        try {
          await storageManager.addRule("blocklist", "domains", domain);
        } catch (e) {
          console.warn("[ThreatLens] Block-domain rule exists or save failed:", e.message);
        }
      }
      return await handleUserAction(downloadId, "block");
    }
    case "trust-url": {
      const url = record.sourceUrl || record.finalUrl;
      if (url) {
        try {
          await storageManager.addRule("allowlist", "urls", url);
        } catch (e) {
          console.warn("[ThreatLens] URL rule exists or save failed:", e.message);
        }
      }
      return await handleUserAction(downloadId, "allow");
    }
    case "cancel": {
      return await handleUserAction(downloadId, "block");
    }
    case "check-reputation":
      await storageManager.incrementStats({
        reputationChecks: 1
      });
      await runInlineReputation(downloadId, true);
      return { status: "checking_reputation" };
    default:
      throw new Error("Unsupported ThreatLens action.");
  }
}

async function handleProviderOpen(downloadId, provider) {
  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) {
    throw new Error("That download is no longer pending.");
  }

  if (provider === "virustotal") {
    return runInlineReputation(downloadId, true);
  }

  if (provider === "urlscan") {
    return runUrlscanLookup(downloadId);
  }

  throw new Error("Unsupported reputation provider.");
}

/**
 * Hash Policy Check — called after a file hash is confirmed.
 * Checks the hash against the managed/local blocklist.hashes array.
 * If a match is found the download is immediately blocked via the same
 * path as a normal policy block — zero changes to existing flows.
 *
 * Returns true if the download was hash-blocked (caller should stop).
 * Returns false if no match — caller continues as normal.
 */
async function checkHashPolicy(downloadId, fileHash) {
  if (!fileHash) return false;

  const config = cachedConfig || await storageManager.getConfig();
  const blockedHashes = config?.blocklist?.hashes || [];
  if (!Array.isArray(blockedHashes) || blockedHashes.length === 0) return false;

  const normalizedHash = String(fileHash).toLowerCase().trim();
  const match = blockedHashes.find(h => String(h).toLowerCase().trim() === normalizedHash);
  if (!match) return false;

  // Hash is on the enterprise blocklist — block immediately.
  console.warn(`[ThreatLens] Hash policy match: ${normalizedHash}`);

  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) return true; // Already gone — treat as blocked.

  // Physically remove the file using the same path as a user "block" action.
  if (record.resumeStrategy === "pause" || record.resumeStrategy === "pause_after_suggest") {
    await safeCancel(downloadId);
    await removeFileIfPresent(downloadId);
    await eraseDownload(downloadId);
  } else {
    heldEphemeralDownloads.delete(downloadId);
    disarmPauseEnforcement(downloadId);
    resolveFilenameHold(downloadId);
    await safeCancel(downloadId);
    await removeFileIfPresent(downloadId);
    await eraseDownload(downloadId);
  }

  await storageManager.incrementStats({ userBlocked: 1 });
  const blockedRecord = await storageManager.patchPendingDownload(downloadId, {
    status: "blocked_rule",
    decision: "block",
    holdOriginalDownload: false,
    riskIndicator: "Blocked",
    ruleMatch: {
      type: "hash",
      typeLabel: "Hash Check",
      value: normalizedHash,
      matchedValue: normalizedHash,
      category: "malware"
    },
    reason: `Blocked by enterprise hash policy. SHA-256: ${normalizedHash}`
  });

  if (blockedRecord) {
    void publishAuditWebhook(blockedRecord, "auto_block");
    await displayBlockedWarning(blockedRecord);
    schedulePendingCleanup(downloadId, 3_000);
  }

  return true; // Blocked — caller must stop.
}

async function handleAdvancedScan(downloadId) {
  let record = await storageManager.getPendingDownload(downloadId);
  if (!record) {
    throw new Error("That download is no longer pending.");
  }

  const isBlobDownload = [record.originalUrl, record.finalUrl].some(u => u && (u.startsWith("blob:") || u.startsWith("data:")));

  if (isBlobDownload) {
    record = await storageManager.patchPendingDownload(downloadId, {
      fileHashStatus: "skipped_blob",
      reason: getStreamingReasons({ ...record, fileHashStatus: "skipped_blob" })
    });
    throw new Error("Cannot extract hash from browser-generated (Blob) files.");
  }

  // Update UI state to show it is hashing
  record = await storageManager.patchPendingDownload(downloadId, {
    fileHashStatus: "loading",
    reason: getStreamingReasons({ ...record, fileHashStatus: "loading" })
  });

  // 1. Calculate the hash using the new utility
  const urlsToTry = [record.finalUrl, record.originalUrl, record.sourceUrl].filter(Boolean);
  const uniqueUrls = [...new Set(urlsToTry)];
  
  let fileHashResult = null;
  for (const u of uniqueUrls) {
    if (!u || u.startsWith("blob:") || u.startsWith("data:")) continue;
    let lastProgressStr = "";
    let lastReportedPct = -1;
    
    fileHashResult = await calculateFileHash(u, async (loaded, total) => {
      let progressStr = "";
      if (total > 0) {
        const percent = Math.min(100, Math.round((loaded / total) * 100));
        const boundary = Math.floor(percent / 5) * 5;
        if (boundary <= lastReportedPct) return;
        lastReportedPct = boundary;
        progressStr = `${percent}%`;
      } else {
        progressStr = `${(loaded / 1024 / 1024).toFixed(0)} MB`;
        if (progressStr === lastProgressStr) return;
      }
      if (progressStr !== lastProgressStr) {
        lastProgressStr = progressStr;
        await storageManager.patchPendingDownload(downloadId, {
          fileHashProgress: progressStr
        });
      }
    });
    
    if (fileHashResult) break; // Found a working stream
  }

  if (!fileHashResult || !fileHashResult.hash) {
    record = await storageManager.patchPendingDownload(downloadId, {
      fileHashStatus: "error",
      reason: getStreamingReasons({ ...record, fileHashStatus: "error" })
    });
    throw new Error("Could not extract file hash (CORS or network issue).");
  }

  const fileHash = fileHashResult.hash;
  const fileAnalysisPatch = buildFileAnalysisPatch(fileHashResult);

  // 2. Patch the pending download with the new hash
  const latestBeforeHash = await storageManager.getPendingDownload(downloadId);
  record = await storageManager.patchPendingDownload(downloadId, {
    ...fileAnalysisPatch,
    fileHashStatus: "complete",
    reason: getStreamingReasons({ ...latestBeforeHash, ...fileAnalysisPatch, fileHashStatus: "complete" })
  });

  // 2a. Hash allowlist check
  const config = cachedConfig || await storageManager.getConfig();
  const allowedHashes = config?.allowlist?.hashes || [];
  const normalizedHash = String(fileHash).toLowerCase().trim();
  
  if (allowedHashes.some(h => String(h).toLowerCase().trim() === normalizedHash)) {
    console.log(`[ThreatLens] Hash allowlist match: ${normalizedHash}`);
    const allowRecord = await storageManager.patchPendingDownload(downloadId, {
      status: "allowed",
      decision: "allow",
      holdOriginalDownload: false,
      riskIndicator: "Trusted",
      ruleMatch: {
        type: "hash",
        typeLabel: "Hash Check",
        value: normalizedHash,
        matchedValue: normalizedHash,
        category: "allowlist"
      },
      reason: `Allowed by enterprise hash policy. SHA-256: ${normalizedHash}`
    });
    
    heldEphemeralDownloads.delete(downloadId);
    disarmPauseEnforcement(downloadId);
    resolveFilenameHold(downloadId);
    void publishAuditWebhook(allowRecord, "auto_allow");
    return { fileHash, allowedByHashPolicy: true };
  }

  // 2b. Hash blocklist check
  if (await checkHashPolicy(downloadId, fileHash)) {
    return { fileHash, blockedByHashPolicy: true };
  }

  // 3. Optional: Trigger VT Lookup again with the new hash 
  await runInlineReputation(downloadId, true);

  return { fileHash, tlshHash: fileAnalysisPatch.tlshHash || "" };
}

function buildFileAnalysisPatch(fileHashResult) {
  const patch = {
    fileHash: fileHashResult.hash,
    fileEntropy: Number.isFinite(fileHashResult.entropy) ? fileHashResult.entropy : null,
    magicMime: fileHashResult.magicMime || "unknown",
    tlshHash: fileHashResult.tlshHash || "",
    fuzzyHash: fileHashResult.fuzzyHash || null,
    isPeFile: fileHashResult.isPeFile === true,
    peAnalysisStatus: fileHashResult.peAnalysisStatus || "unknown",
    peSections: Array.isArray(fileHashResult.peSections) ? fileHashResult.peSections : [],
    peAnomalies: Array.isArray(fileHashResult.peAnomalies) ? fileHashResult.peAnomalies : [],
    peAnomalyDetails: Array.isArray(fileHashResult.peAnomalyDetails) ? fileHashResult.peAnomalyDetails : []
  };

  if (fileHashResult.peHeader) {
    patch.peHeader = fileHashResult.peHeader;
  }

  return patch;
}

function maybeTriggerSandboxScan(record, config) {
  if (!config?.integrations?.hybridAnalysis?.apiKey) return;
  if (!config?.integrations?.hybridAnalysis?.autoSubmitMalicious) return;

  const BAD_INDICATORS = new Set(["Malicious", "Elevated"]);
  if (!BAD_INDICATORS.has(record.riskIndicator)) return;

  // Don't re-trigger if a sandbox job already exists (any status)
  if (record.sandboxJob?.status) return;

  const haKey = `ha-sandbox-${record.downloadId}`;
  if (activeScanWorkers.has(haKey)) return;
  activeScanWorkers.add(haKey);

  void handleSandboxScan(record.downloadId).catch(e => {
    console.warn("[ThreatLens HA] Auto-submit sandbox scan failed:", e.message);
  }).finally(() => activeScanWorkers.delete(haKey));
}

async function maybeAutoLookupReputation(downloadId, config) {
  const hasVirusTotal = Boolean(String(config?.integrations?.virusTotal?.apiKey || "").trim());
  let record = await storageManager.getPendingDownload(downloadId);
  if (!record) return;

  maybeTriggerSandboxScan(record, config);

  // Early exit: if every worker that could run is already in-flight, bail out
  // immediately. This prevents the storage-write → popup-render → re-fire loop
  // that causes the UI to flicker endlessly.
  const allWorkersActive = (
    activeScanWorkers.has(`hash-${downloadId}`) &&
    (!hasVirusTotal || activeScanWorkers.has(`vt-${downloadId}`)) &&
    activeScanWorkers.has(`urlscan-${downloadId}`) &&
    activeScanWorkers.has(`ip-${downloadId}`) &&
    activeScanWorkers.has(`domain-${downloadId}`)
  );
  if (allWorkersActive) return;

  // Only reset riskIndicator to "Checking" if we don't already have a definitive
  // result — never overwrite "Malicious"/"Suspicious"/"Clean" with "Checking"
  const DEFINITIVE = new Set(["Malicious", "Elevated", "Suspicious", "Reviewed", "Clean", "Blocked", "Trusted"]);
  const indicatorPatch = DEFINITIVE.has(record.riskIndicator) ? {} : { riskIndicator: "Checking" };

  // Only set providers to "loading" if they haven't completed yet
  const urlscanCurrent = record.providerReports?.urlscan || {};
  const ipRepCurrent = record.providerReports?.ipReputation || {};
  const urlscanPatch = (urlscanCurrent.status === "complete" || urlscanCurrent.status === "empty" || urlscanCurrent.status === "error")
    ? urlscanCurrent
    : { ...urlscanCurrent, status: "loading" };
  const ipRepPatch = (ipRepCurrent.status === "complete" || ipRepCurrent.status === "error" || ipRepCurrent.status === "not_configured")
    ? ipRepCurrent
    : { ...ipRepCurrent, status: "loading" };

  // Only set domainAudit to loading if not already done
  const domainAuditPatch = (record.domainAudit?.status === "complete" || record.domainAudit?.status === "error")
    ? record.domainAudit
    : { status: "loading" };

  const skipHashing = record.resumeStrategy === "pause" || record.resumeStrategy === "pause_after_suggest" || [record.originalUrl, record.finalUrl].some(u => u && (u.startsWith("blob:") || u.startsWith("data:")));

  // Only set fileHashStatus to loading if not already done
  let hashStatusPatch = record.fileHashStatus;
  if (record.fileHashStatus !== "complete" && record.fileHashStatus !== "error" && record.fileHashStatus !== "skipped_blob") {
    hashStatusPatch = skipHashing ? "skipped_blob" : "loading";
  }

  // 1. One-shot metadata initialization — only update fields that need it
  let patchObj = {
    ...indicatorPatch,
    domainAudit: domainAuditPatch,
    fileHashStatus: hashStatusPatch,
    providerReports: {
      ...(record.providerReports || {}),
      urlscan: urlscanPatch,
      ipReputation: ipRepPatch
    }
  };
  patchObj.reason = getStreamingReasons({ ...record, ...patchObj }, config);
  record = await storageManager.patchPendingDownload(downloadId, patchObj);

  // 2. TRUE Parallel Orchestration
  // Hash worker runs independently of VT key — it streams the file in memory
  // and produces a SHA-256 fingerprint regardless of API configuration.
  const hashKey = `hash-${downloadId}`;
  if (!skipHashing && record.fileHashStatus !== "complete" && !activeScanWorkers.has(hashKey)) {
    activeScanWorkers.add(hashKey);
    void (async () => {
      try {
        // Mark as loading immediately so the UI shows a spinner, not an error state
        await storageManager.patchPendingDownload(downloadId, {
          fileHashStatus: "loading"
        });

        // Re-fetch the latest record so we use current URLs (not the stale closure copy)
        const freshRecord = await storageManager.getPendingDownload(downloadId);
        if (!freshRecord) return;

        const urlsToTry = [freshRecord.finalUrl, freshRecord.originalUrl, freshRecord.sourceUrl].filter(Boolean);
        const uniqueUrls = [...new Set(urlsToTry)];
        const skipHashingWorker = freshRecord.resumeStrategy === "pause" || freshRecord.resumeStrategy === "pause_after_suggest" || [freshRecord.originalUrl, freshRecord.finalUrl].some(u => u && (u.startsWith("blob:") || u.startsWith("data:")));
        
        let fileHashResult = null;
        for (const u of uniqueUrls) {
          if (!u || u.startsWith("blob:") || u.startsWith("data:")) continue;
          let lastProgressStr = "";
          let lastReportedPct = -1;
          
          fileHashResult = await calculateFileHash(u, async (loaded, total) => {
            let progressStr = "";
            if (total > 0) {
              const percent = Math.min(100, Math.round((loaded / total) * 100));
              const boundary = Math.floor(percent / 5) * 5;
              if (boundary <= lastReportedPct) return;
              lastReportedPct = boundary;
              progressStr = `${percent}%`;
            } else {
              progressStr = `${(loaded / 1024 / 1024).toFixed(0)} MB`;
              if (progressStr === lastProgressStr) return;
            }
            if (progressStr !== lastProgressStr) {
              lastProgressStr = progressStr;
              await storageManager.patchPendingDownload(downloadId, {
                fileHashProgress: progressStr
              });
            }
          });
          
          if (fileHashResult) break;
        }

        if (fileHashResult && fileHashResult.hash) {
          const fileHash = fileHashResult.hash;
          const fileAnalysisPatch = buildFileAnalysisPatch(fileHashResult);

          const latestRecord = await storageManager.getPendingDownload(downloadId);
          if (!latestRecord) return;
          await storageManager.patchPendingDownload(downloadId, {
            ...fileAnalysisPatch,
            fileHashStatus: "complete",
            fileHashProgress: "",
            reason: getStreamingReasons({ ...latestRecord, ...fileAnalysisPatch, fileHashStatus: "complete" }, config)
          });
          // Hash policy check — block immediately if the hash is on the enterprise blocklist.
          // If blocked we skip the VT upgrade entirely (no wasted API calls).
          if (await checkHashPolicy(downloadId, fileHash)) return;
          // Upgrade to Hash-based OSINT lookup only if VT key is configured
          if (hasVirusTotal) {
            await runInlineReputation(downloadId, true);
          }
          // Launch HA intelligence lookup after hash is available
          const hasHaKey = Boolean(String(config?.integrations?.hybridAnalysis?.apiKey || "").trim());
          if (hasHaKey) {
            void runHaIntelligenceLookup(downloadId, config);
          }
        } else {
          const latestRecord = await storageManager.getPendingDownload(downloadId);
          if (!latestRecord) return;
          const newStatus = skipHashingWorker ? "skipped_blob" : "error";
          await storageManager.patchPendingDownload(downloadId, {
            fileHashStatus: newStatus,
            fileHashProgress: "",
            reason: getStreamingReasons({ ...latestRecord, fileHashStatus: newStatus }, config)
          });
        }
      } catch (e) {
        console.warn("[ThreatLens] Hash scan inhibited:", e.message);
        const latestRecord = await storageManager.getPendingDownload(downloadId);
        if (latestRecord) {
          const skipHashingCatch = latestRecord.resumeStrategy === "pause" || latestRecord.resumeStrategy === "pause_after_suggest" || [latestRecord.originalUrl, latestRecord.finalUrl].some(u => u && (u.startsWith("blob:") || u.startsWith("data:")));
          const st = skipHashingCatch ? "skipped_blob" : "error";
          await storageManager.patchPendingDownload(downloadId, {
            fileHashStatus: st,
            fileHashProgress: "",
            reason: getStreamingReasons({ ...latestRecord, fileHashStatus: st }, config)
          });
        }
      } finally {
        activeScanWorkers.delete(hashKey);
      }
    })();
  }

  if (hasVirusTotal) {
    const vtKey = `vt-${downloadId}`;
    const vtStatus = record.reputation?.status;
    if ((!vtStatus || vtStatus === "idle") && !activeScanWorkers.has(vtKey)) {
      activeScanWorkers.add(vtKey);
      runInlineReputation(downloadId, false).catch(e => console.error("[ThreatLens] VT Orchestration error:", e));
    }
  }

  // 3. Chain urlscan.io 
  const urlscanKey = `urlscan-${downloadId}`;
  const usStatus = record.providerReports?.urlscan?.status;
  if ((!usStatus || usStatus === "idle" || usStatus === "loading") && !activeScanWorkers.has(urlscanKey)) {
    activeScanWorkers.add(urlscanKey);
    void runUrlscanLookup(downloadId).finally(() => activeScanWorkers.delete(urlscanKey));
  }

  // 4. Chain Network IP Reputation (Google DoH + RDAP)
  const ipKey = `ip-${downloadId}`;
  const ipStatus = record.providerReports?.ipReputation?.status;
  if ((!ipStatus || ipStatus === "idle" || ipStatus === "loading") && !activeScanWorkers.has(ipKey)) {
    activeScanWorkers.add(ipKey);
    void runIpReputationLookup(downloadId).finally(() => activeScanWorkers.delete(ipKey));
  }

  // 5. Chain Domain Audit (RDAP)
  const domainKey = `domain-${downloadId}`;
  const domainStatus = record.domainAudit?.status;
  // Allow re-launch if status is "loading" — a dead service worker may have set it
  // to "loading" but never completed. The activeScanWorkers set prevents true duplicates.
  if ((!domainStatus || domainStatus === "idle" || domainStatus === "loading") && !activeScanWorkers.has(domainKey)) {
    activeScanWorkers.add(domainKey);
    void runDomainAudit(downloadId).finally(() => activeScanWorkers.delete(domainKey));
  }
}

async function runInlineReputation(downloadId, forceRefresh) {
  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) {
    throw new Error("That download is no longer pending.");
  }

  const lookupType = forceRefresh && record.fileHash ? "file" : "url";
  const currentLookupReport = getStoredVirusTotalReport(record, lookupType);

  // Skip only if we already have a definitive result. Do NOT skip for "loading" —
  // that check was the cause of the "stuck at loading forever" bug. The
  // activeScanWorkers guard in maybeAutoLookupReputation already prevents
  // duplicate workers; bailing out here just leaves status stuck at "loading".
  if (currentLookupReport?.status === "complete" && !forceRefresh) {
    activeScanWorkers.delete(`vt-${downloadId}`);
    return currentLookupReport;
  }

  // Never overwrite a definitive verdict with "Checking" — preserve results across restarts
  const DEFINITIVE = new Set(["Malicious", "Elevated", "Suspicious", "Reviewed", "Clean", "Blocked", "Trusted"]);
  const alreadyComplete = currentLookupReport?.status === "complete";
  const hasDefinitiveIndicator = DEFINITIVE.has(record.riskIndicator);

  // ── Fix 5: Silent hash-upgrade path ──────────────────────────────────────
  // When VT already has a complete result and we're being called for a
  // hash-upgrade (forceRefresh=true + fileHash present), do NOT flash the
  // UI back to "loading". Run the VT hash lookup silently and only patch
  // storage if the result actually changes.
  if (lookupType === "file") {
    const config = await storageManager.getConfig();
    void (async () => {
      try {
        const freshForVt = await storageManager.getPendingDownload(downloadId);
        if (!freshForVt) return;
        await storageManager.patchPendingDownload(downloadId, {
          status: "checking_reputation",
          providerReports: {
            ...(freshForVt.providerReports || {}),
            virusTotalFile: {
              ...(freshForVt.providerReports?.virusTotalFile || {}),
              status: "loading",
              provider: "VirusTotal",
              verdict: "loading",
              summary: "ThreatLens is cross-referencing the file fingerprint with VirusTotal.",
              checkedAt: new Date().toISOString(),
              lookupType: "file"
            }
          }
        });

        const reputation = await runVirusTotalLookup(freshForVt, config, { preferHash: true });
        if (!reputation) return;

        // Result is meaningfully different — apply it
        const latestAfterVt = await storageManager.getPendingDownload(downloadId);
        if (!latestAfterVt) return;
        const vtPatch = buildVirusTotalStoragePatch(latestAfterVt, reputation);
        const freshRecord = { ...latestAfterVt, ...vtPatch };
        const threatView = calculateUnifiedVerdict(freshRecord);
        // Only escalate — never downgrade a definitive verdict
        const SEVERITY = { "Malicious": 4, "Suspicious": 3, "Elevated": 2, "Clean": 1, "Unknown": 0, "Checking": 0, "Reviewed": 1 };
        const currentIndicator = latestAfterVt.riskIndicator || "Unknown";
        const newIndicator = (SEVERITY[threatView.indicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)
          ? threatView.indicator
          : currentIndicator;
        // GUARD: Never fire a second webhook or overwrite status if the user already decided.
        // We still patch the record so the UI stops spinning, but we suppress the webhook.
        const DECIDED_STATUSES = new Set(["blocked_user", "blocked_rule", "allowed"]);
        const isDecided = latestAfterVt && DECIDED_STATUSES.has(latestAfterVt.status);

        const patchedRecord = await storageManager.patchPendingDownload(downloadId, {
          // NOTE: Do NOT reset status — only update reputation data.
          ...vtPatch,
          ...(isDecided ? {} : { riskIndicator: newIndicator }),
          reason: getStreamingReasons(freshRecord, config)
        });
        if (!isDecided && patchedRecord && (SEVERITY[newIndicator] ?? 0) >= 2 && (SEVERITY[newIndicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)) {
          void publishAuditWebhook(patchedRecord, "osint_escalation");
          maybeTriggerSandboxScan(patchedRecord, config);
        }
      } catch (e) {
        console.warn("[ThreatLens] Silent hash-upgrade VT lookup failed:", e.message);
      } finally {
        activeScanWorkers.delete(`vt-${downloadId}`);
      }
    })();
    return record.reputation;
  }

  const loadingRecord = await storageManager.patchPendingDownload(downloadId, {
    status: "checking_reputation",
    ...(hasDefinitiveIndicator ? {} : { riskIndicator: "Checking" }),
    reputation: {
      ...(record.reputation || createInitialReputationState(record.sourceUrl)),
      status: "loading",
      verdict: alreadyComplete ? (record.reputation.verdict || "loading") : "loading",
      summary: "ThreatLens is performing OSINT Research for this URL.",
      checkedAt: new Date().toISOString(),
      lookupType: "url"
    },
    providerReports: {
      ...(record.providerReports || {}),
      virusTotalUrl: {
        ...(record.providerReports?.virusTotalUrl || {}),
        status: "loading",
        provider: "VirusTotal",
        verdict: "loading",
        summary: "ThreatLens is performing OSINT Research for this URL.",
        checkedAt: new Date().toISOString(),
        lookupType: "url"
      }
    }
  });


  const config = await storageManager.getConfig();
  
  // DETACHED WORKER: Run VirusTotal lookup and handle the queued state gracefully.
  // This fires immediately and returns control to the caller, keeping the UI responsive.
  void (async () => {
    try {
      // Re-fetch fresh from storage so we always have the latest fileHash —
      // the hash worker may have completed and written it after this function started.
      const freshForVt = await storageManager.getPendingDownload(downloadId);
      if (!freshForVt) return;
      let reputation = await runVirusTotalLookup(freshForVt, config, { preferHash: false });

      // Re-fetch to avoid stale state race conditions from parallel workers.
      let latestAfterVt = await storageManager.getPendingDownload(downloadId);
      if (!latestAfterVt) return;

      // Patch the queued state to storage immediately so the UI shows "QUEUED".
      let vtPatch = buildVirusTotalStoragePatch(latestAfterVt, reputation);
      let freshRecord = { ...latestAfterVt, ...vtPatch };
      let threatView = calculateUnifiedVerdict(freshRecord);
      // ── Fix 6: Severity-based merge guard for riskIndicator ─────────────
      const SEVERITY = { "Malicious": 4, "Suspicious": 3, "Elevated": 2, "Clean": 1, "Unknown": 0, "Checking": 0, "Reviewed": 1 };
      const currentIndicator = latestAfterVt.riskIndicator || "Unknown";
      const newIndicator = (SEVERITY[threatView.indicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)
        ? threatView.indicator
        : (DEFINITIVE.has(currentIndicator) ? currentIndicator : threatView.indicator);
      // GUARD: Never fire a second webhook or overwrite status if the user already decided.
      const DECIDED_STATUSES_URL = new Set(["blocked_user", "blocked_rule", "allowed"]);
      const isDecided = latestAfterVt && DECIDED_STATUSES_URL.has(latestAfterVt.status);

      const patchedRecord = await storageManager.patchPendingDownload(downloadId, {
        // NOTE: Do NOT reset status — only update reputation data.
        ...vtPatch,
        ...(isDecided ? {} : { riskIndicator: newIndicator }),
        reason: getStreamingReasons(freshRecord, config)
      });
      if (!isDecided && patchedRecord && (SEVERITY[newIndicator] ?? 0) >= 2 && (SEVERITY[newIndicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)) {
        void publishAuditWebhook(patchedRecord, "osint_escalation");
        maybeTriggerSandboxScan(patchedRecord, config);
      }

      // If VirusTotal needs more time to analyse a fresh URL, start a background poll.
      // This loop runs silently and auto-updates the UI when the report is ready.
      if (reputation?.status === "queued" && reputation?.lookupId) {
        const { lookupId, analysisId, analysisUrl, targetUrl: vtTargetUrl } = reputation;
        const domainInfo = {
          creationDate: reputation?.details?.domainCreationDate ?? null,
          registrar: reputation?.details?.domainRegistrar ?? null
        };

        let polledReputation = null;
        for (let attempt = 0; attempt < 8; attempt++) {
          await new Promise((r) => setTimeout(r, 3000 + attempt * 1000));

          const current = await storageManager.getPendingDownload(downloadId);
          // Stop if the download was already actioned by the user or rule.
          if (!current || current.status === "blocked_user" || current.status === "blocked_rule" || current.status === "allowed") break;

          polledReputation = await pollVirusTotalResult(
            lookupId, vtTargetUrl, config, domainInfo, analysisId, analysisUrl
          );

          if (polledReputation) {
            // Got the final result — persist and broadcast.
            const latestForPoll = await storageManager.getPendingDownload(downloadId);
            if (!latestForPoll) break;

            const polledPatch = buildVirusTotalStoragePatch(latestForPoll, polledReputation);
            const polledFresh = { ...latestForPoll, ...polledPatch };
            const polledView = calculateUnifiedVerdict(polledFresh);

            const finalRecord = await storageManager.patchPendingDownload(downloadId, {
              ...polledPatch,
              riskIndicator: polledView.indicator,
              reason: getStreamingReasons(polledFresh, config)
            });
            break; // Done — no more polling needed.
          }
        }

        // Updated: If loop finishes without result, mark as complete but unsupported/timeout
        // to prevent the UI from spinning infinitely in 'Checking'
        if (!polledReputation) {
          const timedOutRecord = await storageManager.getPendingDownload(downloadId);
          if (timedOutRecord && timedOutRecord.reputation?.status === "queued") {
            const fallbackRep = { 
              ...timedOutRecord.reputation, 
              status: "complete", 
              verdict: "unknown",
              summary: "VirusTotal took too long to analyze this URL; continuing with available intel.",
              lookupType: "url"
            };
            const fallbackPatch = buildVirusTotalStoragePatch(timedOutRecord, fallbackRep);
            const fallbackFresh = { ...timedOutRecord, ...fallbackPatch };
            const fallbackView = calculateUnifiedVerdict(fallbackFresh);
            await storageManager.patchPendingDownload(downloadId, {
              ...fallbackPatch,
              riskIndicator: fallbackView.indicator,
              reason: getStreamingReasons(fallbackFresh, config)
            });
          }
        }
      }
    } catch (e) {
      console.warn("[ThreatLens] Background OSINT aborted:", e.message);
      
      // Patch state to error so the UI doesn't spin infinitely
      const errorRecord = await storageManager.getPendingDownload(downloadId);
      if (errorRecord) {
        const fallbackRep = { 
          ...(errorRecord.reputation || {}), 
          status: "error", 
          verdict: "unknown",
          summary: "VirusTotal research encountered an internal error and aborted.",
          lookupType: "url"
        };
        const fallbackPatch = buildVirusTotalStoragePatch(errorRecord, fallbackRep);
        const fallbackFresh = { ...errorRecord, ...fallbackPatch };
        const fallbackView = calculateUnifiedVerdict(fallbackFresh);
        await storageManager.patchPendingDownload(downloadId, {
          ...fallbackPatch,
          riskIndicator: fallbackView.indicator,
          reason: getStreamingReasons(fallbackFresh, config)
        });
      }
    } finally {
      activeScanWorkers.delete(`vt-${downloadId}`);
    }
  })();

  return loadingRecord.reputation;
}

function buildVirusTotalStoragePatch(record, incomingReport) {
  const providerReports = { ...(record.providerReports || {}) };

  if (incomingReport?.provider === "VirusTotal") {
    const reportKey = incomingReport.lookupType === "file" ? "virusTotalFile" : "virusTotalUrl";
    providerReports[reportKey] = incomingReport;
  }

  const reputation = selectOverallVirusTotalReputation(
    record.reputation,
    providerReports.virusTotalUrl,
    providerReports.virusTotalFile,
    incomingReport
  );

  return { providerReports, reputation };
}

function getStoredVirusTotalReport(record, lookupType = "url") {
  const reportKey = lookupType === "file" ? "virusTotalFile" : "virusTotalUrl";
  const explicitReport = record?.providerReports?.[reportKey];
  if (explicitReport) {
    return explicitReport;
  }

  const reputation = record?.reputation;
  if (
    reputation?.provider === "VirusTotal" &&
    (reputation.lookupType === lookupType || (!reputation.lookupType && lookupType === "url"))
  ) {
    return reputation;
  }

  return null;
}

function selectOverallVirusTotalReputation(currentReport, urlReport, fileReport, incomingReport) {
  const candidates = [currentReport, urlReport, fileReport, incomingReport]
    .filter((report) => report?.provider === "VirusTotal")
    .filter((report) => !["loading", "queued"].includes(report.status));

  if (!candidates.length) {
    return incomingReport || currentReport || createInitialReputationState("");
  }

  return candidates.reduce((best, report) => {
    if (!best) return report;

    const bestSeverity = getVirusTotalSeverity(best);
    const reportSeverity = getVirusTotalSeverity(report);
    if (reportSeverity > bestSeverity) {
      return report;
    }

    // For equal clean/unknown severity, keep the Source URL report as the stable
    // overall summary so a clean hash lookup does not visually replace URL intel.
    if (reportSeverity === bestSeverity && best.lookupType !== "url" && report.lookupType === "url") {
      return report;
    }

    return best;
  }, null);
}

function getVirusTotalSeverity(report) {
  if (report?.status !== "complete") {
    return 0;
  }

  const malicious = Number(report.stats?.malicious || 0);
  const suspicious = Number(report.stats?.suspicious || 0);
  if (malicious > 0 || report.verdict === "malicious") return 4;
  if (suspicious > 0 || report.verdict === "suspicious") return 3;
  if (report.verdict === "clean") return 1;
  return 0;
}

async function runUrlscanLookup(downloadId) {
  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) {
    throw new Error("That download is no longer pending.");
  }

  const loadingRecord = await storageManager.patchPendingDownload(downloadId, {
    providerReports: {
      ...(record.providerReports || {}),
      urlscan: {
        ...(record.providerReports?.urlscan || {}),
        status: "loading",
        summary: "ThreatLens is scanning this URL with urlscan.io.",
        checkedAt: new Date().toISOString()
      }
    }
  });


  const config = await storageManager.getConfig();
  const result = await openManualProvider("urlscan", record, config);

  // Intermediary Patch: Broadcast discovered IP information to UI immediately
  if (result && result.pageIp) {
    const latestForIp = await storageManager.getPendingDownload(downloadId);
    if (latestForIp) {
      const discoveryRecord = await storageManager.patchPendingDownload(downloadId, {
        providerReports: { ...(latestForIp.providerReports || {}), urlscan: result },
        reason: getStreamingReasons({ ...latestForIp, providerReports: { ...(latestForIp.providerReports || {}), urlscan: result } })
      });
    }
  }

  // Chain the IP Scan if URLScan resolved a host IP (Skip VirusTotal quota via RDAP)
  let ipReputation = null;
  if (result && result.pageIp) {
    const rdapInfo = await fetchRdapIp(result.pageIp);
    ipReputation = {
      status: rdapInfo.status === "error" ? "unsupported" : "complete",
      scanStatus: "complete", // Mark complete so UI doesn't spin
      ip: result.pageIp,
      owner: rdapInfo.owner || "Unknown Hosting Provider",
      country: rdapInfo.country || "",
      stats: {} // Empty VT stats
    };
  }

  const latestRecord = await storageManager.getPendingDownload(downloadId);
  if (!latestRecord) return;

  // Final Synchronization: Build the clinical telemetry suite
  const freshRecord = {
    ...latestRecord,
    providerReports: {
      ...(latestRecord.providerReports || {}),
      urlscan: result,
      ...(ipReputation ? { ipReputation } : {})
    }
  };
  const threatView = calculateUnifiedVerdict(freshRecord);

  const updatedRecord = await storageManager.patchPendingDownload(downloadId, {
    providerReports: freshRecord.providerReports,
    riskIndicator: threatView.indicator,
    reason: getStreamingReasons(freshRecord) // Use streaming reasons for clinical precision
  });


  return result;
}

async function promptForDecision(record) {
  await openActionPopup();
}

async function releaseAllowlistedDownload(downloadId) {
  const record = await storageManager.patchPendingDownload(downloadId, {
    status: "allowed",
    decision: "allow",
    decisionSource: "allowlist"
  });

  disarmPauseEnforcement(downloadId);
  resolveFilenameHold(downloadId);
  await safeResume(downloadId);

  if (record) {
    // Left for future extensions or overlay clearing if needed
  }
}

async function replayDeferredDownload(record) {
  const sourceUrl = record.originalUrl || record.finalUrl || record.sourceUrl;
  if (!sourceUrl) {
    throw new Error("ThreatLens could not rebuild this download request.");
  }

  const replayOptions = {
    url: sourceUrl,
    saveAs: Boolean(record.saveAsRequested)
  };

  if (!record.saveAsRequested && record.fileName && record.fileName !== "Unidentified download") {
    replayOptions.filename = record.fileName;
  }

  return chrome.downloads.download(replayOptions);
}

async function finalizeAllowedReplay(record) {
  try {
    await storageManager.incrementStats({
      userAllowed: 1
    });
    disarmPauseEnforcement(record.downloadId);
    await storageManager.removePendingDownload(record.downloadId);
  } catch {
    // Keep the allow flow fast even if cleanup needs to be recovered later.
  }
}

async function quarantineOriginalDownload(downloadId) {
  await safePause(downloadId);
  await safeCancel(downloadId);
  await removeFileIfPresent(downloadId);
  // Resolve the suggest callback FIRST so Chrome doesn't throw an
  // "Invalid downloadId" exception when erasing it.
  resolveFilenameHold(downloadId);
  await eraseDownload(downloadId);
}

/**
 * Hold a prompted download on the original Chrome download item.
 * Chrome-level pause is the primary gate. The unresolved filename hold is the
 * secondary gate until the user explicitly allows or blocks it.
 */
async function holdEphemeralDownload(downloadId) {
  console.log(`[ThreatLens] Holding download ${downloadId} via filename delay + pause.`);
  await safePause(downloadId);
}

async function displayBlockedWarning(record) {
  await openActionPopup();
}





async function safePause(downloadId) {
  return new Promise((resolve) => {
    chrome.downloads.pause(downloadId, () => {
      const error = chrome.runtime.lastError?.message || "";
      if (error) {
        void logDownloadDiagnostic(downloadId, "pause_failed", { error }, "debug", false);
      }
      resolve({ ok: !error, error });
    });
  });
}

async function safeResume(downloadId) {
  return new Promise((resolve) => {
    chrome.downloads.resume(downloadId, () => {
      const error = chrome.runtime.lastError?.message || "";
      if (error) {
        void logDownloadDiagnostic(downloadId, "resume_failed", { error }, "warn", true);
      }
      resolve({ ok: !error, error });
    });
  });
}

async function safeCancel(downloadId) {
  return new Promise((resolve) => {
    chrome.downloads.cancel(downloadId, () => {
      const error = chrome.runtime.lastError?.message || "";
      if (error) {
        void logDownloadDiagnostic(downloadId, "cancel_failed", { error }, "debug", false);
      }
      resolve({ ok: !error, error });
    });
  });
}

async function eraseDownload(downloadId) {
  try {
    await chrome.downloads.erase({ id: downloadId });
    return true;
  } catch {
    return false;
  }
}

async function removeFileIfPresent(downloadId) {
  try {
    await chrome.downloads.removeFile(downloadId);
    return true;
  } catch {
    return false;
  }
}

function resolveFilenameHold(downloadId) {
  const hold = filenameHolds.get(downloadId);
  if (!hold) {
    return;
  }

  try {
    hold.suggest();
  } finally {
    filenameHolds.delete(downloadId);
  }
}

function schedulePendingCleanup(downloadId, delayMs = 45_000) {
  const existingTimer = cleanupTimers.get(downloadId);
  if (existingTimer) {
    clearTimeout(existingTimer);
  }

  const timer = setTimeout(async () => {
    cleanupTimers.delete(downloadId);
    disarmPauseEnforcement(downloadId);
    await storageManager.removePendingDownload(downloadId);
    // Badge updates handled by service-worker's syncActionState() via storage.onChanged
  }, delayMs);

  cleanupTimers.set(downloadId, timer);
}

async function openActionPopup() {
  if (typeof chrome.action?.openPopup !== "function") {
    return false;
  }

  try {
    await chrome.action.openPopup();
    return true;
  } catch {
    return false;
  }
}

function registerApprovedReplay(record) {
  const token = {
    id: `${record.downloadId}:${Date.now()}`,
    url: getSearchableUrl(record.originalUrl || record.finalUrl || record.sourceUrl),
    fileName: record.fileName,
    expiresAt: Date.now() + 30_000
  };

  approvedReplayTokens.push(token);
  pruneApprovedReplayTokens();
  return token.id;
}

function revokeApprovedReplay(tokenId) {
  const index = approvedReplayTokens.findIndex((token) => token.id === tokenId);
  if (index >= 0) {
    approvedReplayTokens.splice(index, 1);
  }
}

function consumeApprovedReplay(downloadItem) {
  pruneApprovedReplayTokens();

  const targetUrl = getSearchableUrl(downloadItem.finalUrl || downloadItem.url || "");
  const now = Date.now();
  
  // 1. Exact URL Match
  let index = approvedReplayTokens.findIndex((token) => token.url && token.url === targetUrl);

  // 2. Fallback: If there is exactly one recently issued token (< 10 seconds old), assume it's the replay
  if (index < 0 && approvedReplayTokens.length === 1) {
    const token = approvedReplayTokens[0];
    const age = now - (token.expiresAt - 30_000); // Created time was expiresAt - 30s
    if (age >= 0 && age < 10_000) {
      index = 0;
    }
  }

  if (index < 0) {
    return false;
  }

  approvedReplayTokens.splice(index, 1);
  return true;
}

function pruneApprovedReplayTokens() {
  const now = Date.now();
  for (let index = approvedReplayTokens.length - 1; index >= 0; index -= 1) {
    if (approvedReplayTokens[index].expiresAt <= now) {
      approvedReplayTokens.splice(index, 1);
    }
  }
  // Hard cap to prevent unbounded growth under rapid allow-all patterns
  const MAX_REPLAY_TOKENS = 50;
  while (approvedReplayTokens.length > MAX_REPLAY_TOKENS) {
    approvedReplayTokens.shift();
  }
}

function armPauseEnforcement(downloadId, intervalMs = 500) {
  if (pauseEnforcementTimers.has(downloadId)) {
    return;
  }

  pauseEnforcementMeta.set(downloadId, {
    startedAt: Date.now(),
    intervalMs,
    lastSignature: ""
  });

  const timer = setInterval(() => {
    void enforcePendingDownload(downloadId);
  }, intervalMs);

  pauseEnforcementTimers.set(downloadId, timer);
  void enforcePendingDownload(downloadId);
}

function disarmPauseEnforcement(downloadId) {
  const timer = pauseEnforcementTimers.get(downloadId);
  if (!timer) {
    return;
  }

  clearInterval(timer);
  pauseEnforcementTimers.delete(downloadId);
  pauseEnforcementMeta.delete(downloadId);
  enforcementInFlight.delete(downloadId);
}

async function enforcePendingDownload(downloadId) {
  if (enforcementInFlight.has(downloadId)) {
    return;
  }

  enforcementInFlight.add(downloadId);

  try {
    const record = await storageManager.getPendingDownload(downloadId);
    if (!record) {
      disarmPauseEnforcement(downloadId);
      return;
    }

    if (
      record.status === "allowed" ||
      record.status === "blocked_rule" ||
      record.status === "blocked_user"
    ) {
      disarmPauseEnforcement(downloadId);
      return;
    }

    const runtime = await getDownloadRuntimeState(downloadId);
    const meta = pauseEnforcementMeta.get(downloadId);
    if (!meta) {
      return;
    }

    const signature = [
      record.status,
      record.holdOriginalDownload ? "hold" : "nohold",
      runtime?.state || "missing",
      runtime?.paused ? "paused" : "running",
      runtime?.error || "noerr"
    ].join("|");

    if (meta.lastSignature !== signature) {
      meta.lastSignature = signature;
      pauseEnforcementMeta.set(downloadId, meta);
      void logDownloadDiagnostic(downloadId, "enforcement_state", {
        signature,
        runtime
      }, "debug", false);
    }

    if (!runtime) {
      void logDownloadDiagnostic(downloadId, "runtime_missing_while_pending", {
        status: record.status
      }, "warn", true);
      return;
    }

    if (record.holdOriginalDownload) {
      const pauseResult = await safePause(downloadId);
      if (pauseResult.ok) {
        // Track successful pauses for back-off logic
        if (meta) {
          meta.successfulPauses = (meta.successfulPauses || 0) + 1;
          pauseEnforcementMeta.set(downloadId, meta);
        }
      } else {
        void logDownloadDiagnostic(downloadId, "pause_retry_needed", {
          runtime,
          error: pauseResult.error
        }, "warn", true);
      }
    }
  } finally {
    enforcementInFlight.delete(downloadId);
  }
}

async function getDownloadRuntimeState(downloadId) {
  try {
    const [item] = await chrome.downloads.search({ id: downloadId });
    if (!item) {
      return null;
    }

    return {
      id: item.id,
      state: item.state,
      paused: item.paused,
      danger: item.danger,
      error: item.error || "",
      bytesReceived: item.bytesReceived,
      totalBytes: item.totalBytes,
      fileSize: item.fileSize,
      filename: item.filename || "",
      url: item.url || "",
      finalUrl: item.finalUrl || ""
    };
  } catch (error) {
    void logDownloadDiagnostic(downloadId, "search_failed", {
      error: error?.message || String(error)
    }, "debug", false);
    return null;
  }
}

async function logDownloadDiagnostic(downloadId, event, details = {}, level = "info", persist = false) {
  const entry = {
    ts: new Date().toISOString(),
    downloadId,
    event,
    level,
    ...details
  };

  const method = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
  method(`[ThreatLens][DL ${downloadId}] ${event}`, details);

  if (!persist) {
    return;
  }

  // Batched write: accumulate entries and flush every 2 seconds to reduce
  // storage IPC calls (was one read+write per log call at 500ms intervals).
  _diagBuffer.push(entry);

  if (_diagFlushTimer === null) {
    _diagFlushTimer = setTimeout(async () => {
      _diagFlushTimer = null;
      const toFlush = _diagBuffer.splice(0, _diagBuffer.length);
      if (!toFlush.length) return;
      try {
        const stored = await chrome.storage.local.get(DEBUG_LOG_KEY);
        const existing = Array.isArray(stored[DEBUG_LOG_KEY]) ? stored[DEBUG_LOG_KEY] : [];
        const merged = existing.concat(toFlush);
        if (merged.length > MAX_DEBUG_ENTRIES) {
          merged.splice(0, merged.length - MAX_DEBUG_ENTRIES);
        }
        await chrome.storage.local.set({ [DEBUG_LOG_KEY]: merged });
      } catch {
        // Debug persistence should never break download interception.
      }
    }, 2000);
  }
}

async function runIpReputationLookup(downloadId) {
  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) return;

  const config = await storageManager.getConfig();
  const targetUrl = getBestScanUrl(record);
  let hostname = "";
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {}

  if (!hostname) {
    await storageManager.patchPendingDownload(downloadId, {
      providerReports: {
        ...(record.providerReports || {}),
        ipReputation: { status: "error", scanStatus: "error", summary: "Invalid URL for IP lookup." }
      }
    });
    return;
  }

  // 1. Resolve IP via Google DoH — race against 8s timeout
  try {
    const dohFetch = fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`);
    const timeoutP = new Promise((_, reject) => setTimeout(() => reject(new Error("DoH timeout")), 8_000));
    const response = await Promise.race([dohFetch, timeoutP]);
    const data = await response.json();
    const ip = data?.Answer?.find(a => a.type === 1)?.data;

    if (ip) {
      // 2. Perform RDAP Lookup (skip VirusTotal IP scan to save the 4 req/min quota)
      const rdapInfo = await fetchRdapIp(ip);
      const ipReputation = {
        status: rdapInfo.status === "error" ? "unsupported" : "complete",
        scanStatus: "complete", // Mark complete so UI doesn't spin
        ip,
        owner: rdapInfo.owner || "Unknown Hosting Provider",
        country: rdapInfo.country || "",
        stats: {} // Empty VT stats
      };

      const latestRecord = await storageManager.getPendingDownload(downloadId);
      if (!latestRecord) return;

      const freshRecord = {
        ...latestRecord,
        targetIp: ip,
        providerReports: {
          ...(latestRecord.providerReports || {}),
          ipReputation
        }
      };

      const threatView = calculateUnifiedVerdict(freshRecord);
      const currentIndicator = latestRecord.riskIndicator || "Unknown";
      const SEVERITY = { "Malicious": 4, "Suspicious": 3, "Elevated": 2, "Clean": 1, "Unknown": 0, "Checking": 0 };
      const newIndicator = (SEVERITY[threatView.indicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)
        ? threatView.indicator
        : currentIndicator;

      const DECIDED_STATUSES_IP = new Set(["blocked_user", "blocked_rule", "allowed"]);
      const isDecided = DECIDED_STATUSES_IP.has(latestRecord.status);

      const patchedRecord = await storageManager.patchPendingDownload(downloadId, {
        targetIp: ip,
        providerReports: freshRecord.providerReports,
        ...(isDecided ? {} : { riskIndicator: newIndicator }),
        reason: getStreamingReasons(freshRecord, config)
      });
      if (!isDecided && patchedRecord && (SEVERITY[newIndicator] ?? 0) >= 2 && (SEVERITY[newIndicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)) {
        void publishAuditWebhook(patchedRecord, "osint_escalation");
        maybeTriggerSandboxScan(patchedRecord, config);
      }
    } else {
      throw new Error("No IP resolved");
    }
  } catch (e) {
    const latestAfterError = await storageManager.getPendingDownload(downloadId);
    if (latestAfterError) {
      await storageManager.patchPendingDownload(downloadId, {
        providerReports: {
          ...(latestAfterError.providerReports || {}),
          ipReputation: { status: "error", scanStatus: "error", summary: "Network reputation lookup failed." }
        }
      });
    }
  }
}

async function runDomainAudit(downloadId) {
  const record = await storageManager.getPendingDownload(downloadId);
  if (!record) return;

  const config = await storageManager.getConfig(); // fetch config — was missing, caused ReferenceError

  const targetUrl = getBestScanUrl(record);
  let hostname = "";
  try {
    hostname = new URL(targetUrl).hostname;
  } catch (e) {
    console.warn("[ThreatLens] Domain audit failed - invalid URL:", targetUrl, e.message);
  }

  if (!hostname) {
    console.warn("[ThreatLens] Domain audit failed - no hostname for downloadId:", downloadId);
    const latestAfterError = await storageManager.getPendingDownload(downloadId);
    if (latestAfterError) {
      await storageManager.patchPendingDownload(downloadId, {
        domainAudit: { status: "error" }
      });
    }
    return;
  }

  try {
    console.log("[ThreatLens] Starting domain audit for:", hostname);
    const domainInfo = await fetchRdapDomain(hostname);
    console.log("[ThreatLens] Domain audit completed:", domainInfo.status, "for", hostname);
    
    // Patch domain metadata immediately
    const latestRecord = await storageManager.getPendingDownload(downloadId);
    if (!latestRecord) return;

    const ageInDays = domainInfo.creationDate ? (Date.now() - (domainInfo.creationDate * 1000)) / (1000 * 60 * 60 * 24) : null;
    const domainMetadata = {
      creationDate: domainInfo.creationDate,
      updatedDate: domainInfo.updatedDate || null,
      expirationDate: domainInfo.expirationDate || null,
      registrar: domainInfo.registrar || "Unknown / Hidden",
      registrantName: domainInfo.registrantName || null,
      registrantCountry: domainInfo.registrantCountry || "",
      nameservers: domainInfo.nameservers || [],
      queriedDomain: domainInfo.queriedDomain || null,
      isNewDomain: ageInDays !== null && ageInDays < 90
    };

    const freshRecord = {
      ...latestRecord,
      domainMetadata
    };

    const threatView = calculateUnifiedVerdict(freshRecord);
    // Only escalate riskIndicator — never downgrade a definitive verdict (e.g. Malicious → Unknown)
    const currentIndicator = latestRecord.riskIndicator || "Unknown";
    const SEVERITY = { "Malicious": 4, "Suspicious": 3, "Elevated": 2, "Clean": 1, "Unknown": 0, "Checking": 0 };
    const newIndicator = (SEVERITY[threatView.indicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)
      ? threatView.indicator
      : currentIndicator;

    // GUARD: Never fire a second webhook or overwrite status if the user already decided.
    const DECIDED_STATUSES_DOMAIN = new Set(["blocked_user", "blocked_rule", "allowed"]);
    const isDecided = DECIDED_STATUSES_DOMAIN.has(latestRecord.status);

    const patchedRecord = await storageManager.patchPendingDownload(downloadId, {
      domainMetadata,
      // Mark domainAudit as complete so the spinner in Intel resolves correctly.
      // Previously this was only set on error, leaving the spinner spinning forever on success.
      domainAudit: { status: domainInfo.status === "complete" ? "complete" : "error" },
      ...(isDecided ? {} : { riskIndicator: newIndicator }),
      reason: getStreamingReasons(freshRecord, config)
    });
    if (!isDecided && patchedRecord && (SEVERITY[newIndicator] ?? 0) >= 2 && (SEVERITY[newIndicator] ?? 0) > (SEVERITY[currentIndicator] ?? 0)) {
      void publishAuditWebhook(patchedRecord, "osint_escalation");
      maybeTriggerSandboxScan(patchedRecord, config);
    }

    // Storage is already patched above; chrome.storage.onChanged fires automatically
    // and the popup/review window re-render. No separate push function is needed.
  } catch (e) {
    console.warn("[ThreatLens] Domain audit failed for", hostname, ":", e.message);
    const latestAfterError = await storageManager.getPendingDownload(downloadId);
    if (latestAfterError) {
      await storageManager.patchPendingDownload(downloadId, {
        domainAudit: { status: "error" }
      });
    }
  }
}

async function publishAuditWebhook(record, eventName) {
  if (!AUDIT_WEBHOOK_URL) return;
  
  if (_cachedUserEmail === null) {
    try {
      const userInfo = await chrome.identity.getProfileUserInfo();
      _cachedUserEmail = userInfo.email || "Not Logged In";
    } catch {
      _cachedUserEmail = "Not Logged In";
    }
  }

  // --- Resolve IP & Country directly so the webhook ALWAYS has them ---
  let resolvedIp = record.targetIp || record.providerReports?.ipReputation?.ip || "";
  let resolvedCountry = record.providerReports?.ipReputation?.country || "";

  // If we still don't have an IP, resolve it now via Google DoH
  if (!resolvedIp) {
    const targetUrl = record.finalUrl || record.sourceUrl || record.originalUrl || "";
    try {
      const hostname = new URL(targetUrl).hostname;
      if (hostname) {
        const dnsResp = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
        const dnsData = await dnsResp.json();
        resolvedIp = dnsData?.Answer?.find(a => a.type === 1)?.data || "";
      }
    } catch {
      // DNS resolution failed — send without IP
    }
  }

  // --- Normalize riskIndicator to values the Apps Script expects ---
  let finalRisk = record.riskIndicator || "Unknown";
  if (finalRisk === "high") finalRisk = "Blocked";
  if (finalRisk === "Trusted") finalRisk = "Clean"; // Allowlisted files → Clean for the Neutral sheet
  if (finalRisk === "Checking") {
    if (eventName === "auto_allow" || eventName === "user_allow") finalRisk = "Clean";
    if (eventName === "auto_block" || eventName === "user_block") finalRisk = "Blocked";
  }

  // --- Build reason string, always including the policy rule if one matched ---
  let reason = record.reason || "";
  if (Array.isArray(reason)) reason = reason.join(". ");
  // If a rule matched but the reason doesn't mention it, prepend it
  if (record.ruleMatch && record.ruleMatch.value && !String(reason).includes(record.ruleMatch.value)) {
    const ruleLabel = `${record.ruleMatch.typeLabel || record.ruleMatch.type || "Rule"}: "${record.ruleMatch.value}"`;
    reason = `Policy enforced — ${ruleLabel}. ${reason}`.trim();
  }

  const providerReports = record.providerReports || {};
  const ruleMatch = record.ruleMatch || null;
  const policyAction = derivePolicyAction(record, eventName);
  const actionType = deriveAuditAction(record, eventName);
  const manifest = chrome.runtime.getManifest?.() || {};
  const eventId = [
    "tl",
    record.downloadId || "unknown",
    eventName || "event",
    actionType,
    finalRisk,
    record.updatedAt || record.createdAt || Date.now()
  ].join(":");

  const payload = {
    schemaVersion: 2,
    eventId,
    userEmail: _cachedUserEmail,
    event: eventName,
    action: actionType,
    decision: record.decision || record.status || "Unknown",
    decisionSource: record.decisionSource || "",
    policyAction,
    policyCategory: ruleMatch?.category || "",
    policyType: ruleMatch?.typeLabel || ruleMatch?.type || "",
    policyValue: ruleMatch?.value || "",
    policyMatchedValue: ruleMatch?.matchedValue || "",
    riskIndicator: finalRisk,
    fileName: record.fileName || "Unknown",
    url: record.finalUrl || record.sourceUrl || record.originalUrl || "",
    sourceUrl: record.sourceUrl || "",
    finalUrl: record.finalUrl || "",
    originalUrl: record.originalUrl || "",
    sourceHostname: record.sourceHostname || "",
    sourceDisplay: record.sourceDisplay || "",
    isEphemeralUrl: (record.sourceUrl || "").startsWith("blob:") || (record.sourceUrl || "").startsWith("data:"),
    hasSecurityToken: (record.finalUrl || "").includes("security-token="),
    fileHash: (typeof record.fileHash === "object" && record.fileHash !== null) ? (record.fileHash.hash || "") : (record.fileHash || ""),
    tlshHash: record.tlshHash || "",
    fuzzyHash: record.fuzzyHash || null,
    isPeFile: record.isPeFile === true,
    peAnalysisStatus: record.peAnalysisStatus || "",
    peHeader: record.peHeader || null,
    peSections: Array.isArray(record.peSections) ? record.peSections : [],
    peAnomalies: Array.isArray(record.peAnomalies) ? record.peAnomalies : [],
    peAnomalyDetails: Array.isArray(record.peAnomalyDetails) ? record.peAnomalyDetails : [],
    fileHashStatus: record.fileHashStatus || "",
    extension: record.extension || "",
    mime: record.mime || "",
    urlReputation: providerReports.virusTotalUrl || (record.reputation?.lookupType === "url" ? record.reputation : null),
    fileReputation: providerReports.virusTotalFile || (record.reputation?.lookupType === "file" ? record.reputation : null),
    overallReputation: record.reputation || null,
    urlscanReputation: providerReports.urlscan || null,
    ipReputation: {
      ip: resolvedIp || "Unknown",
      country: resolvedCountry || "Unknown",
      ...(providerReports.ipReputation || {})
    },
    domainReputation: record.domainMetadata || null,
    ruleMatch,
    reason: reason,
    downloadId: record.downloadId || "",
    extensionVersion: manifest.version || "",
    browser: "chrome",
    createdAt: record.createdAt || "",
    updatedAt: record.updatedAt || ""
  };

  // --- Send with retry (up to 3 attempts) ---
  // CRITICAL: Chrome extensions with <all_urls> host_permissions can use
  // full CORS mode. Using mode:"no-cors" was silently dropping POST bodies
  // on Google Apps Script's 302 redirects, causing entries to vanish.
  const body = JSON.stringify(payload);
  const MAX_RETRIES = 3;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const resp = await fetch(AUDIT_WEBHOOK_URL, {
        method: "POST",
        redirect: "follow",
        headers: { "Content-Type": "text/plain" },
        body
      });

      // Google Apps Script returns 200 with JSON on success after following the 302.
      // Any 2xx is a success. 4xx/5xx mean the script had an error.
      if (resp.ok) {
        return; // Success — done
      }

      // If the server returned an error, log it and retry
      const errText = await resp.text().catch(() => "");
      console.warn(`[ThreatLens] Webhook attempt ${attempt}/${MAX_RETRIES} failed: HTTP ${resp.status} — ${errText.substring(0, 200)}`);
    } catch (err) {
      console.warn(`[ThreatLens] Webhook attempt ${attempt}/${MAX_RETRIES} network error:`, err.message);
    }

    // Exponential backoff before retrying: 500ms, 1500ms
    if (attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, 500 * attempt));
    }
  }

  console.error(`[ThreatLens] Webhook FAILED after ${MAX_RETRIES} attempts for event: ${eventName}, downloadId: ${record.downloadId}`);
}

function deriveAuditAction(record, eventName) {
  const event = String(eventName || "").toLowerCase();
  const decision = String(record?.decision || record?.status || "").toLowerCase();
  if (event.includes("block") || decision.includes("block")) return "BLOCKED";
  if (event.includes("allow") || decision.includes("allow")) return "ALLOW";
  if (event.includes("escalation")) return "ESCALATED";
  return "REVIEW";
}

function derivePolicyAction(record, eventName) {
  if (!record?.ruleMatch) return "";
  const event = String(eventName || "").toLowerCase();
  const decision = String(record?.decision || record?.status || "").toLowerCase();
  if (event.includes("allow") || decision.includes("allow")) return "ALLOWLIST";
  if (event.includes("block") || decision.includes("block")) return "BLOCKLIST";
  return "POLICY_MATCH";
}
