import { recoverPendingDownloads, initializeDownloadHandler, triggerPendingScanOnKeyChange, resumeAutomaticScans } from "./downloadHandler.js";
import { storageManager } from "../shared/storageManager.js";

let actionStateSyncTimer = null;
let lastActionStateSignature = "";

chrome.runtime.onInstalled.addListener(async () => {
  await storageManager.ensureInitialized();
  await recoverPendingDownloads();
  await syncActionState();
  await resumeAutomaticScans();
});

chrome.runtime.onStartup.addListener(async () => {
  await storageManager.ensureInitialized();
  await recoverPendingDownloads();
  await syncActionState();
  await resumeAutomaticScans();
});

initializeDownloadHandler();
// Ensure storage is initialized and the pending cache is warm BEFORE resuming
// automatic scans. Previously these ran in parallel (both void), creating a
// race where listPendingDownloads could return stale/empty results.
void (async () => {
  await storageManager.ensureInitialized();
  await syncActionState();
  await resumeAutomaticScans();
})();

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local") {
    if (Object.keys(changes).some((key) => key.startsWith("threatlens.pending."))) {
      scheduleActionStateSync();
    }

    // If the user just saved a VirusTotal API key, automatically fire
    // OSINT scans for all downloads that are already waiting for a decision.
    const key = "threatlens.config";
    const configChange = changes?.[key];
    if (configChange) {
      const newKey = String(configChange.newValue?.integrations?.virusTotal?.apiKey || "").trim();
      const oldKey = String(configChange.oldValue?.integrations?.virusTotal?.apiKey || "").trim();
      if (newKey && newKey !== oldKey) {
        console.log("[ThreatLens] VirusTotal API key updated — triggering auto-scan for pending downloads.");
        void triggerPendingScanOnKeyChange();
      }

      // If the user just saved a Hybrid Analysis API key, trigger HA intelligence
      // lookups for all pending downloads that already have a computed hash.
      const newHaKey = String(configChange.newValue?.integrations?.hybridAnalysis?.apiKey || "").trim();
      const oldHaKey = String(configChange.oldValue?.integrations?.hybridAnalysis?.apiKey || "").trim();
      if (newHaKey && newHaKey !== oldHaKey) {
        console.log("[ThreatLens] Hybrid Analysis API key updated — triggering HA lookups for pending downloads.");
        void triggerPendingScanOnKeyChange();
      }
    }
  }
});

function scheduleActionStateSync() {
  clearTimeout(actionStateSyncTimer);
  actionStateSyncTimer = setTimeout(() => {
    actionStateSyncTimer = null;
    void syncActionState();
  }, 150);
}

async function syncActionState() {
  const pending = await storageManager.listPendingDownloads();
  const activePending = pending.filter((item) => item.status === "awaiting_user" || item.status === "checking_reputation");
  const count = activePending.length;
  const signature = `${count}`;

  if (signature === lastActionStateSignature) {
    return;
  }
  lastActionStateSignature = signature;

  await chrome.action.setBadgeText({
    text: count > 0 ? String(Math.min(count, 99)) : ""
  });
  await chrome.action.setBadgeBackgroundColor({
    color: count > 0 ? "#ef4444" : "#2563eb"
  });
  await chrome.action.setTitle({
    title: count > 0
      ? `ThreatLens – ${count} download${count === 1 ? "" : "s"} waiting for review`
      : "ThreatLens"
  });
}
