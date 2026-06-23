/**
 * ThreatLens — Hybrid Analysis (CrowdStrike Falcon) API Client
 * Production-grade integration for threat intelligence, sandbox submission,
 * and fuzzy hash similarity lookups.
 *
 * Security invariants:
 *   • API key transmitted ONLY via the `api-key` HTTP header
 *   • All string values in normalized reports are HTML-escaped before storage
 *   • Hash inputs validated against known patterns before any API call
 *   • Structured error objects returned — exceptions never propagate to caller
 */

const HA_API_BASE = "https://hybrid-analysis.com/api/v2";
const HA_USER_AGENT = "Falcon Sandbox";

// In-memory deduplication cache for concurrent hash lookups
const _inflightRequests = new Map(); // sha256 → Promise

// ─── HTML escaping (mirrors popup.js escapeHtml) ────────────────────────────
function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ─── Hash validation ────────────────────────────────────────────────────────
const HASH_PATTERNS = {
  md5:    /^[0-9a-f]{32}$/,
  sha1:   /^[0-9a-f]{40}$/,
  sha256: /^[0-9a-f]{64}$/
};

/**
 * Validates a hash string against MD5, SHA-1, or SHA-256 patterns.
 * Returns the hash type string or null if invalid.
 */
export function validateHash(hash) {
  if (!hash || typeof hash !== "string") return null;
  const cleaned = hash.trim().toLowerCase();
  if (HASH_PATTERNS.sha256.test(cleaned)) return "sha256";
  if (HASH_PATTERNS.sha1.test(cleaned))   return "sha1";
  if (HASH_PATTERNS.md5.test(cleaned))     return "md5";
  return null;
}

// ─── Core fetch wrapper ─────────────────────────────────────────────────────

/**
 * Low-level fetch wrapper for the Hybrid Analysis API.
 * Returns { ok, status, data } or { ok: false, status, errorCode, message }.
 * NEVER throws — all errors are caught and returned as structured objects.
 */
async function haFetch(endpoint, apiKey, options = {}) {
  try {
    const headers = {
      "api-key": apiKey,
      "user-agent": HA_USER_AGENT,
      "accept": "application/json",
      ...options.headers
    };

    const response = await fetch(`${HA_API_BASE}${endpoint}`, {
      ...options,
      headers
    });

    // Rate limit
    if (response.status === 429) {
      let errorCode = "rate_limited";
      try {
        const body = await response.text();
        if (body.includes("quota_exceeded")) {
          errorCode = "quota_exceeded";
        }
      } catch { /* ignore body parse failure */ }
      return {
        ok: false,
        status: 429,
        errorCode,
        message: errorCode === "quota_exceeded"
          ? "Hybrid Analysis API quota exhausted."
          : "Hybrid Analysis API rate limit hit. Retrying after cooldown."
      };
    }

    // Auth errors
    if (response.status === 401 || response.status === 403) {
      return {
        ok: false,
        status: response.status,
        errorCode: "auth_error",
        message: "Hybrid Analysis API key is invalid or lacks permissions. Verify the key in Settings."
      };
    }

    // Not found
    if (response.status === 404) {
      return {
        ok: false,
        status: 404,
        errorCode: "not_found",
        message: "No Hybrid Analysis report found for this hash."
      };
    }

    // Bad request (unsupported file type, etc.)
    if (response.status === 400) {
      let errorCode = "bad_request";
      let message = "Hybrid Analysis rejected the request.";
      try {
        const body = await response.text();
        if (body.includes("unsupported") || body.includes("file type")) {
          errorCode = "unsupported_file_type";
          message = "This file type is not supported by the Hybrid Analysis sandbox.";
        }
      } catch { /* ignore */ }
      return { ok: false, status: 400, errorCode, message };
    }

    // Other non-OK
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        errorCode: "api_error",
        message: `Hybrid Analysis API returned HTTP ${response.status}.`
      };
    }

    // Success
    const data = await response.json();
    return { ok: true, status: response.status, data };
  } catch (error) {
    console.error(`[ThreatLens HA] Network error on ${endpoint}:`, error?.message || error);
    return {
      ok: false,
      status: 0,
      errorCode: "network_error",
      message: "Network error communicating with Hybrid Analysis API."
    };
  }
}

// ─── Hash overview lookup ───────────────────────────────────────────────────

/**
 * Retrieves the overview report for a given hash (MD5, SHA-1, or SHA-256).
 * Returns { ok, status, data|errorCode } — never throws.
 */
export async function fetchHaOverview(hash, apiKey) {
  if (!apiKey) {
    return { ok: false, status: 0, errorCode: "not_configured", message: "Hybrid Analysis API key is not configured." };
  }

  const hashType = validateHash(hash);
  if (!hashType) {
    return { ok: false, status: 0, errorCode: "invalid_hash", message: "Hash value does not match MD5, SHA-1, or SHA-256 format." };
  }

  const cleaned = hash.trim().toLowerCase();
  return haFetch(`/overview/${cleaned}`, apiKey);
}

/**
 * Retrieves the full sandbox report for a completed job.
 * Returns { ok, data } with the merged summary + IOC data.
 */
export async function fetchHaReport(jobId, apiKey) {
  if (!apiKey || !jobId) {
    return { ok: false, status: 0, errorCode: "missing_params", message: "Job ID or API key is missing." };
  }

  // Fetch summary
  const summary = await haFetch(`/report/${jobId}/summary`, apiKey);
  if (!summary.ok) return summary;

  // Attempt to fetch IOCs (may not be available for all reports)
  let iocs = { ok: false, data: null };
  try {
    iocs = await haFetch(`/report/${jobId}/dropped-files`, apiKey);
  } catch { /* IOC fetch is best-effort */ }

  return {
    ok: true,
    status: 200,
    data: {
      ...summary.data,
      _droppedFiles: iocs.ok ? iocs.data : []
    }
  };
}

// ─── Sandbox submission ─────────────────────────────────────────────────────

/**
 * Submits a file for sandbox analysis using multipart/form-data.
 * @param {Blob|ArrayBuffer} fileData - The file binary
 * @param {string} filename - Original filename
 * @param {number} environmentId - Sandbox environment (default: 120 = Win10 64-bit)
 * @param {string} apiKey - HA API key
 * @returns {{ ok, data|errorCode, message }}
 */
export async function submitFileForSandbox(fileData, filename, environmentId, apiKey) {
  if (!apiKey) {
    return { ok: false, status: 0, errorCode: "not_configured", message: "Hybrid Analysis API key is not configured." };
  }

  if (!fileData) {
    return { ok: false, status: 0, errorCode: "no_file", message: "No file data available for submission." };
  }

  try {
    const formData = new FormData();

    // Convert ArrayBuffer to Blob if needed
    const blob = fileData instanceof Blob
      ? fileData
      : new Blob([fileData], { type: "application/octet-stream" });

    formData.append("file", blob, filename || "unknown");
    formData.append("environment_id", String(environmentId || 120));
    formData.append("no_share_third_party", "true");
    formData.append("allow_community_access", "true");

    // Do NOT set Content-Type header — browser sets it with boundary
    return await haFetch("/submit/file", apiKey, {
      method: "POST",
      body: formData,
      headers: {} // override default accept — FormData needs multipart boundary
    });
  } catch (error) {
    console.error("[ThreatLens HA] File submission error:", error?.message || error);
    return {
      ok: false,
      status: 0,
      errorCode: "submission_error",
      message: "Failed to submit file to Hybrid Analysis sandbox."
    };
  }
}

/**
 * Polls the sandbox job state.
 * @returns {{ ok, data: { state } }}
 */
export async function pollSandboxState(jobId, apiKey) {
  if (!apiKey || !jobId) {
    return { ok: false, status: 0, errorCode: "missing_params", message: "Job ID or API key is missing." };
  }
  return haFetch(`/report/${jobId}/state`, apiKey);
}

// ─── Similarity search ──────────────────────────────────────────────────────

/**
 * Searches for similar samples using a SHA256 hash.
 * Returns { ok, data: { result: [...samples] } }.
 */
export async function searchSimilarTo(sha256, apiKey, opts = {}) {
  if (!apiKey) {
    return { ok: false, status: 0, errorCode: "not_configured", message: "Hybrid Analysis API key is not configured." };
  }
  if (!sha256 || sha256.length !== 64) {
    return { ok: false, status: 0, errorCode: "skipped_insufficient_data", message: "SHA256 hash is required for similarity search." };
  }

  const formData = new URLSearchParams();
  formData.append("similar_to", sha256);

  return haFetch("/search/terms", apiKey, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString()
  });
}


// ─── Intelligence Normalizer ────────────────────────────────────────────────

/**
 * Transforms a raw HA API overview/report response into the standardized
 * HA_Intelligence_Report structure. All string fields are HTML-escaped.
 *
 * Missing/null fields are populated with defined defaults:
 *   • null for objects, [] for arrays, "" for strings, 0 for numbers
 */
export function normalizeHaIntelligenceReport(rawData, overrideVerdict = null) {
  if (!rawData && overrideVerdict === "not_found") {
    return createNotFoundReport();
  }
  if (!rawData) {
    return createEmptyReport();
  }

  const d = rawData;

  // Extract MITRE ATT&CK data
  const mitreAttcks = normalizeMitreAttcks(d.mitre_attcks || d.attack_details || []);

  // Extract IOCs
  const iocs = {
    domains: safeArray(d.domains).map(escapeHtml),
    ip_addresses: safeArray(d.hosts || d.contacted_hosts || d.ip_addresses).map(v =>
      typeof v === "object" ? escapeHtml(v.address || v.ip || "") : escapeHtml(v)
    ).filter(Boolean),
    urls: safeArray(d.contacted_urls || d.urls).map(v =>
      typeof v === "object" ? escapeHtml(v.url || "") : escapeHtml(v)
    ).filter(Boolean)
  };

  // Extract file metadata
  const fileMetadata = {
    filename: escapeHtml(d.submit_name || d.last_file_name || d.file_name || ""),
    size: Number(d.size || d.file_size || 0),
    type: escapeHtml(d.type || d.file_type || d.type_short || ""),
    md5: escapeHtml(d.md5 || ""),
    sha1: escapeHtml(d.sha1 || ""),
    sha256: escapeHtml(d.sha256 || ""),
    tlsh: escapeHtml(d.tlsh || ""),
    ssdeep: escapeHtml(d.ssdeep || ""),
    compilation_timestamp: d.compilation_timestamp || d.pe_timestamp || null
  };

  // Extract behavioral indicators
  const behavioralIndicators = safeArray(
    d.signatures || d.behavioral_indicators || d.incidents
  ).map(sig => {
    if (typeof sig === "string") return escapeHtml(sig);
    return escapeHtml(sig?.name || sig?.description || sig?.threat_level_human || "");
  }).filter(Boolean);

  // Extract scanners
  const scanners = safeArray(d.scanners || d.av_detect_results || []).map(s => {
    if (typeof s === "object") {
      return {
        name: escapeHtml(s.name || s.scanner || ""),
        status: escapeHtml(s.status || s.result || ""),
        positives: Number(s.positives || 0)
      };
    }
    return { name: escapeHtml(String(s)), status: "", positives: 0 };
  });

  // Extract tags
  const tags = safeArray(d.tags || d.classification_tags || []).map(escapeHtml);

  // Determine verdict
  let verdict = escapeHtml(overrideVerdict || d.verdict || d.threat_level_human || "unknown");

  // Normalize verdict strings
  const verdictLower = verdict.toLowerCase();
  if (verdictLower.includes("malicious")) verdict = "malicious";
  else if (verdictLower.includes("suspicious")) verdict = "suspicious";
  else if (verdictLower.includes("no specific threat") || verdictLower.includes("whitelisted") || verdictLower.includes("clean")) verdict = "no specific threat";
  else if (verdictLower === "not_found") verdict = "not_found";

  return {
    verdict,
    threat_score: Number(d.threat_score || d.av_detect || 0),
    classification: escapeHtml(d.classification || d.vx_family_type || ""),
    malware_family: escapeHtml(d.vx_family || d.malware_family || ""),
    tags,
    mitre_attcks: mitreAttcks,
    threat_actors: safeArray(d.threat_actors || []).map(escapeHtml),
    iocs,
    file_metadata: fileMetadata,
    behavioral_indicators: behavioralIndicators,
    environment_id: escapeHtml(d.environment_id || d.environment || ""),
    environment_desc: escapeHtml(d.environment_description || d.environment_desc || ""),
    job_id: escapeHtml(d.job_id || ""),
    scanners,
    // Additional enrichment fields
    analysis_start_time: d.analysis_start_time || null,
    processes: safeArray(d.processes || d.process_tree || []),
    extracted_files: safeArray(d.extracted_files || d._droppedFiles || []).map(f => ({
      name: escapeHtml(f.name || f.file_name || "Unknown"),
      sha256: escapeHtml(f.sha256 || ""),
      size: Number(f.file_size || f.size || 0),
      type: escapeHtml(f.type_tags?.[0] || f.file_type || ""),
      threat_level: Number(f.threat_level || 0),
      runtime_process: escapeHtml(f.runtime_process || ""),
      description: escapeHtml(f.description || "")
    })),
    network_activity: {
      domains: iocs.domains,
      contacted_urls: safeArray(d.contacted_urls || []).map(u => ({
        url: escapeHtml(u.url || u),
        method: escapeHtml(u.method || ""),
        ip: escapeHtml(u.ip || ""),
        port: Number(u.port || 0),
        status: Number(u.status || 0)
      })),
      dns_requests: safeArray(d.dns_lookups || d.dns_requests || []).map(r => ({
        hostname: escapeHtml(r.hostname || r.domain || ""),
        ip: escapeHtml(r.response || r.ip || ""),
        type: escapeHtml(r.type || "A")
      })),
      http_requests: safeArray(d.http_conversations || d.http_requests || []).map(r => ({
        method: escapeHtml(r.request_method || r.method || ""),
        host: escapeHtml(r.host || ""),
        path: escapeHtml(r.url || r.path || ""),
        status_code: Number(r.response_status_code || r.status || 0)
      })),
      tls_connections: safeArray(d.tls || d.tls_connections || []).map(t => ({
        host: escapeHtml(t.server_name || t.host || ""),
        ja3: escapeHtml(t.ja3 || ""),
        ja3s: escapeHtml(t.ja3s || "")
      }))
    },
    persistence: {
      registry_keys: safeArray(d.registry || d.registry_keys_set || []).map(r => ({
        key: escapeHtml(r.key || r.reg_key || ""),
        value: escapeHtml(r.value || r.reg_value || ""),
        data: escapeHtml(r.data || r.reg_data || "")
      })),
      scheduled_tasks: safeArray(d.scheduled_tasks || []).map(t => ({
        name: escapeHtml(t.name || ""),
        command: escapeHtml(t.command || t.action || "")
      })),
      services: safeArray(d.services || d.services_started || []).map(s => ({
        name: escapeHtml(s.name || s.display_name || ""),
        path: escapeHtml(s.image_path || s.path || "")
      })),
      startup_entries: safeArray(d.startup || []).map(escapeHtml)
    },
    filesystem: {
      created: safeArray(d.files_written || d.created_files || []).map(f =>
        typeof f === "object" ? escapeHtml(f.path || f.file || "") : escapeHtml(f)
      ).filter(Boolean),
      modified: safeArray(d.files_modified || d.modified_files || []).map(f =>
        typeof f === "object" ? escapeHtml(f.path || f.file || "") : escapeHtml(f)
      ).filter(Boolean),
      deleted: safeArray(d.files_deleted || d.deleted_files || []).map(f =>
        typeof f === "object" ? escapeHtml(f.path || f.file || "") : escapeHtml(f)
      ).filter(Boolean),
      dropped: safeArray(d.extracted_files || d._droppedFiles || []).map(f => ({
        name: escapeHtml(f.name || f.file_name || "Unknown"),
        sha256: escapeHtml(f.sha256 || ""),
        size: Number(f.file_size || f.size || 0)
      }))
    },
    // Raw data reference (not escaped — for internal use only)
    _raw: rawData
  };
}

function normalizeMitreAttcks(raw) {
  return safeArray(raw).map(entry => {
    if (typeof entry === "string") {
      return { tactic: "", technique_id: "", technique: escapeHtml(entry), url: "" };
    }
    const tactic = escapeHtml(entry.tactic || entry.tactic_name || "");
    const techniqueId = escapeHtml(entry.technique_id || entry.attck_id || entry.id || "");
    const technique = escapeHtml(entry.technique || entry.technique_name || entry.name || "");
    const url = techniqueId
      ? `https://attack.mitre.org/techniques/${techniqueId.replace(/\./g, "/")}/`
      : "";
    return { tactic, technique_id: techniqueId, technique, url };
  });
}

/**
 * Normalizes fuzzy hash search results into a consistent structure.
 */
export function normalizeTlshResults(rawResults) {
  if (!rawResults || !Array.isArray(rawResults)) {
    return [];
  }

  return rawResults.map(sample => ({
    sha256: escapeHtml(sample.sha256 || ""),
    similarity_score: Number(sample.similarity || sample.score || 0),
    verdict: escapeHtml(sample.verdict || sample.threat_level_human || "unknown"),
    malware_family: escapeHtml(sample.vx_family || sample.malware_family || ""),
    threat_score: Number(sample.threat_score || sample.av_detect || 0)
  })).filter(s => s.sha256);
}

// ─── Concurrent deduplication ───────────────────────────────────────────────

/**
 * Ensures only one API call per SHA-256 runs at a time.
 * If a request for the same hash is already in-flight, the caller
 * receives the same Promise (shared result, no duplicate API call).
 *
 * @param {string} sha256 - The hash key
 * @param {function} fn - Async function that performs the actual API call
 * @returns {Promise} The shared result
 */
export function deduplicateHaRequest(sha256, fn) {
  const key = String(sha256).toLowerCase().trim();
  if (_inflightRequests.has(key)) {
    return _inflightRequests.get(key);
  }

  const promise = fn().finally(() => {
    _inflightRequests.delete(key);
  });

  _inflightRequests.set(key, promise);
  return promise;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function createNotFoundReport() {
  const report = createEmptyReport();
  report.verdict = "not_found";
  report.threat_score = 0;
  return report;
}

function createEmptyReport() {
  return {
    verdict: "unknown",
    threat_score: 0,
    classification: "",
    malware_family: "",
    tags: [],
    mitre_attcks: [],
    threat_actors: [],
    iocs: { domains: [], ip_addresses: [], urls: [] },
    file_metadata: {
      filename: "", size: 0, type: "", md5: "", sha1: "", sha256: "",
      tlsh: "", ssdeep: "", compilation_timestamp: null
    },
    behavioral_indicators: [],
    environment_id: "",
    environment_desc: "",
    job_id: "",
    scanners: [],
    analysis_start_time: null,
    processes: [],
    extracted_files: [],
    network_activity: {
      domains: [], contacted_urls: [], dns_requests: [],
      http_requests: [], tls_connections: []
    },
    persistence: {
      registry_keys: [], scheduled_tasks: [], services: [], startup_entries: []
    },
    filesystem: { created: [], modified: [], deleted: [], dropped: [] },
    _raw: null
  };
}

function safeArray(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object" && !Array.isArray(value)) return [value];
  return [];
}

// ─── Legacy exports (backward compatibility) ────────────────────────────────

/**
 * @deprecated Use fetchHaOverview instead
 */
export async function fetchHybridAnalysisOverview(hash, apiKey) {
  const result = await fetchHaOverview(hash, apiKey);
  if (result.ok) return result.data;
  if (result.errorCode === "not_found") {
    const error = new Error("Not Found");
    error.status = 404;
    throw error;
  }
  throw new Error(result.message || `Hybrid Analysis API error: ${result.status}`);
}

/**
 * @deprecated Use submitFileForSandbox instead
 */
export async function submitUrlForSandbox(url, apiKey) {
  if (!url || !apiKey) return null;

  const formData = new URLSearchParams();
  formData.append("url", url);
  formData.append("environment_id", "120");

  const result = await haFetch("/submit/url", apiKey, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString()
  });

  if (result.ok) return result.data;
  throw new Error(result.message || `Hybrid Analysis API error: ${result.status}`);
}

/**
 * @deprecated Use searchSimilarTo instead
 */
export async function searchByTlsh(sha256, apiKey) {
  const result = await searchSimilarTo(sha256, apiKey);
  if (result.ok) return result.data;
  return null;
}
