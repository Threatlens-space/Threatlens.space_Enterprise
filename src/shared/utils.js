import { SHA256 } from "./sha256-stream.js";
import { TLSH } from "./tlsh.js";

const URL_PROTOCOL_ALLOWLIST = new Set(["http:", "https:", "ftp:"]);
const PE_HEADER_ANALYSIS_BYTES = 64 * 1024;
const FALLBACK_ARRAY_BUFFER_MAX_BYTES = 64 * 1024 * 1024;
const FUZZY_HASH_ALGORITHM = "TL-Fuzzy-v1";

export function parseUrl(rawValue) {
  if (!rawValue || typeof rawValue !== "string") {
    return null;
  }

  try {
    return new URL(rawValue);
  } catch {
    return null;
  }
}

export function normalizeDomainInput(rawValue) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (!value) {
    throw new Error("Enter a domain like example.com.");
  }

  const parsed = value.includes("://") ? parseUrl(value) : null;
  const hostname = parsed?.hostname || value.split("/")[0];
  const cleaned = hostname.replace(/^\.+/, "").replace(/\.+$/, "");

  if (!/^(?:[a-z0-9-]+\.)+[a-z0-9-]{2,}$/i.test(cleaned)) {
    throw new Error("Domain rules must look like example.com.");
  }

  return cleaned;
}

export function normalizeUrlInput(rawValue) {
  const parsed = parseUrl(String(rawValue || "").trim());
  if (!parsed || !URL_PROTOCOL_ALLOWLIST.has(parsed.protocol)) {
    throw new Error("URL rules must be valid http://, https://, or ftp:// addresses.");
  }

  parsed.hash = "";
  return parsed.toString();
}

export function normalizeFileTypeInput(rawValue) {
  const cleaned = String(rawValue || "").trim().toLowerCase();
  const normalized = cleaned.startsWith(".") ? cleaned : `.${cleaned}`;

  if (!/^\.[a-z0-9]{1,16}$/i.test(normalized)) {
    throw new Error("File type rules must look like .pdf or .zip.");
  }

  return normalized;
}

export function getDownloadFileName(downloadItem) {
  const filePath = downloadItem?.filename || "";
  const byPath = filePath.split(/[\\/]/).pop();
  if (byPath) {
    return decodeURIComponentSafe(byPath);
  }

  const targetUrl = downloadItem?.finalUrl || downloadItem?.url || "";
  const parsed = parseUrl(targetUrl);
  const pathName = parsed?.pathname || "";
  const byUrl = pathName.split("/").pop();

  return decodeURIComponentSafe(byUrl) || "Unidentified download";
}

export function getPrimaryDownloadUrl(downloadItem) {
  return downloadItem?.finalUrl || downloadItem?.url || downloadItem?.referrer || "";
}

export function getSearchableUrl(rawUrl) {
  const parsed = parseUrl(rawUrl);
  if (!parsed) {
    return String(rawUrl || "");
  }

  if (parsed.protocol === "blob:") {
    const innerParsed = parseUrl(parsed.pathname);
    if (innerParsed && innerParsed.origin && innerParsed.origin !== "null") {
      return innerParsed.origin + "/";
    }
    return ""; // Cannot scan a pure blob with no origin
  }

  if (parsed.protocol === "data:") {
    return ""; // Cannot scan data URLs
  }

  parsed.hash = "";
  return parsed.toString();
}

export function getBestScanUrl(record) {
  let url = record?.sourceUrl || record?.finalUrl || record?.originalUrl || "";
  
  // If the primary URL is ephemeral, the referrer (the page that triggered the download) 
  // is much more relevant and accurate for OSINT scanning.
  if ((url.startsWith("blob:") || url.startsWith("data:")) && record?.referrer) {
    if (!record.referrer.startsWith("blob:") && !record.referrer.startsWith("data:")) {
      url = record.referrer;
    }
  }
  
  return getSearchableUrl(url);
}

export function getCandidateUrls(downloadItem) {
  return [downloadItem?.finalUrl, downloadItem?.url, downloadItem?.referrer]
    .filter(Boolean)
    .map((value) => {
      const parsed = parseUrl(value);
      if (!parsed) {
        return null;
      }

      parsed.hash = "";
      return parsed.toString();
    })
    .filter(Boolean);
}

export function getCandidateDomains(downloadItem) {
  const domains = new Set();

  for (const value of [downloadItem?.finalUrl, downloadItem?.url, downloadItem?.referrer]) {
    const parsed = parseUrl(value);
    if (!parsed) continue;

    let hostname = parsed.hostname;
    if (!hostname && parsed.protocol === "blob:") {
      const innerParsed = parseUrl(parsed.pathname);
      if (innerParsed && innerParsed.hostname) {
        hostname = innerParsed.hostname;
      }
    }

    if (hostname) {
      domains.add(hostname.toLowerCase());
    }
  }

  return [...domains];
}

export function getFileExtension(downloadItem) {
  // 1. Try filename check first (most reliable)
  const fileName = getDownloadFileName(downloadItem);
  const match = fileName.toLowerCase().match(/(\.[a-z0-9]{1,16})(?:[?#]|$)/i);
  if (match) {
    return match[1];
  }

  // 2. Try MIME type mapping as a robust fallback
  if (downloadItem.mime) {
    const mime = downloadItem.mime.toLowerCase();
    if (mime.includes("jpeg") || mime.includes("jpg")) return ".jpg";
    if (mime.includes("png")) return ".png";
    if (mime.includes("pdf")) return ".pdf";
    if (mime.includes("zip")) return ".zip";
    if (mime.includes("html")) return ".html";
    if (mime.includes("exe")) return ".exe";
    if (mime.includes("json")) return ".json";
    if (mime.includes("msi")) return ".msi";
  }

  // 3. Try URL parsing (strip query parameters first)
  const primaryUrl = getPrimaryDownloadUrl(downloadItem);
  const parsed = parseUrl(primaryUrl);
  if (parsed) {
    const cleanPath = parsed.pathname.split("?")[0];
    const pathMatch = cleanPath.toLowerCase().match(/(\.[a-z0-9]{1,16})$/i);
    if (pathMatch) return pathMatch[1];
  }

  return "";
}

export function matchesDomainRule(candidateDomain, ruleDomain) {
  const domain = String(candidateDomain || "").toLowerCase();
  const rule = String(ruleDomain || "").toLowerCase();

  return domain === rule || domain.endsWith(`.${rule}`);
}

export function getReadableSource(downloadItem) {
  const primaryUrl = getPrimaryDownloadUrl(downloadItem);
  const parsed = parseUrl(primaryUrl);

  if (!parsed) {
    return {
      display: "Browser-generated or invalid source",
      hostname: "Unknown source",
      raw: primaryUrl || "Unavailable"
    };
  }

  let finalHostname = parsed.hostname;
  let path = `${parsed.pathname || "/"}${parsed.search || ""}`;

  // Extract inner hostname for blob: URLs (like Canva exports)
  if (!finalHostname && parsed.protocol === "blob:") {
    const innerParsed = parseUrl(parsed.pathname);
    if (innerParsed && innerParsed.hostname) {
      finalHostname = innerParsed.hostname;
      path = `${innerParsed.pathname || "/"}${innerParsed.search || ""}`;
    }
  }

  finalHostname = finalHostname || "Unknown source";
  const displayPath = path.length > 62 ? `${path.slice(0, 59)}...` : path;

  return {
    display: finalHostname !== "Unknown source" ? `${finalHostname}${displayPath}` : parsed.toString(),
    hostname: finalHostname,
    raw: parsed.toString()
  };
}

export function buildVirusTotalReportUrl(reportId) {
  return reportId ? `https://www.virustotal.com/gui/url/${reportId}/detection` : "";
}

export function buildVirusTotalAnalysisUrl(analysisId) {
  return analysisId ? `https://www.virustotal.com/gui/url-analysis/${analysisId}` : "";
}

export function buildUrlscanSearchUrl(rawUrl) {
  const normalizedUrl = getSearchableUrl(rawUrl);
  const escapedUrl = normalizedUrl.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const query = `page.url:"${escapedUrl}" OR task.url:"${escapedUrl}"`;

  return `https://urlscan.io/search/#${encodeURIComponent(query)}`;
}

export function humanizeRuleType(ruleType) {
  switch (ruleType) {
    case "domains":
      return "Domain";
    case "urls":
      return "URL";
    case "fileTypes":
      return "File Type";
    case "hashes":
      return "File Hash";
    default:
      return "Rule";
  }
}

export function humanizeStatus(status) {
  switch (status) {
    case "awaiting_user":
      return "Decision required";
    case "checking_reputation":
      return "Analyzing";
    case "allowed":
      return "Allowed";
    case "blocked_rule":
      return "Blocked by rule";
    case "blocked_user":
      return "Blocked by user";
    case "resolved":
      return "Resolved";
    default:
      return "Monitoring";
  }
}

export function formatTimestamp(timestamp) {
  if (!timestamp) {
    return "No activity yet";
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit"
  }).format(new Date(timestamp));
}

export function buildDownloadRecord(downloadItem, evaluation) {
  const source = getReadableSource(downloadItem);

  return {
    downloadId: downloadItem.id,
    tabId: Number.isInteger(downloadItem.tabId) && downloadItem.tabId >= 0 ? downloadItem.tabId : null,
    saveAsRequested: !downloadItem.filename,
    fileName: getDownloadFileName(downloadItem),
    extension: getFileExtension(downloadItem),
    sourceDisplay: source.display,
    sourceHostname: source.hostname,
    sourceUrl: source.raw,
    finalUrl: downloadItem.finalUrl || "",
    originalUrl: downloadItem.url || "",
    referrer: downloadItem.referrer || "",
    mime: downloadItem.mime || "",
    bytesReceived: downloadItem.bytesReceived || 0,
    totalBytes: downloadItem.totalBytes || 0,
    riskIndicator: evaluation.riskIndicator,
    ruleMatch: evaluation.match || null,
    reason: evaluation.reason,
    decision: evaluation.verdict,
    status: evaluation.verdict === "prompt" ? "awaiting_user" : evaluation.verdict === "allow" ? "allowed" : "blocked_rule",
    promptSurface: null,
    promptTabId: null,
    reviewTabId: null,
    reviewWindowId: null,
    fileHash: "",
    fileHashStatus: "idle",
    tlshHash: "",
    fuzzyHash: null,
    isPeFile: false,
    peAnalysisStatus: "idle",
    peHeader: null,
    peSections: [],
    peAnomalies: [],
    peAnomalyDetails: [],
    reputation: createInitialReputationState(source.raw),
    providerReports: createInitialProviderReports(source.raw),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

export function createInitialReputationState(rawUrl) {
  return {
    status: "idle",
    provider: "VirusTotal",
    verdict: "unknown",
    summary: "Inline reputation lookup is not configured.",
    checkedAt: null,
    reportId: "",
    reportUrl: "",
    analysisId: "",
    analysisUrl: "",
    targetUrl: getSearchableUrl(rawUrl),
    stats: {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      timeout: 0
    }
  };
}

export function createInitialProviderReports(rawUrl) {
  return {
    urlscan: {
      status: "idle",
      provider: "urlscan.io",
      summary: "Run urlscan.io only when you need an additional provider view.",
      checkedAt: null,
      reportUrl: "",
      searchUrl: buildUrlscanSearchUrl(rawUrl)
    }
  };
}

export function getReputationTone(reputation) {
  switch (reputation?.verdict) {
    case "malicious":
      return "critical";
    case "suspicious":
      return "warning";
    case "clean":
      return "good";
    case "loading":
      return "checking";
    default:
      return "neutral";
  }
}

export function getIndicatorTone(indicator) {
  switch (String(indicator || "").toLowerCase()) {
    case "malicious":
    case "blocked":
      return "critical";
    case "elevated":
      return "warning";
    case "reviewed":
    case "trusted":
      return "good";
    case "checking":
      return "checking";
    default:
      return "neutral";
  }
}

export function getRiskLabel(record) {
  const reputation = record?.reputation;

  if (reputation?.status === "loading") {
    return "Analyzing";
  }

  if (reputation?.verdict === "malicious") {
    return "Malicious";
  }

  if (reputation?.verdict === "suspicious") {
    return "Suspicious";
  }

  if (reputation?.verdict === "clean") {
    return "Clean";
  }

  return record?.riskIndicator || "Unknown";
}

export function maskSecret(secret) {
  const value = String(secret || "");
  if (!value) {
    return "Not configured";
  }

  if (value.length <= 8) {
    return `${"*".repeat(Math.max(0, value.length - 2))}${value.slice(-2)}`;
  }

  return `${value.slice(0, 4)}${"*".repeat(Math.max(0, value.length - 8))}${value.slice(-4)}`;
}

export function isPromptableTabUrl(url) {
  const parsed = parseUrl(url);
  return Boolean(parsed && (parsed.protocol === "http:" || parsed.protocol === "https:" || parsed.protocol === "file:"));
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

const HIGH_RISK_EXTENSIONS = new Set([
  // Executables
  ".exe", ".msi", ".dmg", ".apk", ".vbs", ".scr", ".bat", ".cmd", ".ps1",
  // Documents
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  // Archives
  ".zip", ".tar", ".7z", ".rar",
  // Scripts
  ".js", ".py", ".sh"
]);

export function isHighRiskExtension(ext) {
  if (!ext) return false;
  const normExt = String(ext).toLowerCase().trim();
  const cleanExt = normExt.startsWith(".") ? normExt : `.${normExt}`;
  return HIGH_RISK_EXTENSIONS.has(cleanExt);
}

/**
 * Returns true for URLs that cannot survive a cancel-then-replay cycle:
 *   • blob: — in-memory reference tied to the originating page/renderer
 *   • Signed/token-gated CDN URLs — expire within seconds or after first use
 *
 * Downloads matching this predicate must use pause-and-hold, not
 * cancel-and-erase, so that Chrome can simply resume them on approval.
 */
export function isEphemeralUrl(url) {
  if (!url || typeof url !== "string") return false;

  // blob: and data: URLs die the moment the originating page cancels them.
  if (url.startsWith("blob:") || url.startsWith("data:")) return true;

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  const hostname = parsed.hostname.toLowerCase();
  const params   = parsed.searchParams;

  // ── AWS S3 / CloudFront pre-signed URLs ─────────────────────────────────
  if (params.has("X-Amz-Signature") || params.has("X-Amz-Expires")) return true;

  // ── Azure Blob Storage SAS tokens ────────────────────────────────────────
  if (params.has("sig") && (params.has("se") || params.has("sv"))) return true;

  // ── Google Cloud Storage signed URLs ─────────────────────────────────────
  if (params.has("X-Goog-Signature")) return true;

  // ── Generic "token + expiry" pattern (ChatGPT, many others) ─────────────
  if (
    params.has("token") &&
    (params.has("expires") || params.has("exp") || params.has("Expires"))
  ) return true;

  // ── OpenAI file CDN (token is embedded in the URL path / query) ──────────
  if (hostname.endsWith("oaiusercontent.com") || hostname.endsWith("oaistatic.com")) return true;

  return false;
}

// Pre-computed hex lookup table — eliminates per-byte toString(16) overhead
const HEX_LOOKUP = Object.freeze(Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0")));

function hexFromBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_LOOKUP[bytes[i]];
  }
  return hex;
}

export async function calculateFileHash(url, onProgress = null) {
  if (!url) return null;

  const MAX_SIZE_BYTES = 500 * 1024 * 1024; // 500 MB
  const INACTIVITY_TIMEOUT_MS = 30_000;     // 30s idle stall timeout
  const controller = new AbortController();
  let idleTimeout;

  const resetIdleTimeout = () => {
    clearTimeout(idleTimeout);
    idleTimeout = setTimeout(() => controller.abort(), INACTIVITY_TIMEOUT_MS);
  };
  resetIdleTimeout();

  // Multi-strategy fetch: CDNs like AWS CloudFront/S3 have wildly different CORS policies.
  // Try multiple credential & header combos to maximise the chance of a successful stream.
  const strategies = [
    { credentials: "omit",    redirect: "follow", signal: controller.signal },
    { credentials: "include", redirect: "follow", signal: controller.signal },
    { credentials: "omit",    redirect: "follow", signal: controller.signal, headers: { "Accept": "*/*" } },
    { credentials: "include", redirect: "follow", signal: controller.signal, cache: "no-store" },
  ];

  try {
    let response = null;

    for (let i = 0; i < strategies.length; i++) {
      try {
        const r = await fetch(url, strategies[i]);
        if (r.ok) {
          response = r;
          break;
        }
        // Non-ok (403, 401, etc.) — log and try next strategy
        console.warn(`[ThreatLens Hash] Strategy ${i + 1}/${strategies.length} returned HTTP ${r.status} for ${url.substring(0, 100)}`);
      } catch (fetchErr) {
        // Network/CORS throw — log and try next strategy
        if (fetchErr?.name === "AbortError") throw fetchErr; // Propagate abort
        console.warn(`[ThreatLens Hash] Strategy ${i + 1}/${strategies.length} threw: ${fetchErr.message}`);
      }
    }

    if (!response) {
      console.warn(`[ThreatLens Hash] All ${strategies.length} fetch strategies exhausted for ${url.substring(0, 100)}`);
      clearTimeout(idleTimeout);
      return null;
    }

    // Fast-reject via Content-Length when available (skip streaming entirely)
    const declaredSize = Number(response.headers.get("content-length")) || 0;
    if (declaredSize > MAX_SIZE_BYTES) {
      console.warn("ThreatLens File Hash skipped: Content-Length exceeds 500MB limit");
      clearTimeout(idleTimeout);
      return null;
    }

    const reader = response.body?.getReader();
    if (!reader) {
      // Fallback for environments where ReadableStream is unavailable
      if (!declaredSize || declaredSize > FALLBACK_ARRAY_BUFFER_MAX_BYTES) {
        console.warn("ThreatLens File Hash skipped: browser stream API unavailable and fallback would require an unsafe memory load");
        clearTimeout(idleTimeout);
        return null;
      }

      const buf = await response.arrayBuffer();
      clearTimeout(idleTimeout);
      if (buf.byteLength > MAX_SIZE_BYTES) return null;
      const hashDigest = await crypto.subtle.digest("SHA-256", buf);
      const hashHex = hexFromBuffer(hashDigest);

      // Compute entropy and magic bytes from the full buffer
      const bytes = new Uint8Array(buf);
      const fallbackByteCounts = new Uint32Array(256);
      for (let i = 0; i < bytes.length; i++) {
        fallbackByteCounts[bytes[i]]++;
      }
      let fallbackEntropy = 0;
      if (bytes.length > 0) {
        for (let i = 0; i < 256; i++) {
          if (fallbackByteCounts[i] > 0) {
            const p = fallbackByteCounts[i] / bytes.length;
            fallbackEntropy -= p * Math.log2(p);
          }
        }
      }
      let fallbackMagic = "unknown";
      if (bytes.length >= 4) {
        const magic = Array.from(bytes.slice(0, 4))
          .map(b => b.toString(16).padStart(2, '0').toUpperCase())
          .join(' ');
        if (magic.startsWith("4D 5A")) fallbackMagic = "executable";
        else if (magic.startsWith("25 50 44 46")) fallbackMagic = "pdf";
        else if (magic.startsWith("50 4B 03 04")) fallbackMagic = "zip/office";
        else if (magic.startsWith("7F 45 4C 46")) fallbackMagic = "elf";
        else if (magic.startsWith("D0 CF 11 E0")) fallbackMagic = "office_legacy";
        else if (magic.startsWith("89 50 4E 47")) fallbackMagic = "png";
        else if (magic.startsWith("FF D8 FF")) fallbackMagic = "jpg";
      }

      const peAnalysis = analyzePeHeader(bytes.slice(0, PE_HEADER_ANALYSIS_BYTES));
      const tlsh = new TLSH();
      tlsh.update(bytes);
      const tlshHash = tlsh.digest();

      return {
        hash: hashHex,
        entropy: fallbackEntropy,
        magicMime: peAnalysis.magicMime || fallbackMagic,
        tlshHash,
        fuzzyHash: createFuzzyHashMetadata(tlshHash),
        ...peAnalysis
      };
    }

    let totalBytes = 0;
    const hasher = new SHA256();
    let lastReportTime = 0;

    const byteCounts = new Uint32Array(256);
    let magicMime = "unknown";
    let isFirstChunk = true;
    let headerBytes = new Uint8Array(0);
    const tlsh = new TLSH();

    while (true) {
      const { done, value } = await reader.read();
      resetIdleTimeout(); // Reset the idle timer because bytes are flowing

      if (done) break;

      totalBytes += value.byteLength;
      if (totalBytes > MAX_SIZE_BYTES) {
        reader.cancel();
        console.warn("ThreatLens File Hash skipped: Stream exceeded 500MB limit");
        clearTimeout(idleTimeout);
        return null;
      }

      if (isFirstChunk && value.length >= 4) {
        isFirstChunk = false;
        const magic = Array.from(value.slice(0, 4))
          .map(b => b.toString(16).padStart(2, '0').toUpperCase())
          .join(' ');
        
        if (magic.startsWith("4D 5A")) magicMime = "executable"; // MZ
        else if (magic.startsWith("25 50 44 46")) magicMime = "pdf"; // %PDF
        else if (magic.startsWith("50 4B 03 04")) magicMime = "zip/office"; // PK (zip/docx/xlsx)
        else if (magic.startsWith("7F 45 4C 46")) magicMime = "elf"; // ELF
        else if (magic.startsWith("D0 CF 11 E0")) magicMime = "office_legacy"; // doc/xls
        else if (magic.startsWith("89 50 4E 47")) magicMime = "png";
        else if (magic.startsWith("FF D8 FF")) magicMime = "jpg";
      }

      for (let i = 0; i < value.length; i++) {
        byteCounts[value[i]]++;
      }

      headerBytes = appendPrefixBytes(headerBytes, value, PE_HEADER_ANALYSIS_BYTES);
      tlsh.update(value);

      // Hash chunk incrementally (avoids keeping entire file in RAM)
      hasher.update(value);

      if (onProgress) {
        const now = Date.now();
        // Throttle progress updates to ~4fps to prevent heavy storage/UI thrashing
        if (now - lastReportTime > 250) {
          lastReportTime = now;
          onProgress(totalBytes, declaredSize);
        }
      }
    }

    if (onProgress) {
      onProgress(totalBytes, declaredSize);
    }

    clearTimeout(idleTimeout);
    
    let entropy = 0;
    if (totalBytes > 0) {
      for (let i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
          const p = byteCounts[i] / totalBytes;
          entropy -= p * Math.log2(p);
        }
      }
    }

    const peAnalysis = analyzePeHeader(headerBytes);
    const tlshHash = tlsh.digest();

    return {
      hash: hasher.digest(),
      entropy,
      magicMime: peAnalysis.magicMime || magicMime,
      tlshHash,
      fuzzyHash: createFuzzyHashMetadata(tlshHash),
      ...peAnalysis
    };
  } catch (error) {
    clearTimeout(idleTimeout);
    if (error?.name === "AbortError") {
      console.warn("ThreatLens File Hash timed out after 30s of network inactivity");
    } else {
      console.warn("ThreatLens File Hash failed (CORS or Network):", error);
    }
    return null;
  }
}

function appendPrefixBytes(existing, chunk, maxBytes) {
  if (existing.length >= maxBytes) return existing;

  const remaining = maxBytes - existing.length;
  const take = Math.min(remaining, chunk.length);
  const next = new Uint8Array(existing.length + take);
  next.set(existing, 0);
  next.set(chunk.subarray(0, take), existing.length);
  return next;
}

function createFuzzyHashMetadata(hash) {
  return {
    algorithm: FUZZY_HASH_ALGORITHM,
    hash: hash || "",
    browserSafe: true,
    officialTlshCompatible: false,
    purpose: "Locality-sensitive similarity signal for clustering polymorphic payload variants."
  };
}

export function analyzePeHeader(headerBytes) {
  const bytes = headerBytes instanceof Uint8Array ? headerBytes : new Uint8Array(headerBytes || []);
  const magicMime = detectMagicMime(bytes);

  if (bytes.length < 2 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
    return {
      magicMime,
      isPeFile: false,
      peAnalysisStatus: "not_pe",
      peSections: [],
      peAnomalies: [],
      peAnomalyDetails: []
    };
  }

  const peAnomalies = [];
  const peAnomalyDetails = [];
  const addPeAnomaly = (code, severity, message, evidence = {}) => {
    peAnomalies.push(message);
    peAnomalyDetails.push({ code, severity, message, evidence });
  };

  if (bytes.length < 64) {
    addPeAnomaly("pe_dos_header_truncated", "medium", "MZ header found, but the DOS header is too short to locate a PE signature.");
    return { magicMime: "executable", isPeFile: false, peAnalysisStatus: "truncated", peSections: [], peAnomalies, peAnomalyDetails };
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset < 64 || peOffset + 24 > bytes.length) {
    addPeAnomaly(
      "pe_header_offset_out_of_window",
      "medium",
      `MZ header found, but PE header offset 0x${peOffset.toString(16)} is outside the inspected ${formatBytes(PE_HEADER_ANALYSIS_BYTES)} header window.`,
      { peOffset, inspectedHeaderBytes: bytes.length }
    );
    return { magicMime: "executable", isPeFile: false, peAnalysisStatus: "truncated", peSections: [], peAnomalies, peAnomalyDetails };
  }

  const hasPeSignature =
    bytes[peOffset] === 0x50 &&
    bytes[peOffset + 1] === 0x45 &&
    bytes[peOffset + 2] === 0x00 &&
    bytes[peOffset + 3] === 0x00;

  if (!hasPeSignature) {
    addPeAnomaly("pe_signature_missing", "high", "MZ header found, but the expected PE signature was missing at the declared header offset.", { peOffset });
    return { magicMime: "executable", isPeFile: false, peAnalysisStatus: "malformed", peSections: [], peAnomalies, peAnomalyDetails };
  }

  const machine = view.getUint16(peOffset + 4, true);
  const sectionCount = view.getUint16(peOffset + 6, true);
  const optionalHeaderSize = view.getUint16(peOffset + 20, true);
  const sectionTableOffset = peOffset + 24 + optionalHeaderSize;
  const peSections = [];

  if (sectionCount === 0) {
    addPeAnomaly("pe_zero_sections", "high", "PE header declares zero sections.");
  }
  if (sectionCount > 96) {
    addPeAnomaly("pe_excessive_section_count", "medium", `PE header declares an unusually high section count (${sectionCount}).`, { sectionCount });
  }

  const parseableSections = Math.min(sectionCount, 96);
  for (let index = 0; index < parseableSections; index++) {
    const offset = sectionTableOffset + (index * 40);
    if (offset + 40 > bytes.length) {
      addPeAnomaly(
        "pe_section_table_truncated",
        "medium",
        `PE section table is truncated after ${peSections.length}/${sectionCount} section headers in the inspected ${formatBytes(PE_HEADER_ANALYSIS_BYTES)} header window.`,
        { parsedSections: peSections.length, sectionCount }
      );
      break;
    }

    const name = readPeSectionName(bytes.subarray(offset, offset + 8)) || `(section ${index + 1})`;
    const virtualSize = view.getUint32(offset + 8, true);
    const rawSize = view.getUint32(offset + 16, true);
    const rawPointer = view.getUint32(offset + 20, true);
    const characteristics = view.getUint32(offset + 36, true);

    peSections.push({
      name,
      rawSize,
      virtualSize,
      rawPointer,
      characteristics: `0x${characteristics.toString(16).padStart(8, "0")}`
    });
  }

  const sectionAnomalies = detectPeSectionAnomalies(peSections);
  for (const anomaly of sectionAnomalies) {
    peAnomalies.push(anomaly.message);
    peAnomalyDetails.push(anomaly);
  }

  return {
    magicMime: "executable",
    isPeFile: true,
    peAnalysisStatus: peSections.length === sectionCount ? "complete" : "partial",
    peHeader: {
      machine: `0x${machine.toString(16).padStart(4, "0")}`,
      sectionCount,
      optionalHeaderSize,
      inspectedHeaderBytes: bytes.length
    },
    peSections,
    peAnomalies: [...new Set(peAnomalies)],
    peAnomalyDetails: dedupePeAnomalyDetails(peAnomalyDetails)
  };
}

function detectMagicMime(bytes) {
  if (!bytes || bytes.length < 4) return "unknown";

  const magic = Array.from(bytes.slice(0, 4))
    .map(b => b.toString(16).padStart(2, "0").toUpperCase())
    .join(" ");

  if (magic.startsWith("4D 5A")) return "executable";
  if (magic.startsWith("25 50 44 46")) return "pdf";
  if (magic.startsWith("50 4B 03 04")) return "zip/office";
  if (magic.startsWith("7F 45 4C 46")) return "elf";
  if (magic.startsWith("D0 CF 11 E0")) return "office_legacy";
  if (magic.startsWith("89 50 4E 47")) return "png";
  if (magic.startsWith("FF D8 FF")) return "jpg";
  return "unknown";
}

function readPeSectionName(nameBytes) {
  let name = "";
  for (const value of nameBytes) {
    if (value === 0) break;
    if (value >= 32 && value <= 126) {
      name += String.fromCharCode(value);
    }
  }
  return name.trim();
}

function detectPeSectionAnomalies(peSections) {
  const anomalies = [];
  if (!Array.isArray(peSections) || peSections.length === 0) {
    return anomalies;
  }

  const suspiciousSectionPatterns = [
    /^\.?upx/i,
    /^\.?themida/i,
    /^\.?aspack/i,
    /^\.?mpress/i,
    /^\.?vmp/i,
    /^\.?enigma/i,
    /^\.?petite/i,
    /^\.?packed/i,
    /^\.?yzpack/i,
    /^\.?nsp/i
  ];

  let codeSize = 0;
  let dataSize = 0;

  for (const section of peSections) {
    const name = String(section.name || "");
    const normalized = name.toLowerCase();
    const rawSize = Number(section.rawSize || 0);
    const virtualSize = Number(section.virtualSize || 0);
    const effectiveSize = Math.max(rawSize, virtualSize);
    const characteristics = parseInt(String(section.characteristics || "0").replace(/^0x/i, ""), 16) || 0;
    const isCode = Boolean(characteristics & 0x00000020) || normalized.includes("text") || normalized.includes("code");
    const isData = Boolean(characteristics & 0x00000040) ||
      Boolean(characteristics & 0x00000080) ||
      [".data", ".rdata", ".rsrc", ".reloc", ".bss"].some((prefix) => normalized.startsWith(prefix));

    if (isCode) codeSize += effectiveSize;
    if (isData) dataSize += effectiveSize;

    if (suspiciousSectionPatterns.some((pattern) => pattern.test(normalized))) {
      anomalies.push({
        code: "pe_suspicious_section_name",
        severity: "high",
        message: `Suspicious PE section name "${name}" is commonly associated with packers or protectors.`,
        evidence: { sectionName: name, rawSize, virtualSize }
      });
    }

    if (rawSize > 0 && virtualSize > rawSize * 8 && virtualSize - rawSize > 1024 * 1024) {
      anomalies.push({
        code: "pe_section_memory_expansion",
        severity: "medium",
        message: `PE section "${name}" expands from ${formatBytes(rawSize)} on disk to ${formatBytes(virtualSize)} in memory.`,
        evidence: { sectionName: name, rawSize, virtualSize }
      });
    }
  }

  if (codeSize > 0 && dataSize > 1024 * 512 && dataSize / codeSize >= 10) {
    anomalies.push({
      code: "pe_data_code_disproportion",
      severity: "medium",
      message: `PE data/resource sections (${formatBytes(dataSize)}) outweigh code sections (${formatBytes(codeSize)}) by ${(dataSize / codeSize).toFixed(1)}x.`,
      evidence: { codeSize, dataSize, ratio: dataSize / codeSize }
    });
  }

  if (dataSize > 0 && codeSize > 1024 * 512 && codeSize / dataSize >= 20) {
    anomalies.push({
      code: "pe_code_data_disproportion",
      severity: "low",
      message: `PE code sections (${formatBytes(codeSize)}) outweigh data sections (${formatBytes(dataSize)}) by ${(codeSize / dataSize).toFixed(1)}x.`,
      evidence: { codeSize, dataSize, ratio: codeSize / dataSize }
    });
  }

  return dedupePeAnomalyDetails(anomalies);
}

function dedupePeAnomalyDetails(anomalies) {
  const seen = new Set();
  return anomalies.filter((anomaly) => {
    const key = `${anomaly.code}:${anomaly.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${bytes}B`;
}



export function calculateStringEntropy(str) {
  if (!str) return 0;
  const chars = {};
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    chars[c] = (chars[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in chars) {
    const p = chars[c] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
