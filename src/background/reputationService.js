import {
  buildUrlscanSearchUrl,
  buildVirusTotalAnalysisUrl,
  buildVirusTotalReportUrl,
  getSearchableUrl,
  getBestScanUrl,
  getRiskLabel,
  isHighRiskExtension,
  parseUrl
} from "../shared/utils.js";

const VT_API_BASE = "https://www.virustotal.com/api/v3";
const URLSCAN_SEARCH_API = "https://urlscan.io/api/v1/search/";

export async function runVirusTotalLookup(record, config, options = {}) {
  const apiKey = String(config?.integrations?.virusTotal?.apiKey || "").trim();
  const targetUrl = getBestScanUrl(record);
  const preferHash = Boolean(options?.preferHash && record?.fileHash);
  const lookupType = preferHash ? "file" : "url";

  const hostname = parseUrl(targetUrl)?.hostname || "";
  let domainInfo = { creationDate: null, registrar: null };

  // Phase 1: Removed blocking fetchRdapDomain call from here.
  // This is now handled by a parallel runDomainAudit worker in downloadHandler.

  if (!apiKey) {
    return {
      status: "not_configured",
      provider: "VirusTotal",
      verdict: "unknown",
      summary: "Add a VirusTotal API key in Settings if you want inline security results.",
      checkedAt: new Date().toISOString(),
      reportId: "",
      reportUrl: "",
      analysisId: "",
      analysisUrl: "",
      targetUrl,
      stats: createEmptyStats(),
      lookupType,
      ...mapDomainDetailsToStatus(domainInfo)
    };
  }

  if (!targetUrl) {
    return {
      status: "unsupported",
      provider: "VirusTotal",
      summary: "ThreatLens could not extract a valid URL for reputation lookup.",
      checkedAt: new Date().toISOString(),
      reportId: "",
      reportUrl: "",
      analysisId: "",
      analysisUrl: "",
      targetUrl,
      stats: createEmptyStats(),
      lookupType
    };
  }

  const lookupId = toVirusTotalUrlId(targetUrl);

  if (preferHash) {
    const safeHash = (typeof record.fileHash === "object" && record.fileHash !== null) ? record.fileHash.hash : record.fileHash;
    try {
      const hashPayload = await vtFetchJson(`/files/${safeHash}`, apiKey);
      const res = mapVirusTotalReport(hashPayload.data, targetUrl, domainInfo.creationDate, domainInfo.registrar, "file");
      res.hashChecked = true;
      return res;
    } catch (error) {
      if (error.status === 404) {
        return mapVirusTotalHashNotFound(safeHash, targetUrl);
      } else {
        return mapLookupError(error, targetUrl, "", "", "file");
      }
    }
  }

  const existingUrlReport = record?.providerReports?.virusTotalUrl || (
    record?.reputation?.provider === "VirusTotal" && (record.reputation.lookupType === "url" || !record.reputation.lookupType)
      ? record.reputation
      : null
  );
  if (existingUrlReport?.status === "complete") {
     return existingUrlReport;
  }

  try {
    const reportPayload = await vtFetchJson(`/urls/${lookupId}`, apiKey);
    return mapVirusTotalReport(reportPayload.data, targetUrl, domainInfo.creationDate, domainInfo.registrar, "url");
  } catch (error) {
    if (error.status !== 404) {
      return mapLookupError(error, targetUrl, "", "", "url");
    }
  }

  try {
    const analysisPayload = await vtFetchJson("/urls", apiKey, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        url: targetUrl
      }).toString()
    });

    const analysisId = analysisPayload?.data?.id || "";
    const analysisUrl = buildVirusTotalAnalysisUrl(analysisId);

    return {
      status: "queued",
      provider: "VirusTotal",
      verdict: "unknown",
      summary: "VirusTotal research has been initiated; the analysis report is being generated.",
      checkedAt: new Date().toISOString(),
      reportId: "",
      reportUrl: "",
      analysisId,
      analysisUrl,
      targetUrl,
      stats: createEmptyStats(),
      lookupType: "url",
      lookupId // Include this so the background handler can poll
    };
  } catch (error) {
    return mapLookupError(error, targetUrl, "", "", "url");
  }
}

/**
 * Specifically checks an existing URL ID for a completed analysis.
 * Meant to be called by a detached background loop in the orchestrator.
 */
export async function pollVirusTotalResult(lookupId, targetUrl, config, domainInfo = { creationDate: null, registrar: null }, analysisId = "", analysisUrl = "") {
  const apiKey = String(config?.integrations?.virusTotal?.apiKey || "").trim();
  if (!apiKey) return null;

  try {
    const reportPayload = await vtFetchJson(`/urls/${lookupId}`, apiKey);
    const stats = reportPayload.data?.attributes?.last_analysis_stats || {};
    const totalEngines = Object.values(stats).reduce((sum, value) => sum + Number(value || 0), 0);

    if (totalEngines > 0) {
      return {
        ...mapVirusTotalReport(reportPayload.data, targetUrl, domainInfo.creationDate, domainInfo.registrar),
        lookupType: "url",
        analysisId,
        analysisUrl
      };
    }
    return null; // Still computing
  } catch (error) {
    if (error.status !== 404) {
      return mapLookupError(error, targetUrl, analysisId, analysisUrl, "url");
    }
    return null; // 404 = still not computed
  }
}

export async function runVirusTotalIpLookup(ip, config) {
  const apiKey = String(config?.integrations?.virusTotal?.apiKey || "").trim();
  if (!apiKey) return { status: "not_configured", ip };
  if (!ip) return { status: "unsupported" };

  try {
    const response = await fetchWithTimeout(`${VT_API_BASE}/ip_addresses/${encodeURIComponent(ip)}`, {
      headers: {
        Accept: "application/json",
        "x-apikey": apiKey
      }
    }, 10_000);
    if (!response.ok) return { status: "error", summary: "VirusTotal IP reputation lookup failed." };
    
    const { data } = await response.json();
    const attributes = data?.attributes || {};
    const stats = {
      ...createEmptyStats(),
      ...(attributes.last_analysis_stats || {})
    };
    
    return {
      status: "complete",
      ip,
      stats,
      owner: attributes.as_owner || "Unknown Hosting Provider",
      country: attributes.country || ""
    };
  } catch (error) {
    return {
      status: "error",
      summary: error?.name === "AbortError"
        ? "VirusTotal IP reputation lookup timed out."
        : "VirusTotal IP reputation lookup failed."
    };
  }
}

export async function fetchRdapIp(ip) {
  if (!ip) {
    return {
      status: "error",
      owner: null,
      country: "",
      asn: null,
      networkName: null
    };
  }

  try {
    const response = await fetchWithTimeout(`https://rdap.net/ip/${encodeURIComponent(ip)}`, {
      headers: {
        Accept: "application/rdap+json"
      }
    }, 6_000);

    if (!response.ok) {
      return {
        status: "error",
        owner: null,
        country: "",
        asn: null,
        networkName: null
      };
    }

    const data = await response.json();
    const registrantEntity = findRdapEntityByRole(data.entities, ["registrant", "registrar", "administrative"]);
    const owner = getRdapEntityName(registrantEntity) || String(data.name || data.handle || "").trim() || null;
    const country = normalizeCountryCode(getRdapEntityCountry(registrantEntity) || data.country || "");
    const asn = parseAutnum(data.startAutnum, data.endAutnum);
    const networkName = String(data.name || "").trim() || null;

    return {
      status: "complete",
      owner,
      country,
      asn,
      networkName
    };
  } catch {
    return {
      status: "error",
      owner: null,
      country: "",
      asn: null,
      networkName: null
    };
  }
}

export async function openManualProvider(provider, record, config) {
  switch (provider) {
    case "virustotal": {
      return await runVirusTotalLookup(record, config);
    }
    case "urlscan": {
      const targetUrl = getBestScanUrl(record);
      return await findUrlscanReport(targetUrl);
    }
    case "vt_ip": {
      return await runVirusTotalIpLookup(record.targetIp, config);
    }
    default:
      throw new Error("Unsupported reputation provider.");
  }
}

export function calculateUnifiedVerdict(record) {
  const reputation = record.reputation || {};
  const vtUrlReport = getVirusTotalUrlReport(record);
  const vtFileReport = getVirusTotalFileReport(record);
  const completedVtReports = [vtUrlReport, vtFileReport].filter((report) => report?.status === "complete");
  const urlscan = record.providerReports?.urlscan || {};
  const ipRep = record.providerReports?.ipReputation;
  const ipScanStatus = ipRep?.scanStatus || ipRep?.status || "idle";
  
  const isVtLoading = [reputation, vtUrlReport, vtFileReport].some((report) =>
    report?.status === "loading" || report?.status === "queued"
  );
  const isUrlscanLoading = urlscan.status === "loading";

  // Updated: Only return 'Checking' if we are actually still in a loading state.
  // If we hit a timeout or error, we should proceed to evaluate based on available data.
  if (isVtLoading || isUrlscanLoading) {
    return {
      indicator: "Checking",
      reason: [
        "Infrastructure Audit: Actively scanning target servers... ↻",
        "VirusTotal Engines: Correlating global security consensus... ↻",
        "Network Reputation: Evaluating historical server associations... ↻"
      ]
    };
  }

  const vtMalicious = Math.max(0, ...completedVtReports.map((report) => Number(report.stats?.malicious || 0)));
  const vtSuspicious = Math.max(0, ...completedVtReports.map((report) => Number(report.stats?.suspicious || 0)));
  const urlscanMalicious = urlscan.verdict === "malicious";
  const urlscanScore = Number(urlscan.score || 0);
  const totalVtEngines = Math.max(0, ...completedVtReports.map(getVirusTotalEngineCount));
  
  const domainMetadata = record.domainMetadata || {};
  const isNewDomain = domainMetadata.isNewDomain === true;
  const urlDetails = vtUrlReport?.details || reputation.details || {};
  const vtCategories = urlDetails.categories ? Object.values(urlDetails.categories).join(" ").toLowerCase() : "";
  const firstCategory = urlDetails.categories ? Object.values(urlDetails.categories)[0] : "Unknown";
  
  const ipMalicious = ipScanStatus === "complete" ? (ipRep?.stats?.malicious || 0) : 0;
  
  const fileExtRaw = record.extension || "";
  let fileExt = fileExtRaw ? fileExtRaw.replace(".", "").toUpperCase() : "";
  if (!fileExt && record.fileName) {
    const extMatch = record.fileName.match(/\.([a-z0-9]{2,5})(?:[?#]|$)/i);
    if (extMatch) fileExt = extMatch[1].toUpperCase();
  }
  fileExt = fileExt || "FILE"; 

  const isExecutable = /\.(exe|msi|dmg|apk|vbs|scr|js|bat|cmd|ps1)$/i.test(record.fileName || "") || 
                       /\.(exe|msi|dmg|apk|vbs|scr|js|bat|cmd|ps1)$/i.test(fileExtRaw);
  
  const isUnusualSize = (fileExt === "JPG" || fileExt === "PNG") && record.totalBytes > 10 * 1024 * 1024;
  const isSocialOrSearch = vtCategories.includes("social") || vtCategories.includes("search engine") || vtCategories.includes("portal") || vtCategories.includes("messaging");

  const peAnomalies = Array.isArray(record.peAnomalies) ? record.peAnomalies.filter(Boolean) : [];
  const peAnomalyDetails = Array.isArray(record.peAnomalyDetails) ? record.peAnomalyDetails : [];
  const hasHighSeverityPeAnomaly = peAnomalyDetails.some((anomaly) => anomaly?.severity === "high") ||
    peAnomalies.some((anomaly) => /packer|protector|upx|themida|aspack|mpress|vmp|enigma|packed/i.test(String(anomaly)));

  let reasons = [];
  let indicator = "Unknown";

  if (record.isDriveBy) {
    reasons.push(`Critical Attack Vector: No trusted human click was observed within 2 seconds before this download started.`);
  }

  if (reputation.status === "not_configured") {
    reasons.push(`OSINT core analysis is running with supplementary providers only (Add a VirusTotal API key in Settings).`);
  } else if (vtMalicious >= 2) {
    reasons.push(`VirusTotal engines flagged this as <b>Malicious</b>.`);
  } else if (vtMalicious === 1 || vtSuspicious > 0) {
    reasons.push(`VirusTotal engines flagged this as <b>Suspicious</b>.`);
  } else if (totalVtEngines > 0) {
    reasons.push(`VirusTotal engines did not detect known malware signatures.`);
  }

  if (isUnusualSize) {
    reasons.push(`The ${fileExt} file has an unusually large size (${(record.totalBytes / 1024 / 1024).toFixed(1)}MB).`);
  }

  if (isExecutable && isSocialOrSearch) {
    reasons.push(`Dangerous executable (${fileExt}) originating from a ${firstCategory} website.`);
  }

  if (record.fileHashStatus === "complete" && record.fileHash) {
    reasons.push(`ThreatLens generated a Zero-Disk SHA-256 fingerprint for this file.`);
  }
  if (record.tlshHash) {
    reasons.push(`ThreatLens generated a TLSH-style fuzzy fingerprint for polymorphic malware correlation.`);
  }

  // --- Static AI Rules ---
  if (record.fileEntropy > 7.2) {
    reasons.push(`Static AI Warning: This file exhibits highly anomalous entropy (${record.fileEntropy.toFixed(2)}), which is a common indicator of packed or encrypted malware.`);
  }

  if (record.magicMime && record.magicMime !== "unknown") {
    const extRaw = fileExt.toLowerCase();
    if ((extRaw === "pdf" || extRaw === "txt" || extRaw === "jpg" || extRaw === "png" || extRaw === "docx") && record.magicMime === "executable") {
      reasons.push(`Static AI Warning: File extension spoofing detected! The filename implies a safe document, but the internal structure is a Windows Executable.`);
    }
  }

  for (const anomaly of peAnomalies) {
    reasons.push(`PE Header Warning: ${anomaly}`);
  }

  if (isNewDomain) {
    reasons.push(`The domain hosting this file was registered very recently.`);
  } else if (domainMetadata.creationDate) {
    reasons.push(`The domain hosting this file has an established registration history.`);
  }

  if (ipRep && ipRep.owner && ipScanStatus === "complete") {
    let flagEmoji = "";
    if (/^[A-Z]{2}$/.test(String(ipRep.country || "").toUpperCase())) {
      flagEmoji = ipRep.country.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
    }
    if (ipMalicious >= 2) {
      reasons.push(`The server IP (${ipRep.ip}) is owned by ${ipRep.owner} ${flagEmoji} and flagged Malicious.`);
    } else {
      reasons.push(`The server IP (${ipRep.ip}) is owned by ${ipRep.owner} ${flagEmoji} and is not flagged.`);
    }
  } else if (ipRep && ipRep.ip && ipScanStatus === "complete") {
    if (ipMalicious >= 2) {
      reasons.push(`The server IP (${ipRep.ip}) was flagged Malicious, but ASN ownership was not publicly exposed.`);
    } else {
      reasons.push(`The server IP (${ipRep.ip}) completed reputation checks, but ASN ownership was not publicly exposed.`);
    }
  } else if (ipRep && ipRep.owner && (ipScanStatus === "error" || ipScanStatus === "not_configured" || ipScanStatus === "unsupported")) {
    reasons.push(`The server IP (${ipRep.ip}) is owned by ${ipRep.owner}, but the IP threat scan was unavailable.`);
  } else if (ipRep && (ipScanStatus === "error" || ipScanStatus === "not_configured" || ipScanStatus === "unsupported")) {
    reasons.push(`The server IP reputation lookup could not be completed, so ThreatLens continued with the remaining evidence.`);
  }

  if (record.isDriveBy || hasHighSeverityPeAnomaly || vtMalicious >= 1 || urlscanMalicious || ipMalicious >= 1) {
    indicator = "Malicious";
  } else if (vtSuspicious >= 1 || urlscanScore >= 50 || (ipRep && ipRep.stats && ipRep.stats.suspicious >= 1) || (isExecutable && isSocialOrSearch) || isNewDomain || peAnomalies.length > 0) {
    indicator = "Suspicious";
  } else if (totalVtEngines > 0 || urlscanScore > 0 || (ipRep && ipRep.status === "complete")) {
    indicator = "Clean";
  } else {
    indicator = "Unknown";
  }

  return { indicator, reason: reasons };
}

export function getStreamingReasons(record, config = {}) {
  const reputation = record.reputation || {};
  const vtUrlReport = getVirusTotalUrlReport(record) || {};
  const vtFileReport = getVirusTotalFileReport(record) || {};
  const urlscan = record.providerReports?.urlscan || {};
  const ipRep = record.providerReports?.ipReputation || {};
  
  const sourceStatus = vtUrlReport.status || (reputation.lookupType === "file" ? "idle" : reputation.status) || "idle";
  const hashVtStatus = vtFileReport.status || (reputation.lookupType === "file" ? reputation.status : "idle") || "idle";
  const ipStatus = ipRep?.status || "idle";
  const ipScanStatus = ipRep?.scanStatus || ipStatus;
  const hashStatus = record.fileHashStatus || "idle";
  const hasVirusTotalKey = Boolean(String(config?.integrations?.virusTotal?.apiKey || "").trim());
  
  const reasons = [];
  reasons.push(`Security Interception: ThreatLens has safely quarantined this download for a multi-stage security audit.`);

  if (record.isDriveBy) {
    reasons.push(`Critical Attack Vector: Drive-by download behavior detected — no trusted human click was captured within 2 seconds of initiation. !`);
  }

  // 1. Source URL (First Priority)
  if (!hasVirusTotalKey || sourceStatus === "not_configured") {
    reasons.push(`Source URL: Add a VirusTotal API key in Settings for inline URL reputation !`);
  } else if (sourceStatus === "loading" || sourceStatus === "queued" || sourceStatus === "idle") {
    reasons.push(`Source URL: Analyzing destination against 94 global security vendors... ↻`);
  } else if (sourceStatus === "complete") {
    const isTimeout = vtUrlReport.summary && vtUrlReport.summary.includes("too long");
    
    if (isTimeout) {
      reasons.push(`Source URL: Global vendor consensus took too long; continuing with partial intel !`);
    } else {
      const malicious = vtUrlReport.stats?.malicious || 0;
      const suspicious = vtUrlReport.stats?.suspicious || 0;
      const total = getVirusTotalEngineCount(vtUrlReport);
      const hashStillRunning = hashStatus === "loading" || hashStatus === "idle";
      if (malicious >= 1) {
        reasons.push(`Source URL: VirusTotal engines flagged this destination as <b>Malicious</b> (${malicious}/${total}) !`);
      } else if (suspicious >= 1) {
        reasons.push(`Source URL: Global vendors flagged this source as <b>Suspicious</b> (${suspicious}/${total}) !`);
      } else if (hashStillRunning) {
        // Hold the clean verdict — hash-based VT check may upgrade this result
        reasons.push(`Source URL: URL scan complete — verifying file fingerprint against threat databases... ↻`);
      } else {
        reasons.push(`Source URL: Global security vendors did not detect known malware signatures (0/${total}) ✓`);
      }
    }
  } else if (sourceStatus === "error" || sourceStatus === "unsupported") {
    reasons.push(`Source URL: Provider lookup was unavailable for this URL !`);
  }

  // 2. Network Infrastructure (IP / Owner)
  const resolvedIp = ipRep.ip || urlscan.pageIp || "";

  if (ipRep.owner && ipScanStatus === "complete") {
    const malicious = ipRep.stats?.malicious || 0;
    const flagEmoji = /^[A-Z]{2}$/.test(String(ipRep.country || "").toUpperCase())
      ? ipRep.country.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397))
      : "";
    reasons.push(`Network Owner: Host server (${resolvedIp || "resolved host"}) is owned by ${ipRep.owner} ${flagEmoji} (Vendor Flags: ${malicious}) ${malicious >= 2 ? '!' : '✓'}`);
  } else if (ipScanStatus === "complete" && resolvedIp) {
    const malicious = Number(ipRep.stats?.malicious || 0);
    const suspicious = Number(ipRep.stats?.suspicious || 0);
    if (malicious > 0) {
      reasons.push(`Network Reputation: Server IP (${resolvedIp}) was flagged malicious by ${malicious} vendors; ASN owner was not exposed. !`);
    } else if (suspicious > 0) {
      reasons.push(`Network Reputation: Server IP (${resolvedIp}) was flagged suspicious by ${suspicious} vendors; ASN owner was not exposed. !`);
    } else {
      reasons.push(`Network Reputation: Server IP (${resolvedIp}) completed reputation checks with no malicious flags; ASN owner was not exposed. ✓`);
    }
  } else if (ipRep.owner && (ipScanStatus === "error" || ipScanStatus === "not_configured" || ipScanStatus === "unsupported")) {
    const flagEmoji = /^[A-Z]{2}$/.test(String(ipRep.country || "").toUpperCase())
      ? ipRep.country.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397))
      : "";
    reasons.push(`Network Owner: Host server (${resolvedIp || "resolved host"}) is owned by ${ipRep.owner} ${flagEmoji}; IP threat scan unavailable.`);
  } else if (ipScanStatus === "not_configured" && resolvedIp) {
    reasons.push(`Network Reputation: Server IP (${resolvedIp}) resolved; VirusTotal IP scan requires an API key.`);
  } else if (ipScanStatus === "unsupported" && resolvedIp) {
    reasons.push(`Network Reputation: Server IP (${resolvedIp}) resolved; provider does not support this IP scan.`);
  } else if ((ipScanStatus === "error" || ipStatus === "error") && resolvedIp) {
    reasons.push(`Network Reputation: Server IP (${resolvedIp}) was resolved, but reputation lookup was unavailable. !`);
  } else if ((ipStatus === "loading" || ipStatus === "queued") || (ipScanStatus === "loading" || ipScanStatus === "queued")) {
    reasons.push(`Network Reputation: Evaluating server IP for historical malicious associations... ↻`);
  } else if (resolvedIp) {
    reasons.push(`Network Reputation: Server IP (${resolvedIp}) was discovered; reputation audit is queued to start.`);
  } else {
    reasons.push(`Network Resolution: Resolving target server IP and infrastructure footprint... ↻`);
  }

  // 3. File Hash Consistency
  if (hashStatus === "loading") {
    const progress = record.fileHashProgress ? ` (${record.fileHashProgress})` : "";
    reasons.push(`SHA-256 Audit: Downloading to secure sandbox and generating fingerprint${progress}... ↻`);
  } else if (hashStatus === "complete" && record.fileHash) {
    if (!hasVirusTotalKey || hashVtStatus === "not_configured") {
      reasons.push(`SHA-256 Audit: Fingerprint generated — add a VirusTotal API key to check it against threat databases !`);
    } else if (hashVtStatus === "loading" || hashVtStatus === "queued" || hashVtStatus === "idle") {
      reasons.push(`SHA-256 Audit: Fingerprint generated — cross-referencing with global threat databases... ↻`);
    } else if (hashVtStatus === "complete") {
      const hMalicious = Number(vtFileReport.stats?.malicious || 0);
      const hSuspicious = Number(vtFileReport.stats?.suspicious || 0);
      const hTotal = getVirusTotalEngineCount(vtFileReport);
      if (hMalicious >= 1) {
        reasons.push(`SHA-256 Audit: Fingerprint flagged as Malicious by ${hMalicious}/${hTotal} vendors !`);
      } else if (hSuspicious >= 1) {
        reasons.push(`SHA-256 Audit: Fingerprint flagged as Suspicious by ${hSuspicious}/${hTotal} vendors !`);
      } else if (hTotal > 0) {
        reasons.push(`SHA-256 Audit: Fingerprint checked — 0/${hTotal} vendors flagged this file ✓`);
      } else {
        reasons.push(`SHA-256 Audit: Fingerprint generated — not found in VirusTotal database ✓`);
      }
    } else if (hashVtStatus === "not_found") {
      reasons.push(`SHA-256 Audit: Fingerprint generated — not found in VirusTotal database ✓`);
    } else {
      reasons.push(`SHA-256 Audit: Fingerprint lookup was unavailable; URL reputation remains separate. !`);
    }
  } else if (hashStatus === "skipped") {
    reasons.push(`SHA-256 Audit: Automatic fingerprint generation was not required for this file type ✓`);
  } else if (hashStatus === "skipped_blob") {
    reasons.push(`SHA-256 Audit: File generated securely within isolated browser memory; physical disk extraction not required. ✓`);
  } else if (hashStatus === "error") {
    reasons.push(`SHA-256 Audit: Fingerprint extraction unavailable (file exceeded limits or CORS) !`);
  } else {
    reasons.push(`SHA-256 Audit: Fingerprint generation in progress... ↻`);
  }

  // --- Static AI Alerts & Shannon Entropy ---
  if (record.fileEntropy) {
    if (record.fileEntropy > 7.2) {
      reasons.push(`Shannon Entropy: Highly anomalous structural entropy (${record.fileEntropy.toFixed(2)}) detected. Possible packed or encrypted payload. !`);
    } else if (record.fileEntropy > 6.5) {
      reasons.push(`Shannon Entropy: Elevated structural entropy (${record.fileEntropy.toFixed(2)}). File may be heavily compressed. !`);
    } else {
      reasons.push(`Shannon Entropy: Normal code structure detected (${record.fileEntropy.toFixed(2)}). ✓`);
    }
  } else if (hashStatus === "loading" || hashStatus === "idle") {
    reasons.push(`Shannon Entropy: Computing payload entropy... ↻`);
  }

  if (record.magicMime && record.magicMime === "executable") {
    const extRaw = (record.extension || "").replace(".", "").toLowerCase();
    if (extRaw === "pdf" || extRaw === "txt" || extRaw === "jpg" || extRaw === "png" || extRaw === "docx") {
      reasons.push(`File Structure: Extension spoofing detected! File claims to be ${extRaw} but contains executable magic bytes. !`);
    }
  }

  if (record.tlshHash) {
    reasons.push(`Fuzzy Hash Audit: TLSH-style locality-sensitive fingerprint generated for polymorphic malware correlation. ✓`);
  }

  const peAnomalies = Array.isArray(record.peAnomalies) ? record.peAnomalies.filter(Boolean) : [];
  for (const anomaly of peAnomalies) {
    reasons.push(`PE Header Analyzer: ${anomaly} !`);
  }

  // --- Signature & Domain Coherence ---
  if (vtFileReport && vtFileReport.details?.signatureInfo) {
    const sigInfo = vtFileReport.details.signatureInfo;
    const isSigned = String(sigInfo.verified || "").toLowerCase().includes("signed");
    const signers = sigInfo.signers ? (Array.isArray(sigInfo.signers) ? sigInfo.signers.join(", ") : String(sigInfo.signers)) : "";

    if (!isSigned && record.extension && ["exe", "msi", "dll", "app", "dmg", "pkg"].includes(record.extension.toLowerCase().replace(".", ""))) {
      reasons.push(`Digital Signature: <b>Warning!</b> This executable is explicitly unsigned and lacks provenance. !`);
    } else if (isSigned && signers) {
      const domainStr = String(record.sourceHostname || "").toLowerCase().replace(/[^a-z0-9]/g, " ");
      const signerStr = String(signers).toLowerCase().replace(/[^a-z0-9]/g, " ");
      
      const ignoreWords = new Set(["inc", "llc", "corp", "corporation", "ltd", "com", "net", "org", "co", "the"]);
      const domainWords = domainStr.split(" ").filter(w => w.length > 2 && !ignoreWords.has(w));
      const signerWords = signerStr.split(" ").filter(w => w.length > 2 && !ignoreWords.has(w));

      if (domainWords.length === 0 || signerWords.length === 0) {
        reasons.push(`Digital Signature: File is signed by <b>${signers}</b>. ✓`);
      } else {
        const hasMatch = domainWords.some(dw => signerWords.some(sw => dw.includes(sw) || sw.includes(dw)));
        if (hasMatch) {
          reasons.push(`Digital Signature: File is signed by <b>${signers}</b>, which correlates with the source domain. ✓`);
        } else {
          reasons.push(`Digital Signature: File is signed by <b>${signers}</b>, but this does NOT correlate with the source domain (${record.sourceHostname}). !`);
        }
      }
    }
  } else if (record.extension && ["exe", "msi", "dll", "app", "dmg", "pkg"].includes(record.extension.toLowerCase().replace(".", ""))) {
    reasons.push(`Digital Signature: <b>Warning!</b> This executable is unsigned or its signature could not be verified. !`);
  }

  // 4. Domain Maturity
  const domainMetadata = record.domainMetadata || {};
  const domainCreationDate = domainMetadata.creationDate || null;
  const registrar = domainMetadata.registrar || "";

  const domainAudit = record.domainAudit || {};

  if (domainCreationDate) {
    const ageInDays = (Date.now() - (domainCreationDate * 1000)) / (1000 * 60 * 60 * 24);
    const years = (ageInDays / 365).toFixed(1);
    const registrarText = registrar ? ` via ${registrar}` : "";
    reasons.push(ageInDays < 90 
      ? `Domain Maturity: Recently registered host${registrarText} (Risk: High) !` 
      : `Domain Maturity: Established industry lifecycle of ${years} years${registrarText} ✓`);
  } else if (domainAudit.status === "error") {
    reasons.push(`Domain Maturity: RDAP lookup was unavailable, so registry age could not be confirmed.`);
  } else if (domainAudit.status === "complete") {
    reasons.push(`Domain Maturity: RDAP lookup completed, but no creation date was exposed.`);
  } else {
    reasons.push(`Maturity Audit: Evaluating host registration history and registrar validity... ↻`);
  }

  // 5. Context/Category
  const categories = vtUrlReport.details?.categories || reputation.details?.categories || {};
  const primaryCategory = Object.values(categories)[0];
  if (primaryCategory) {
    reasons.push(`Contextual Audit: Source site categorized as '${primaryCategory}' ✓`);
  } else if (sourceStatus === "complete") {
    reasons.push(`Contextual Audit: General purpose website category identified ✓`);
  } else {
    reasons.push(`Contextual Audit: Correlating website category with file profile... ↻`);
  }

  return reasons;
}

export async function findUrlscanReport(targetUrl) {
  if (!targetUrl) return { status: "unsupported" };
  try {
    const hostname = parseUrl(targetUrl)?.hostname || "";
    const query = hostname ? `page.url:"${escapeQuery(targetUrl)}" OR task.url:"${escapeQuery(targetUrl)}" OR page.domain:"${escapeQuery(hostname)}"` : `page.url:"${escapeQuery(targetUrl)}" OR task.url:"${escapeQuery(targetUrl)}"`;
    const response = await fetchWithTimeout(`${URLSCAN_SEARCH_API}?q=${encodeURIComponent(query)}&size=1`, {}, 10_000);
    if (!response.ok) return { status: "error", summary: "urlscan.io lookup failed." };
    const payload = await response.json();
    const result = payload?.results?.[0];
    if (!result) return { status: "empty" };
    const score = Number(result.verdicts?.overall?.score ?? 0);
    return {
      status: "complete",
      provider: "urlscan.io",
      verdict: result.verdicts?.overall?.malicious ? "malicious" : score > 0 ? "suspicious" : "unknown",
      summary: `urlscan.io found a historical scan with a score of ${score}.`,
      checkedAt: new Date().toISOString(),
      reportUrl: normalizeUrlscanResultUrl(result.result || ""),
      searchUrl: buildUrlscanSearchUrl(targetUrl),
      score,
      pageIp: result.page?.ip || "",
      scannedAt: result.task?.time || ""
    };
  } catch {
    return { status: "error", summary: "urlscan.io lookup failed." };
  }
}

async function vtFetchJson(path, apiKey, init = {}) {
  const { timeoutMs = 10_000, ...fetchInit } = init;
  const response = await fetchWithTimeout(`${VT_API_BASE}${path}`, {
    ...fetchInit,
    headers: { Accept: "application/json", "x-apikey": apiKey, ...(fetchInit.headers || {}) }
  }, timeoutMs);
  if (!response.ok) {
    const error = new Error(`VirusTotal failed: ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function mapDomainDetailsToStatus(domainInfo) {
  const ageInDays = domainInfo.creationDate ? (Date.now() - (domainInfo.creationDate * 1000)) / (1000 * 60 * 60 * 24) : null;
  return {
    details: { domainCreationDate: domainInfo.creationDate, domainRegistrar: domainInfo.registrar, isNewDomain: ageInDays !== null && ageInDays < 90 }
  };
}

export async function fetchRdapDomain(hostname) {
  const candidates = buildRdapDomainCandidates(hostname);

  for (const testDomain of candidates) {
    // Try up to 2 attempts per candidate to handle transient rate-limits / 503s
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const resp = await fetchWithTimeout(
          `https://rdap.net/domain/${testDomain}`,
          { headers: { "Accept": "application/rdap+json" } },
          8_000  // raised from 5s — rdap.net can be slow
        );

        // Rate-limited or server error — wait briefly and retry once
        if (resp.status === 429 || resp.status === 503 || resp.status === 502) {
          if (attempt === 0) {
            await new Promise(r => setTimeout(r, 1500));
            continue;
          }
          break; // second attempt also failed — try next candidate
        }

        if (!resp.ok) break; // 404, 400 etc — this candidate doesn't exist, try next

        const data = await resp.json();
        const regEvent = getRdapEventDate(data.events, ["registration", "registered", "creation"]);
        const updateEvent = getRdapEventDate(data.events, ["last changed", "last update of rdap database", "last update", "updated"]);
        const expiryEvent = getRdapEventDate(data.events, ["expiration", "expiry", "expiration date", "expires"]);
        const regEntity = findRdapEntityByRole(data.entities, ["registrar"]);
        const registrantEntity = findRdapEntityByRole(data.entities, ["registrant"]);
        const registrar = getRdapEntityName(regEntity) || String(data.port43 || "").trim() || null;
        const registrantName = getRdapEntityName(registrantEntity);
        const registrantCountry = normalizeCountryCode(getRdapEntityCountry(registrantEntity));
        const nameservers = Array.isArray(data.nameservers)
          ? data.nameservers
            .map((item) => String(item?.ldhName || "").trim().toLowerCase())
            .filter(Boolean)
            .slice(0, 4)
          : [];

        return {
          status: "complete",
          queriedDomain: testDomain,
          creationDate: regEvent,
          updatedDate: updateEvent,
          expirationDate: expiryEvent,
          registrar,
          registrantName,
          registrantCountry,
          nameservers
        };
      } catch (e) {
        // AbortError (timeout) or network error — try next candidate immediately
        if (attempt === 0 && e?.name !== "AbortError") {
          await new Promise(r => setTimeout(r, 500));
          continue;
        }
        break;
      }
    }
  }

  return {
    status: "error",
    queriedDomain: null,
    creationDate: null,
    updatedDate: null,
    expirationDate: null,
    registrar: null,
    registrantName: null,
    registrantCountry: "",
    nameservers: []
  };
}

function buildRdapDomainCandidates(hostname) {
  const cleanHost = String(hostname || "").trim().toLowerCase().replace(/\.$/, "");
  if (!cleanHost) {
    return [];
  }

  const parts = cleanHost.split(".").filter(Boolean);
  if (parts.length < 2) {
    return [cleanHost];
  }

  const candidates = [];
  for (let index = 0; index <= parts.length - 2; index += 1) {
    const candidate = parts.slice(index).join(".");
    if (candidate && !candidates.includes(candidate)) {
      candidates.push(candidate);
    }
  }
  return candidates;
}

function mapVirusTotalReport(data, targetUrl, domainCreationDate = null, domainRegistrar = null, lookupType = "url") {
  const attributes = data?.attributes || {};
  const stats = { ...createEmptyStats(), ...(attributes.last_analysis_stats || {}) };
  const total = Object.values(stats).reduce((s, v) => s + Number(v || 0), 0);
  const malicious = stats.malicious || 0;
  const ageInDays = domainCreationDate ? (Date.now() - (domainCreationDate * 1000)) / (1000 * 60 * 60 * 24) : null;
  const isNew = ageInDays !== null && ageInDays < 90;
  const isFileLookup = lookupType === "file";
  return {
    status: "complete", provider: "VirusTotal", verdict: malicious > 0 ? "malicious" : (stats.suspicious > 0 || isNew) ? "suspicious" : "clean",
    summary: isFileLookup
      ? `VirusTotal fingerprint report: ${malicious}/${total} vendors flagged this file.`
      : `VirusTotal URL report: ${malicious}/${total} vendors flagged this source.`,
    checkedAt: new Date().toISOString(), reportUrl: buildVirusTotalReportUrl(data?.id || ""), targetUrl, stats, lookupType,
    hashChecked: isFileLookup,
    hashLookupDone: isFileLookup,
    details: { 
      categories: attributes.categories || null, 
      domainCreationDate, 
      domainRegistrar, 
      isNewDomain: isNew,
      signatureInfo: attributes.signature_info || null
    }
  };
}

function mapVirusTotalHashNotFound(fileHash, targetUrl) {
  return {
    status: "not_found",
    provider: "VirusTotal",
    verdict: "unknown",
    summary: "VirusTotal has no report for this file fingerprint.",
    checkedAt: new Date().toISOString(),
    targetUrl,
    fileHash,
    stats: createEmptyStats(),
    lookupType: "file",
    hashChecked: true,
    hashLookupDone: true
  };
}

function mapLookupError(error, targetUrl, analysisId = "", analysisUrl = "", lookupType = "url") {
  return {
    status: "error",
    provider: "VirusTotal",
    verdict: "unknown",
    summary: "Lookup failed.",
    checkedAt: new Date().toISOString(),
    targetUrl,
    analysisId,
    analysisUrl,
    stats: createEmptyStats(),
    lookupType,
    ...(lookupType === "file" ? { hashChecked: true, hashLookupDone: true } : {})
  };
}

function getVirusTotalUrlReport(record) {
  const report = record?.providerReports?.virusTotalUrl;
  if (report) return report;

  const reputation = record?.reputation;
  if (
    reputation?.provider === "VirusTotal" &&
    (reputation.lookupType === "url" || !reputation.lookupType)
  ) {
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

function getVirusTotalEngineCount(report) {
  return Object.values(report?.stats || {}).reduce((sum, value) => sum + Number(value || 0), 0);
}

function findRdapEntityByRole(entities, roles) {
  if (!Array.isArray(entities) || !Array.isArray(roles)) {
    return null;
  }
  const loweredRoles = roles.map((role) => String(role || "").toLowerCase());
  return entities.find((entity) => {
    const entityRoles = Array.isArray(entity?.roles) ? entity.roles.map((role) => String(role || "").toLowerCase()) : [];
    return entityRoles.some((role) => loweredRoles.includes(role));
  }) || null;
}

function getRdapEntityName(entity) {
  const props = entity?.vcardArray?.[1];
  if (!Array.isArray(props)) {
    return null;
  }
  const fnProp = props.find((item) => Array.isArray(item) && String(item[0] || "").toLowerCase() === "fn");
  if (fnProp && fnProp[3]) {
    return String(fnProp[3]).trim() || null;
  }
  const orgProp = props.find((item) => Array.isArray(item) && String(item[0] || "").toLowerCase() === "org");
  if (orgProp && orgProp[3]) {
    if (Array.isArray(orgProp[3])) {
      return String(orgProp[3].join(" ").trim() || "") || null;
    }
    return String(orgProp[3]).trim() || null;
  }
  return null;
}

function getRdapEntityCountry(entity) {
  const props = entity?.vcardArray?.[1];
  if (!Array.isArray(props)) {
    return "";
  }
  const adrProp = props.find((item) => Array.isArray(item) && String(item[0] || "").toLowerCase() === "adr");
  if (!adrProp) {
    return "";
  }
  const value = adrProp[3];
  if (Array.isArray(value) && value.length) {
    return String(value[value.length - 1] || "").trim();
  }
  return typeof value === "string" ? value.trim() : "";
}

function getRdapEventDate(events, eventNames) {
  if (!Array.isArray(events) || !Array.isArray(eventNames)) {
    return null;
  }
  const lowered = eventNames.map((name) => String(name || "").toLowerCase());
  const matched = events.find((item) => lowered.includes(String(item?.eventAction || "").toLowerCase()));
  if (!matched?.eventDate) {
    return null;
  }
  const timestamp = Math.floor(new Date(matched.eventDate).getTime() / 1000);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function normalizeCountryCode(value) {
  return String(value || "").trim().toUpperCase();
}

function parseAutnum(startAutnum, endAutnum) {
  const start = Number(startAutnum);
  if (Number.isFinite(start)) {
    return start;
  }
  const end = Number(endAutnum);
  return Number.isFinite(end) ? end : null;
}

function toVirusTotalUrlId(value) {
  // Safe UTF-8 → base64url: handles Unicode characters that btoa alone cannot encode.
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function createEmptyStats() { return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 }; }
function escapeQuery(v) { return String(v || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"'); }
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
async function fetchWithTimeout(input, init = {}, timeoutMs = 8_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}
function normalizeUrlscanResultUrl(v) { return String(v).replace(/\/api\/v1\/result\//, "/result/"); }
