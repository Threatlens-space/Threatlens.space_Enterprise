/**
 * ThreatLens Rules Engine
 * -----------------------
 * Production-hardened evaluation of downloads against allowlist / blocklist.
 *
 * SECURITY MODEL:
 *   • Allowlist matching is STRICT — only the actual download origin (finalUrl
 *     and url) is checked for domain/URL rules. The referrer is intentionally
 *     excluded to prevent a bypass where a trusted referrer auto-approves a
 *     file hosted on an untrusted server.
 *   • Blocklist matching is BROAD — referrer is included so that downloads
 *     triggered by a blocked domain are also intercepted, even if the file
 *     itself is hosted elsewhere.
 *   • Allowlist always takes priority over blocklist. If a download matches
 *     both (e.g. a file type is blocked but its domain is trusted), the
 *     allowlist wins.
 *   • File-type rules are extracted from the URL pathname at evaluation time
 *     because downloadItem.filename is not yet populated during onCreated.
 */

import { isEphemeralUrl, matchesDomainRule, parseUrl, calculateStringEntropy } from "../shared/utils.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Evaluate a Chrome DownloadItem against the stored config.
 * @returns {{ verdict: "allow"|"block"|"prompt", riskIndicator: string, reason: string, match: object|null }}
 */
export function evaluateDownload(downloadItem, config) {
  const downloadCandidates = buildStrictCandidates(downloadItem);   // allowlist: no referrer
  const broadCandidates    = buildBroadCandidates(downloadItem);    // blocklist: includes referrer

  // Allowlist checked first using strict candidates (download origin only)
  const allowMatch = findRuleMatch(config.allowlist, downloadCandidates);
  if (allowMatch) {
    return {
      verdict: "allow",
      riskIndicator: "Trusted",
      reason: `Auto-allowed by ${allowMatch.typeLabel} allowlist rule: "${allowMatch.value}"`,
      match: allowMatch
    };
  }

  // Blocklist checked with broad candidates (includes referrer)
  const blockMatch = findRuleMatch(config.blocklist, broadCandidates);
  if (blockMatch) {
    return {
      verdict: "block",
      riskIndicator: "Blocked",
      reason: `Auto-blocked by ${blockMatch.typeLabel} blocklist rule: "${blockMatch.value}"`,
      match: blockMatch
    };
  }

  // Static AI: Lexical Domain Analysis (Typosquatting & DGA)
  for (const domain of broadCandidates.domains) {
    const domainNamePart = domain.split(".")[0];
    if (domainNamePart.length > 12) {
      const entropy = calculateStringEntropy(domainNamePart);
      // Heuristic: DGA domains usually have high entropy.
      if (entropy > 3.8) {
        return {
          verdict: "block",
          riskIndicator: "Malicious",
          reason: `Auto-blocked: Domain "${domain}" appears to be machine-generated (High Entropy DGA).`,
          match: { typeLabel: "AI Lexical", value: "DGA" }
        };
      }
    }
  }

  return {
    verdict: "prompt",
    riskIndicator: "Unknown",
    reason: "No rule matched — ThreatLens is waiting for your decision.",
    match: null,
    requiresPauseStrategy: isOneTimeTokenUrl(downloadItem.url) || isOneTimeTokenUrl(downloadItem.finalUrl)
  };
}

/**
 * Detects URLs that are true one-time ephemeral tokens that CANNOT be replayed
 * or re-requested. These must bypass the normal hash-and-hold pipeline because
 * canceling and re-downloading them would fail (the URL would be expired/invalid).
 *
 * IMPORTANT: AWS S3 pre-signed URLs (X-Amz-Signature), Azure SAS tokens, and
 * generic CDN tokens are intentionally NOT in this list. Although they look
 * like one-time tokens, they typically have long expiry windows (hours or days)
 * and can safely be held for hash analysis. Including them caused ThreatLens to
 * skip SHA-256 hash calculation for the majority of cloud-hosted files (Canva,
 * Dropbox, Google Drive exports, etc.) — a major security gap.
 *
 * Only truly non-replayable URLs (like the Chrome installer's tag-based CDN)
 * are listed here.
 */
function isOneTimeTokenUrl(url) {
  if (!url) return false;

  try {
    const parsed = new URL(url);

    // Google Chrome installer — uses a signed tag URL that expires immediately
    // after the first byte is consumed. Canceling and re-downloading results in
    // a 403 error. This is the ONLY known case that requires the bypass strategy.
    const isChromeInstaller = (
      parsed.hostname === "dl.google.com" &&
      (parsed.pathname.includes("/chrome/") || parsed.pathname.includes("/tag/"))
    );

    return isChromeInstaller;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Candidate builders
// ---------------------------------------------------------------------------

/**
 * STRICT candidates — allowlist only.
 * Uses only the actual download URLs (finalUrl + url). 
 * Referrer is intentionally excluded to prevent bypass attacks where a 
 * trusted site's referrer would auto-allow a file hosted on an evil server.
 */
function buildStrictCandidates(downloadItem) {
  const stableTrustUrls = [downloadItem?.finalUrl, downloadItem?.url]
    .filter(Boolean);
  const urls    = extractUrls(stableTrustUrls);
  const domains = extractDomains(stableTrustUrls);
  const fileType = extractFileType(downloadItem);
  return { urls, domains, fileType };
}

/**
 * BROAD candidates — blocklist only.
 * Also checks the referrer so downloads triggered from a blocked domain
 * are intercepted even if the file is hosted elsewhere.
 */
function buildBroadCandidates(downloadItem) {
  const urls    = extractUrls([downloadItem?.finalUrl, downloadItem?.url, downloadItem?.referrer]);
  const domains = extractDomains([downloadItem?.finalUrl, downloadItem?.url, downloadItem?.referrer]);
  const fileType = extractFileType(downloadItem);
  return { urls, domains, fileType };
}

// ---------------------------------------------------------------------------
// Core matcher
// ---------------------------------------------------------------------------

function findRuleMatch(ruleCollection, candidates) {
  // 1. Domain rules  
  //    Handles: main domain + all subdomains (sub.example.com matches example.com)
  //    Safe: matchesDomainRule only matches if domain IS the rule or ends with ".rule"
  //    so "evilexample.com" will never match "example.com".
  for (const rule of ruleCollection.domains || []) {
    if (!rule) continue;
    const matched = candidates.domains.find((d) => matchesDomainRule(d, rule));
    if (matched) {
      return { category: "domains", value: rule, matchedValue: matched, typeLabel: "domain" };
    }
  }

  // 2. URL rules
  //    Normalised comparison: strips hash, lowercases, removes trailing slash.
  //    Query strings are preserved — a URL rule is intentionally exact.
  //    This means https://cdn.com/file.zip?token=x won't match the stored
  //    rule https://cdn.com/file.zip — correct behaviour documented in UI copy.
  for (const rule of ruleCollection.urls || []) {
    if (!rule) continue;
    const normRule = normalizeUrlForComparison(rule);
    const matched  = candidates.urls.find((u) => normalizeUrlForComparison(u) === normRule);
    if (matched) {
      return { category: "urls", value: rule, matchedValue: matched, typeLabel: "URL" };
    }
  }

  // 3. File-type rules
  //    Both sides normalised to have a leading dot and lowercased.
  //    Extracted from URL pathname because downloadItem.filename is empty
  //    at onCreated time (populated only after onDeterminingFilename).
  const fileType = candidates.fileType;
  if (fileType) {
    const normFileType = normalizeExtension(fileType);
    const matched = (ruleCollection.fileTypes || []).find(
      (rule) => rule && normalizeExtension(rule) === normFileType
    );
    if (matched) {
      return { category: "fileTypes", value: matched, matchedValue: fileType, typeLabel: "file-type" };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

/**
 * Parse a list of raw URL strings into normalised, hash-stripped URLs.
 * Handles blob: URLs (Edge/Chrome Canva, Google Drive exports) by unwrapping
 * the inner URL so they can be matched against stored rules.
 */
function extractUrls(rawList) {
  const seen = new Set();
  const results = [];
  for (const raw of rawList) {
    if (!raw) continue;
    const parsed = safeParseUrl(raw);
    if (!parsed) continue;

    // Unwrap blob: URLs — the real host is inside the pathname
    const effective = (parsed.protocol === "blob:" && parsed.pathname)
      ? (safeParseUrl(parsed.pathname) || parsed)
      : parsed;

    effective.hash = "";
    const normalised = effective.toString();
    if (!seen.has(normalised)) {
      seen.add(normalised);
      results.push(normalised);
    }
  }
  return results;
}

/**
 * Extract unique lowercase hostnames from a list of raw URL strings.
 * Handles blob: URLs used by Edge, Chrome (Canva, Google Drive exports).
 */
function extractDomains(rawList) {
  const seen = new Set();
  for (const raw of rawList) {
    if (!raw) continue;
    const parsed = safeParseUrl(raw);
    if (!parsed) continue;

    let hostname = parsed.hostname;

    // blob: URLs have no hostname — the real host lives in the pathname
    if (!hostname && parsed.protocol === "blob:" && parsed.pathname) {
      const inner = safeParseUrl(parsed.pathname);
      hostname = inner?.hostname || "";
    }

    if (hostname) {
      seen.add(hostname.toLowerCase());
    }
  }
  return [...seen];
}

/**
 * Extract a file extension from the download URL pathname.
 * Priority: (1) filename field when already populated (onDeterminingFilename),
 *           (2) URL pathname,  (3) query-string path fallback.
 * Never throws — returns empty string on failure.
 */
function extractFileType(downloadItem) {
  // Prefer filename when already populated (available in onDeterminingFilename)
  if (downloadItem?.filename) {
    const namePart = downloadItem.filename.split(/[\\/]/).pop() || "";
    const extMatch = namePart.match(/(\.[a-z0-9]{1,16})$/i);
    if (extMatch) return extMatch[1].toLowerCase();
  }

  // Fall back to URL pathname
  const primaryUrl = downloadItem?.finalUrl || downloadItem?.url || "";
  let parsed = safeParseUrl(primaryUrl);

  // Unwrap blob: URLs on Edge / Chrome
  if (parsed?.protocol === "blob:" && parsed.pathname) {
    parsed = safeParseUrl(parsed.pathname) || parsed;
  }

  if (parsed) {
    const match = parsed.pathname.match(/(\.[a-z0-9]{1,16})$/i);
    if (match) return match[1].toLowerCase();
  }

  // Last-resort: check query string path segments (rare CDN patterns)
  const searchMatch = primaryUrl.match(/\/([^/?#]+\.[a-z0-9]{1,16})(?:[?#]|$)/i);
  return searchMatch ? searchMatch[1].split(".").pop().toLowerCase().replace(/^/, ".") : "";
}

// ---------------------------------------------------------------------------
// Normalisation utilities
// ---------------------------------------------------------------------------

function normalizeUrlForComparison(rawUrl) {
  const parsed = safeParseUrl(rawUrl);
  if (!parsed) return String(rawUrl || "").toLowerCase().replace(/\/$/, "");
  parsed.hash = "";
  return parsed.toString().toLowerCase().replace(/\/$/, "");
}

function normalizeExtension(ext) {
  const clean = String(ext || "").trim().toLowerCase();
  return clean.startsWith(".") ? clean : `.${clean}`;
}

function safeParseUrl(raw) {
  if (!raw || typeof raw !== "string") return null;
  // Attempt with raw URL
  try { return new URL(raw); } catch { /* fall through */ }
  // Attempt with https:// prefix for bare domains accidentally stored in URL rules
  try { return new URL(`https://${raw}`); } catch { return null; }
}
