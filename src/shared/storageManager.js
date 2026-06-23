import {
  humanizeRuleType,
  normalizeDomainInput,
  normalizeFileTypeInput,
  normalizeUrlInput
} from "./utils.js";

const CONFIG_KEY = "threatlens.config";
const STATS_KEY = "threatlens.stats";
const PENDING_PREFIX = "threatlens.pending.";

let configCache = null;
let statsCache = null;
let pendingCache = null;
let storageSyncBound = false;

export const DEFAULT_CONFIG = {
  allowlist: {
    domains: [],
    urls: [],
    fileTypes: [],
    hashes: []
  },
  blocklist: {
    domains: [],
    urls: [],
    fileTypes: [],
    hashes: []
  },
  settings: {
    preferOverlayPrompt: true
  },
  integrations: {
    virusTotal: {
      apiKey: "",
      autoLookup: true
    },
    hybridAnalysis: {
      apiKey: "",
      autoSubmitMalicious: false
    }
  }
};

export const DEFAULT_STATS = {
  downloadsChecked: 0,
  autoAllowed: 0,
  autoBlocked: 0,
  prompted: 0,
  userAllowed: 0,
  userBlocked: 0,
  reputationChecks: 0,
  lastEventAt: null
};

export const storageManager = {
  async ensureInitialized() {
    const existing = await chrome.storage.local.get([CONFIG_KEY, STATS_KEY]);
    const localConfig = existing[CONFIG_KEY];

    let managedConfig = null;
    if (chrome.storage.managed) {
      try {
        const mStored = await chrome.storage.managed.get(CONFIG_KEY);
        managedConfig = mStored[CONFIG_KEY] ?? null;
      } catch (e) {
        console.warn("[ThreatLens] Failed to read managed storage:", e);
      }
    }

    // Merge local user rules + managed cloud policy into a single effective config.
    // We keep local user rules in local storage unchanged (so they survive policy updates),
    // but the live configCache always reflects both sources.
    const nextConfig = mergeConfig(localConfig, managedConfig);
    const nextStats = mergeStats(existing[STATS_KEY]);

    configCache = nextConfig;
    statsCache = nextStats;

    // Persist ONLY local-user state back (do NOT write managed rules into local storage
    // — they are always re-read from chrome.storage.managed at runtime).
    const localOnly = mergeConfig(localConfig);
    await chrome.storage.local.set({
      [CONFIG_KEY]: localOnly,
      [STATS_KEY]: nextStats
    });
  },

  async getConfig() {
    if (configCache) {
      return cloneValue(configCache);
    }

    const stored = await chrome.storage.local.get(CONFIG_KEY);
    let localConfig = stored[CONFIG_KEY];

    let managedConfig = null;
    if (chrome.storage.managed) {
      try {
        const mStored = await chrome.storage.managed.get(CONFIG_KEY);
        managedConfig = mStored[CONFIG_KEY];
      } catch (e) {}
    }

    configCache = mergeConfig(localConfig, managedConfig);
    return cloneValue(configCache);
  },

  async saveConfig(config) {
    const nextConfig = mergeConfig(config);
    configCache = nextConfig;
    await chrome.storage.local.set({
      [CONFIG_KEY]: nextConfig
    });
  },

  async updateSettings(partialSettings) {
    const config = await this.getConfig();
    config.settings = {
      ...config.settings,
      ...partialSettings
    };
    await this.saveConfig(config);
    return config.settings;
  },

  async updateVirusTotal(partialConfig) {
    const config = await this.getConfig();
    config.integrations.virusTotal = {
      ...config.integrations.virusTotal,
      ...partialConfig,
      apiKey: String(partialConfig.apiKey ?? config.integrations.virusTotal.apiKey ?? "").trim()
    };
    await this.saveConfig(config);
    return config.integrations.virusTotal;
  },

  async updateHybridAnalysis(partialConfig) {
    const config = await this.getConfig();
    const existing = config.integrations.hybridAnalysis || {};
    config.integrations.hybridAnalysis = {
      ...existing,
      ...partialConfig,
      apiKey: String(partialConfig.apiKey ?? existing.apiKey ?? "").trim(),
      autoSubmitMalicious: Boolean(partialConfig.autoSubmitMalicious ?? existing.autoSubmitMalicious ?? false)
    };
    await this.saveConfig(config);
    return config.integrations.hybridAnalysis;
  },

  async addRule(listType, ruleType, rawValue) {
    const config = await this.getConfig();
    assertRuleCollection(config, listType, ruleType);

    const normalized = normalizeRuleValue(ruleType, rawValue);
    const existing = new Set(config[listType][ruleType]);

    if (existing.has(normalized)) {
      throw new Error(`${humanizeRuleType(ruleType)} rule already exists.`);
    }

    config[listType][ruleType] = [...existing, normalized].sort(sortRules);

    // Common Sense update: Ensure the rule doesn't exist in the opposite list
    const oppositeList = listType === "allowlist" ? "blocklist" : "allowlist";
    if (config[oppositeList] && Array.isArray(config[oppositeList][ruleType])) {
      config[oppositeList][ruleType] = config[oppositeList][ruleType].filter((entry) => entry !== normalized);
    }

    await this.saveConfig(config);
    return normalized;
  },

  async removeRule(listType, ruleType, value) {
    const config = await this.getConfig();
    assertRuleCollection(config, listType, ruleType);

    config[listType][ruleType] = config[listType][ruleType].filter((entry) => entry !== value);
    await this.saveConfig(config);
  },

  async getStats() {
    if (statsCache) {
      return cloneValue(statsCache);
    }

    const stored = await chrome.storage.local.get(STATS_KEY);
    statsCache = mergeStats(stored[STATS_KEY]);
    return cloneValue(statsCache);
  },

  async incrementStats(delta) {
    const stats = await this.getStats();

    for (const [key, value] of Object.entries(delta || {})) {
      if (typeof value === "number" && Number.isFinite(value)) {
        stats[key] = (stats[key] || 0) + value;
      }
    }

    stats.lastEventAt = new Date().toISOString();
    statsCache = stats;
    await chrome.storage.local.set({
      [STATS_KEY]: stats
    });

    return cloneValue(stats);
  },

  async resetStats() {
    const nextStats = {
      ...DEFAULT_STATS
    };

    statsCache = nextStats;
    await chrome.storage.local.set({
      [STATS_KEY]: nextStats
    });

    return cloneValue(nextStats);
  },

  async savePendingDownload(record) {
    const nextRecord = sanitizePendingRecord(record);
    if (pendingCache) {
      pendingCache.set(record.downloadId, nextRecord);
    }

    await chrome.storage.local.set({
      [getPendingKey(record.downloadId)]: nextRecord
    });

    return cloneValue(nextRecord);
  },

  async patchPendingDownload(downloadId, patch) {
    const current = await this.getPendingDownload(downloadId);
    if (!current) {
      return null;
    }

    const nextRecord = sanitizePendingRecord({
      ...current,
      ...patch,
      updatedAt: new Date().toISOString()
    });

    if (pendingCache) {
      pendingCache.set(downloadId, nextRecord);
    }

    await chrome.storage.local.set({
      [getPendingKey(downloadId)]: nextRecord
    });

    return cloneValue(nextRecord);
  },

  async getPendingDownload(downloadId) {
    if (pendingCache) {
      return cloneValue(pendingCache.get(downloadId) || null);
    }

    const stored = await chrome.storage.local.get(getPendingKey(downloadId));
    return cloneValue(stored[getPendingKey(downloadId)] || null);
  },

  async listPendingDownloads() {
    const cache = await loadPendingCache();
    return [...cache.values()]
      .sort((left, right) => (left.createdAt > right.createdAt ? -1 : 1))
      .map((value) => cloneValue(value));
  },

  /**
   * Returns pending downloads WITHOUT deep-cloning. For read-only consumers
   * (popup rendering) this eliminates expensive structuredClone on every render.
   * IMPORTANT: Callers MUST NOT mutate the returned objects.
   */
  async listPendingDownloadsRaw() {
    const cache = await loadPendingCache();
    return [...cache.values()]
      .sort((left, right) => (left.createdAt > right.createdAt ? -1 : 1));
  },

  async removePendingDownload(downloadId) {
    if (pendingCache) {
      pendingCache.delete(downloadId);
    }

    await chrome.storage.local.remove(getPendingKey(downloadId));
  },

  getPendingKey
};

function mergeConfig(config, managedConfig = null) {
  const nextConfig = structuredClone(DEFAULT_CONFIG);
  if (config && typeof config === "object") {
    for (const listType of ["allowlist", "blocklist"]) {
      for (const ruleType of ["domains", "urls", "fileTypes"]) {
        const entries = config[listType]?.[ruleType];
        if (Array.isArray(entries)) {
          nextConfig[listType][ruleType] = entries.map((value) => String(value).trim()).filter(Boolean);
        }
      }
    }

    nextConfig.settings = {
      ...DEFAULT_CONFIG.settings,
      ...(config.settings || {})
    };

    nextConfig.integrations = {
      virusTotal: {
        ...DEFAULT_CONFIG.integrations.virusTotal,
        ...(config.integrations?.virusTotal || {})
      },
      hybridAnalysis: {
        ...DEFAULT_CONFIG.integrations.hybridAnalysis,
        ...(config.integrations?.hybridAnalysis || {})
      }
    };
  }

  if (typeof managedConfig === "string") {
    try {
      managedConfig = JSON.parse(managedConfig);
    } catch (e) {
      console.warn("[ThreatLens] Failed to parse managedConfig string:", e);
    }
  }

  if (managedConfig && typeof managedConfig === "object") {
    // Google Workspace's Custom JSON editor wraps the payload in {"Value": {...}}.
    // We must unwrap it, or parse it if it was passed as a string.
    let effectiveManaged = managedConfig;
    if (managedConfig.Value !== undefined) {
      if (typeof managedConfig.Value === "string") {
        try {
          effectiveManaged = JSON.parse(managedConfig.Value);
        } catch (e) {
          console.warn("[ThreatLens] Failed to parse managedConfig.Value string:", e);
          effectiveManaged = {};
        }
      } else {
        effectiveManaged = managedConfig.Value;
      }
    }

    for (const listType of ["allowlist", "blocklist"]) {
      // If the admin provided a flat array (e.g. "allowlist": ["google.com"]),
      // treat them as domains. Managed REPLACES local for this field.
      if (Array.isArray(effectiveManaged[listType])) {
        nextConfig[listType]["domains"] = effectiveManaged[listType]
          .map((value) => String(value).trim())
          .filter(Boolean);
      } else if (effectiveManaged[listType] && typeof effectiveManaged[listType] === "object") {
        for (const ruleType of ["domains", "urls", "fileTypes", "hashes"]) {
          const entries = effectiveManaged[listType]?.[ruleType];
          if (Array.isArray(entries)) {
            // Managed policy REPLACES local rules for this specific field.
            // This prevents stale local rules from persisting after the admin
            // removes or changes an entry in Google Workspace.
            nextConfig[listType][ruleType] = entries
              .map((value) => String(value).trim())
              .filter(Boolean);
          }
          // If the field is absent from managed policy (undefined), the local
          // value built from nextConfig above is preserved as-is.
        }
      }
    }
  }

  for (const listType of ["allowlist", "blocklist"]) {
    for (const ruleType of ["domains", "urls", "fileTypes", "hashes"]) {
      if (!Array.isArray(nextConfig[listType][ruleType])) {
        nextConfig[listType][ruleType] = [];
      }
      nextConfig[listType][ruleType] = [...new Set(nextConfig[listType][ruleType])].sort(sortRules);
    }
  }

  return nextConfig;
}

async function loadPendingCache() {
  if (pendingCache) {
    return pendingCache;
  }

  const stored = await chrome.storage.local.get(null);
  pendingCache = new Map(
    Object.entries(stored)
      .filter(([key]) => key.startsWith(PENDING_PREFIX))
      .map(([, value]) => [value.downloadId, value])
  );

  return pendingCache;
}

function mergeStats(stats) {
  return {
    ...DEFAULT_STATS,
    ...(stats || {})
  };
}

function cloneValue(value) {
  if (value == null) {
    return value;
  }

  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }

  return JSON.parse(JSON.stringify(value));
}

function sanitizePendingRecord(record) {
  return {
    ...record,
    updatedAt: record.updatedAt || new Date().toISOString(),
    createdAt: record.createdAt || new Date().toISOString()
  };
}

function assertRuleCollection(config, listType, ruleType) {
  if (!config[listType] || !Array.isArray(config[listType][ruleType])) {
    throw new Error("ThreatLens could not load that rule collection.");
  }
}

function normalizeRuleValue(ruleType, rawValue) {
  switch (ruleType) {
    case "domains":
      return normalizeDomainInput(rawValue);
    case "urls":
      return normalizeUrlInput(rawValue);
    case "fileTypes":
      return normalizeFileTypeInput(rawValue);
    case "hashes": {
      const cleaned = String(rawValue || "").trim().toLowerCase();
      if (!/^[0-9a-f]{32,64}$/.test(cleaned)) {
        throw new Error("Hash must be a valid MD5 (32 chars) or SHA-256 (64 chars) hex string.");
      }
      return cleaned;
    }
    default:
      throw new Error("Unsupported rule type.");
  }
}

function getPendingKey(downloadId) {
  return `${PENDING_PREFIX}${downloadId}`;
}

function sortRules(left, right) {
  return left.localeCompare(right);
}

function bindStorageSync() {
  if (storageSyncBound || !chrome?.storage?.onChanged) {
    return;
  }

  chrome.storage.onChanged.addListener(async (changes, areaName) => {
    if (areaName === "managed" && changes[CONFIG_KEY]) {
      const stored = await chrome.storage.local.get(CONFIG_KEY);
      configCache = mergeConfig(stored[CONFIG_KEY], changes[CONFIG_KEY].newValue);
      return;
    }

    if (areaName !== "local") {
      return;
    }

    if (changes[CONFIG_KEY]) {
      let managedConfig = null;
      if (chrome.storage.managed) {
        try {
          const mStored = await chrome.storage.managed.get(CONFIG_KEY);
          managedConfig = mStored[CONFIG_KEY];
        } catch (e) {}
      }
      configCache = mergeConfig(changes[CONFIG_KEY].newValue, managedConfig);
    }

    if (changes[STATS_KEY]) {
      statsCache = mergeStats(changes[STATS_KEY].newValue);
    }

    if (!pendingCache) {
      return;
    }

    for (const [key, change] of Object.entries(changes)) {
      if (!key.startsWith(PENDING_PREFIX)) {
        continue;
      }

      if (change.newValue) {
        pendingCache.set(change.newValue.downloadId, change.newValue);
      } else if (change.oldValue) {
        pendingCache.delete(change.oldValue.downloadId);
      }
    }
  });

  storageSyncBound = true;
}

bindStorageSync();
