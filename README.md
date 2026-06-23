<div align="center">
  <img src="docs/logo.png" alt="ThreatLens.space Logo" width="220" />
  <h1>ThreatLens.space</h1>
  <p><strong>Zero-Trust Browser Intrusion Prevention System</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Manifest_V3-Ready-success?style=for-the-badge&logo=google-chrome" alt="MV3 Ready" />
    <img src="https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge" alt="Version 2.0.0" />
    <img src="https://img.shields.io/badge/Security-Enterprise_Grade-brightgreen?style=for-the-badge" alt="Security" />
  </p>
</div>

---

**ThreatLens** is a high-fidelity, enterprise-grade Chrome extension that intercepts browser downloads, enforces strict security policies, and quarantines unknown files until an explicit decision is made. It ensures malicious payloads are stopped in memory before they ever touch your physical disk.

<br/>

## ✨ Key Features

- 🛡️ **Zero-Trust Interception:** Catches direct downloads, auto-downloads, and "Save As" flows directly through Chrome's native lifecycle.
- 🚦 **Policy Enforcement:** Instantly evaluates targets against your customized **Allowlist** and **Blocklist**.
- 🔍 **Deep Heuristic Auditing:** Calculates in-memory SHA-256 fingerprints of incoming payloads without saving them to disk.
- 🌍 **Global Threat Intelligence:** Correlates source domains and file hashes directly against **VirusTotal** and **urlscan.io**.
- ⚡ **Seamless UX:** A premium, non-blocking UI that centralizes decision-making inside the extension toolbar.

<br/>

## 🏢 Enterprise Deployment & Policy Setup

ThreatLens Enterprise supports centralized management via **Google Workspace Admin Console**. You can seamlessly deploy global download policies (Allowlist/Blocklist) to all your managed browsers without requiring user interaction.

### How to Publish Policies to Admin Console

**1. Navigate to the Extension Settings**
1. Go to [admin.google.com](https://admin.google.com)
2. Open **Devices → Chrome → Apps & Extensions → Users & browsers**
3. Select the **ThreatLens Enterprise** extension.
4. Scroll to the **Policy for extensions** section.

**2. Insert Policy JSON**
Paste the following JSON format. ThreatLens will automatically unwrap the `"Value"` object and enforce your organizational rules across all enrolled browsers.

```json
{
  "threatlens.config": {
    "Value": {
      "allowlist": {
        "domains": ["your-trusted-company-domain.com"],
        "urls": [],
        "fileTypes": []
      },
      "blocklist": {
        "domains": ["malicious-domain.com", "suspicious-cdn.net"],
        "urls": [],
        "fileTypes": [".exe", ".bat"]
      }
    }
  }
}
```

> **Note:** The `"Value"` key is explicitly required by Google Workspace Admin Console to properly deliver extension policies. ThreatLens parses this automatically upon synchronization.

**3. Verify Deployment**
Open `chrome://policy` on any managed machine and click **Reload policies**. Under the **Extension Policies** section, you will see `threatlens.config` populated with your exact JSON. 

<br/>

## 🚀 Individual Installation & Setup

If you are using the individual extension, setup is simple:

1. Navigate to the [Chrome Web Store](https://chromewebstore.google.com/detail/dojfphnfdcdhlhhdnjomojndhhfaoemd?utm_source=item-share-cb).
2. Click **Add to Chrome**.
3. Pin **ThreatLens** to your toolbar.
4. (Optional) Provide your free **VirusTotal API Key** in the ThreatLens settings to unlock deep OSINT cross-referencing on your local downloads.

<br/>

## 🛠️ Architecture Overview

ThreatLens is designed using an ephemeral, highly secure service-worker model built for Manifest V3.

- **`service-worker.js`**: Orchestrates storage, deep scans, and download interception.
- **`downloadHandler.js`**: Manages the quarantine-and-replay lifecycle.
- **`reputationService.js`**: Integrates deep threat-intelligence APIs (VirusTotal, urlscan, IP lookup, RDAP domain maturity).
- **`rulesEngine.js`**: Evaluates active strict Allow/Block policies.
- **`popup/`**: The primary dashboard for managing intelligence insights and configuring policies.

<br/>

---

<div align="center">
  <sub>Built for security, engineered for speed. © 2026 ThreatLens.space</sub>
</div>
