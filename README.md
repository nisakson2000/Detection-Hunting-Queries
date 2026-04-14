<p align="center">
  <h1 align="center">🔎 Detection & Hunting Queries</h1>
  <p align="center">
    A curated collection of KQL detection rules and hunting queries for<br>
    <strong>Microsoft Sentinel</strong> and <strong>Defender XDR</strong>, organized by <a href="https://attack.mitre.org/">MITRE ATT&CK</a> tactics.
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/queries-17-blue?style=flat-square" alt="Total Queries">
    <img src="https://img.shields.io/badge/MITRE%20tactics-8-red?style=flat-square" alt="MITRE Tactics">
    <img src="https://img.shields.io/badge/language-KQL-purple?style=flat-square" alt="Language">
    <img src="https://img.shields.io/badge/license-open-green?style=flat-square" alt="License">
  </p>
</p>

---

**Author:** [Nick Isakson](https://github.com/nisakson2000) — Information Security Analyst | [Detections.AI Profile](https://detections.ai/user/nisakson2000)

---

## 📋 At a Glance

| | |
|:--|:--|
| **Detections** | 13 analytics rules covering initial access through impact |
| **Hunting Queries** | 4 security operations queries for triage, enrichment, and validation |
| **Data Sources** | `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `CommonSecurityLog`, `EmailEvents`, `IdentityLogonEvents`, `IntuneAuditLogs`, and more |
| **Platforms** | Microsoft Sentinel (primary) · Defender XDR Advanced Hunting |

---

## 📂 Repository Structure

```
Detection-Hunting-Queries/
│
├── initial-access/              # TA0001 — 3 queries
├── execution/                   # TA0002 — 1 query
├── persistence/                 # TA0003 — 2 queries
├── credential-access/           # TA0006 — 1 query
├── discovery/                   # TA0007 — 1 query
├── command-and-control/         # TA0011 — 2 queries
├── exfiltration/                # TA0010 — 2 queries
├── impact/                      # TA0040 — 1 query
└── security-operations/         # Ops & triage — 4 queries
```

Each `.kql` file is fully self-contained with inline documentation: purpose, MITRE mappings, data source requirements, tunable thresholds, and tuning guidance.

---

## 🎯 Query Index

Tactics are ordered to follow the [ATT&CK kill chain](https://attack.mitre.org/) progression.

### Initial Access (TA0001)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Stolen Device Logon Detection](initial-access/stolen-device-logon-detection.kql) | T1078 | Detects successful logon activity on devices reported as stolen or missing, enriched with ISP IP data from Azure AD sign-in logs. |
| [Phishing Investigation & Impact Analysis](initial-access/phishing-investigation-impact-analysis.kql) | T1566.001, T1566.002, T1204 | Comprehensive phishing triage correlating email delivery, URL clicks, attachments, endpoint file activity, reply behavior, and post-delivery ZAP actions into a single view per recipient. |
| [Cato Anti Malware — Confirmed Malware Detection](initial-access/cato-anti-malware-detection.kql) | T1566.001, T1105 | Alerts on confirmed malware verdicts from Cato's inline Anti Malware engine, covering both blocked and allowed files with severity escalation when malware passes through unblocked. |

### Execution (TA0002)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Winget Abuse Detection](execution/winget-abuse-detection.kql) | T1218, T1059, T1105 | Multi-layered detection for `winget.exe` abuse including command shell spawning, temp path execution, suspicious network egress, and unsigned binary drops. |

### Persistence (TA0003)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Sensitive Group Membership Changes](persistence/sensitive-group-membership-changes.kql) | T1098 | Detects members added or removed from sensitive Active Directory groups (Domain Admins, Enterprise Admins, etc.). |
| [ChatGPT Stealer Extension Installation](persistence/chatgpt-stealer-extension-installation.kql) | T1176 | Detects installation of known malicious browser extension IDs associated with the ChatGPT Stealer campaign targeting AI session tokens. |

### Credential Access (TA0006)

| Query | Technique | Description |
|:------|:----------|:------------|
| [ML-Based Privileged Account Anomaly Detection](credential-access/ml-privileged-account-anomaly-detection.kql) | T1078, T1098, T1087, T1556 | Multi-layered, self-calibrating detection combining statistical anomaly detection, absolute rules, ratio-based thresholds, behavioral shift analysis, reconnaissance anomaly detection, and MFA gap detection for privileged accounts. |

### Discovery (TA0007)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Vulnerable Software Version Discovery](discovery/vulnerable-software-version-discovery.kql) | T1518.001 | Template query to identify devices running vulnerable software versions. Supports configurable software name, version comparison, and CVE tagging. |

### Command and Control (TA0011)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Cato Networks Blocked URL Access](command-and-control/cato-networks-blocked-url-access.kql) | T1189, T1071.001 | Identifies blocked URL access attempts from Cato Networks security policies with configurable device and URL filtering. |
| [ChatGPT Stealer C2 Domains](command-and-control/chatgpt-stealer-c2-domains.kql) | T1071.001, T1567 | Detects network connections to known C2 domains used by the ChatGPT Stealer campaign for AI session token exfiltration. |

### Exfiltration (TA0010)

| Query | Technique | Description |
|:------|:----------|:------------|
| [USB File Copy — Intune Enriched](exfiltration/usb-file-copy-intune-enriched.kql) | T1052.001 | Detects files written to USB drives with enrichment from fleet-wide PnP events, providing `VID_PID`, `InstancePathId`, and `SerialNumberId` for Intune device control cross-referencing. |
| [Periodic AI Data Exfiltration (Beaconing)](exfiltration/periodic-ai-data-exfiltration-beaconing.kql) | T1071.001, T1041 | Detects periodic beaconing behavior from browser processes to external domains, designed to catch automated data exfiltration by malicious extensions at ~30-minute intervals. |

### Impact (TA0040)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Intune Mass Device Wipe / Destructive Actions](impact/intune-mass-device-wipe-destructive-actions.kql) | T1485, T1561, T1561.001 | Multi-signal detection for mass device wipe/retire/delete via Microsoft Intune, inspired by the Stryker/Handala attack. Combines static velocity thresholds, bulk operator detection, first-time operator baselining, UEBA anomaly correlation, and ML behavioral anomaly detection with tiered severity escalation. |

---

### Security Operations

Operational queries for triage, enrichment, and validation — not tied to a specific ATT&CK technique.

| Query | Description |
|:------|:------------|
| [MSSP Alert Tracking & Deduplication](security-operations/mssp-alert-tracking-deduplication.kql) | Configurable query to track and deduplicate alert emails from an MSSP, using session logic to group email bursts and extract case numbers from portal URLs. |
| [Imperva WAF Blocked Requests by Organization](security-operations/imperva-waf-blocked-requests-by-org.kql) | Multi-layer aggregation of Imperva WAF blocked requests, enriched with ASN/organization data, rolling up from pattern to attack type to IP to organization for threat analysis. |
| [Email Delivery Telemetry & Threat Exposure](security-operations/email-delivery-telemetry-threat-exposure.kql) | Identifies accounts with the highest email volume and threat exposure, including a key risk metric for threats that bypassed filtering and reached user inboxes. |
| [Sporadic Device Activity Validation](security-operations/sporadic-device-activity-validation.kql) | Hunting query to validate whether a device flagged by a decommissioned-asset detection exhibits sporadic legitimate use. Builds a daily timeline across logon, process, and network telemetry over a configurable lookback window. |

---

## 🛠️ Platforms & Compatibility

| Platform | Status | Notes |
|:---------|:-------|:------|
| **Microsoft Sentinel** | Primary | All queries use `TimeGenerated` |
| **Defender XDR Advanced Hunting** | Compatible | Replace `TimeGenerated` with `Timestamp` where noted |

---

## 📝 Getting Started

1. **Browse** the query index above or explore the tactic folders directly.
2. **Copy** the `.kql` file contents into your Sentinel Logs or Defender Advanced Hunting query editor.
3. **Configure** the tunable parameters at the top of each query — time windows, thresholds, and exclusion lists — for your environment.
4. **Deploy** as an analytics rule or run ad-hoc for hunting and triage.

> **Tip:** Each query includes inline comments explaining every section. Start with the configuration block and read the purpose header to understand what the query surfaces and how to tune it.

---

## 📄 License

These queries are shared for the benefit of the security community. Use and modify them freely. Attribution is appreciated but not required.
