# 🔎 Detection & Hunting Queries

A collection of KQL detection rules and hunting queries for **Microsoft Sentinel** and **Defender XDR**, organized by [MITRE ATT&CK](https://attack.mitre.org/) tactics.

**Author:** [Nick Isakson](https://github.com/nisakson2000) — Information Security Analyst | [Detections.AI Profile](https://detections.ai/user/nisakson2000)

---

## 📂 Repository Structure

Queries are organized by MITRE ATT&CK tactic. Each `.kql` file contains the full query with inline documentation including author notes, MITRE mappings, data source requirements, and tuning guidance.

```
├── initial-access/
├── discovery/
├── persistence/
├── execution/
├── credential-access/
├── command-and-control/
├── exfiltration/
└── security-operations/
```

---

## 🎯 Query Index

### Initial Access (TA0001)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Stolen Device Logon Detection](initial-access/stolen-device-logon-detection.kql) | T1078 | Detects successful logon activity on devices reported as stolen or missing, enriched with ISP IP data from Azure AD sign-in logs. |
| [Phishing Investigation & Impact Analysis](initial-access/phishing-investigation-impact-analysis.kql) | T1566.001, T1566.002, T1204 | Comprehensive phishing triage query correlating email delivery, URL clicks, attachments, endpoint file activity, and reply behavior into a single view per recipient. |

### Discovery (TA0007)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Vulnerable Software Version Discovery](discovery/vulnerable-software-version-discovery.kql) | T1518.001 | Template query to identify devices running vulnerable software versions. Supports configurable software name, version comparison, and CVE tagging. |

### Persistence (TA0003)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Sensitive Group Membership Changes](persistence/sensitive-group-membership-changes.kql) | T1098 | Detects members added or removed from sensitive Active Directory groups (Domain Admins, Enterprise Admins, etc.). |
| [ChatGPT Stealer Extension Installation](persistence/chatgpt-stealer-extension-installation.kql) | T1176 | Detects installation of known malicious browser extension IDs associated with the ChatGPT Stealer campaign targeting AI session tokens. |

### Execution (TA0002)

| Query | Technique | Description |
|:------|:----------|:------------|
| [Winget Abuse Detection](execution/winget-abuse-detection.kql) | T1218, T1059, T1105 | Multi-layered detection for winget.exe abuse including command shell spawning, temp path execution, suspicious network egress, and unsigned binary drops. |

### Credential Access (TA0006)

| Query | Technique | Description |
|:------|:----------|:------------|
| [ML-Based Privileged Account Anomaly Detection](credential-access/ml-privileged-account-anomaly-detection.kql) | T1078, T1098, T1087, T1556 | Multi-layered, self-calibrating detection combining statistical anomaly detection, absolute rules, ratio-based thresholds, behavioral shift analysis, reconnaissance anomaly detection, and MFA gap detection for privileged accounts. |

### Command and Control (TA0011)

| Query | Technique | Description |
|:------|:----------|:------------|
| [CATO Networks Blocked URL Access](command-and-control/cato-networks-blocked-url-access.kql) | T1189, T1071.001 | Identifies blocked URL access attempts from CATO Networks security policies with configurable device and URL filtering. |
| [ChatGPT Stealer C2 Domains](command-and-control/chatgpt-stealer-c2-domains.kql) | T1071.001, T1567 | Detects network connections to known C2 domains used by the ChatGPT Stealer campaign for AI session token exfiltration. |

### Exfiltration (TA0010)

| Query | Technique | Description |
|:------|:----------|:------------|
| [USB File Copy — Intune Enriched](exfiltration/usb-file-copy-intune-enriched.kql) | T1052.001 | Detects files written to USB drives with enrichment from fleet-wide PnP events, providing VID_PID, InstancePathId, and SerialNumberId for Intune device control cross-referencing. |
| [Periodic AI Data Exfiltration (Beaconing)](exfiltration/periodic-ai-data-exfiltration-beaconing.kql) | T1071.001, T1041 | Detects periodic beaconing behavior from browser processes to external domains, designed to catch automated data exfiltration by malicious extensions at ~30-minute intervals. |

### Security Operations

| Query | Description |
|:------|:------------|
| [MSSP Alert Tracking & Deduplication](security-operations/mssp-alert-tracking-deduplication.kql) | Configurable query to track and deduplicate alert emails from an MSSP, using session logic to group email bursts and extract case numbers from portal URLs. |
| [Imperva WAF Blocked Requests by Organization](security-operations/imperva-waf-blocked-requests-by-org.kql) | Multi-layer aggregation of Imperva WAF blocked requests, enriched with ASN/organization data, rolling up from pattern → attack type → IP → organization for threat analysis. |
| [Email Delivery Telemetry & Threat Exposure](security-operations/email-delivery-telemetry-threat-exposure.kql) | Identifies accounts with the highest email volume and threat exposure, including a key risk metric for threats that bypassed filtering and reached user inboxes. |

---

## 🛠️ Platforms

- **Microsoft Sentinel** (primary — uses `TimeGenerated`)
- **Microsoft Defender XDR** Advanced Hunting (replace `TimeGenerated` with `Timestamp` where noted)

---

## 📝 Usage

Each query is self-contained with inline documentation. Copy the `.kql` file contents directly into your Sentinel Logs or Defender Advanced Hunting query editor. Review the configuration sections at the top of each query and adjust parameters (time windows, thresholds, exclusion lists) for your environment before deploying.

---

## 📄 License

These queries are shared for the benefit of the security community. Use and modify them freely. Attribution is appreciated but not required.
