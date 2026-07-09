# Sentinel Detections — casa.lab

A detection engineering portfolio built on a hybrid Microsoft Sentinel lab. Five MITRE ATT&CK-mapped analytics rules, validated against real attack traffic, backed by agent-based vulnerability management and a full interactive workbook — all built end-to-end on a self-hosted Windows/Linux environment feeding Azure natively.

## Why this exists

Most "I know Sentinel" claims are portfolio-thin — a screenshot of a template rule with no proof it ever fired. This repo documents the opposite: rules written against specific ATT&CK techniques, attacked from a red-team box to confirm they actually detect what they claim to, tuned after false positives, and wrapped in the vulnerability management and visualization layers a real detection engineering practice needs around it.

## Architecture

```
Windows DCs (WINDC1, WINDC2) ─┐
                               ├─→ Azure Arc → Azure Monitor Agent → Data Collection Rules → Log Analytics → Sentinel → Incidents
Linux hosts (linuxcore1/2) ───┘
                               └─→ Defender for Servers → MDE agent → Microsoft Defender Vulnerability Management
```

Workspace: `law-casalab-sentinel` | Resource Group: `rg-sentinel` | Region: East US 2

## Contents

| Doc | What it covers |
|---|---|
| [`sentinel-detection-rules.md`](./sentinel-detection-rules.md) | The five MITRE-mapped analytics rules — Kerberoasting, AS-REP Roasting, Password Spray, SSH Brute Force, Linux Account Lifecycle Abuse — with data sources, validation status, and the KQL engineering gotchas hit along the way (raw XML parsing, ingestion-lag tuning, protocol-forcing for the spray detection) |
| [`sentinel-workbook.md`](./sentinel-workbook.md) | The 19-panel interactive workbook that visualizes all five detections — one overview table plus a chart + detail table per rule, driven by a shared time-range filter, built and exported programmatically for reproducibility |
| [`mdvm-mde-deployment.md`](./mdvm-mde-deployment.md) | Standing up Microsoft Defender Vulnerability Management and Defender for Endpoint across all four Arc-enrolled hosts — the decision process (why not the retired Qualys scanner, why "agentless" doesn't cover on-prem), findings, and remediation |

## The five detections at a glance

| Rule | MITRE Technique | Data Source | Status |
|---|---|---|---|
| Kerberoasting | T1558.003 | Windows Event 4769 | Incident confirmed |
| AS-REP Roasting | T1558.004 | Windows Event 4768 | Incident confirmed |
| Password Spray | T1110.003 | Windows Event 4776 | Incident confirmed |
| SSH Brute Force | T1110.001 | Linux auth.log | Validated by query |
| Linux Account Lifecycle Abuse | T1136.001 / T1548.003 / T1070 | Linux audit logs | Incident confirmed |

## Detection Validation

Detection rules are only as good as the evidence they've been tested against. This section documents hands-on validation exercises confirming the analytics rules and scanning tooling above actually catch what they claim to.

| Exercise | Focus | Write-up |
|---|---|---|
| Nessus vuln-lab scan | Deliberately misconfigured Azure VM (outdated Samba, anonymous FTP, weak SSH config, weak local credentials) scanned before/after hardening changes to validate detection coverage | [`docs/validation/vuln-lab-nessus-scan-writeup.md`](docs/validation/vuln-lab-nessus-scan-writeup.md) |

**Approach:** rather than trusting a clean scan result at face value, target infrastructure is deliberately built with known weaknesses, isolated in its own network segment (no public IP, NSG deny-by-default, JIT-scoped management access), scanned, then hardened and re-scanned to confirm findings close out. Maps to the NIST CSF Detect function, with Respond/Recover as a planned follow-on.

## Planned next

- Version-controlled rule definitions (`rules/<name>/rule.yaml` + `query.kql`) with a GitHub Actions workflow to deploy via ARM on merge to `main` — not yet built, noted honestly rather than implied as done
- Cross-referencing MDVM exposure findings against hosts with live detections firing, to tie vulnerability management and detection engineering into one combined risk view

## About

Built by Juan Rojas — Information Security Manager, ~20 years across IAM, PAM, vulnerability management, and cloud security. This lab supports both ongoing SC-300/SC-200 certification prep and a consulting practice ([Intihuatana Cyber LLC](#)) focused on Microsoft-stack security for SMBs.
