# Microsoft Defender Vulnerability Management (MDVM) & Defender for Endpoint (MDE) Deployment

**Author:** Juan Rojas
**Environment:** 4x Azure Arc-enrolled hosts (WINDC1, WINDC2, linuxcore1, linuxcore2) — `casa.lab`
**Workspace/Subscription:** `law-casalab-sentinel` | `rg-sentinel` | East US 2

## Objective

Stand up agent-based vulnerability management and endpoint protection across every host in the lab using Microsoft's native stack — Defender for Servers → auto-deploys MDE → lights up MDVM — rather than a separate scanner, since this is exactly the stack an SMB client on M365/Defender would actually run. Time-boxed to the trial window to demonstrate real findings without incurring ongoing cost.

## Decision: Why Defender for Servers (not a separate scanner)

Considered three options before deploying:

| Option | Tradeoff |
|---|---|
| **MDVM via Defender for Servers** (chosen) | Zero additional scanner infrastructure — since all 4 hosts were already Arc-enrolled, enabling Defender for Servers auto-deploys the MDE agent and MDVM findings appear with no separate install. On-brand for an M365/Defender-stack consulting pitch. |
| Third-party network scanner (e.g., OpenVAS/Greenbone) | Free forever, unlimited scans, clean exportable reports — but doesn't demonstrate the Microsoft-native stack a client would actually be sold on. Better suited as a *complementary*, not primary, exercise. |
| Integrated Qualys scanner | **Not viable** — Microsoft fully retired the integrated Qualys vulnerability scanner as of May 1, 2024. MDVM via the MDE agent is the current path. |

**Key constraint that shaped the decision:** Defender's "agentless scanning" capability only covers Azure VMs — it does **not** extend to Arc-connected/on-prem machines. For on-premises hosts like this lab's DCs and Linux boxes, the MDE agent is mandatory for vulnerability visibility regardless of which Defender for Servers plan is selected. This is a common point of confusion worth knowing cold for both the exam and client conversations — "agentless" doesn't mean "no agent everywhere," it means "no agent, but only on Azure-native compute."

## Cost Management

Defender for Servers offers a single 30-day free trial per subscription that cannot be paused, stopped, or extended once started. Post-trial list pricing:

| Plan | Cost/server/month | Includes |
|---|---|---|
| Plan 1 | ~$7 | Core Defender for Endpoint protection |
| Plan 2 | ~$15 | Adds MDVM, JIT access, adaptive app controls, file integrity monitoring |

At 4 machines, that's $28–60/month ongoing. **Approach used:** enable during the trial, capture findings and screenshots for the portfolio, then disable before billing kicks in — the goal was demonstrated capability, not a permanent production deployment on a home lab budget.

## Deployment Steps

1. **Azure Portal → Defender for Cloud → Environment settings** → select the subscription/RG containing the Arc machines
2. **Enable Defender for Servers** (Plan 2, to get MDVM alongside core MDE protection) at the subscription or resource-group scope
3. Confirm auto-provisioning is enabled for the MDE agent — this pushes the agent to all Arc-connected machines in scope automatically, no manual install needed
4. Verify each of the 4 hosts shows **Onboarded** status in **Defender for Cloud → Inventory**
5. Allow 24–48 hours for initial vulnerability assessment data to populate — MDVM findings aren't instant on first onboarding

## Findings — Endpoint Exposure Snapshot

Initial dashboard results from **Microsoft Defender Vulnerability Management** (Defender portal → Vulnerability management → Dashboard):

- **Endpoint exposure score: 26/100** (low range) — Microsoft's aggregate risk score across all onboarded devices, weighted toward unpatched CVEs and risky configurations
- **Device exposure distribution**: breakdown of devices by exposure tier (low/medium/high)
- **Exposure score trend**: tracked over time to show whether remediation is improving posture, not just a point-in-time snapshot

### Top prioritized recommendations surfaced

- Enable real-time antivirus protection (found disabled/misconfigured on at least one host)
- Block executable content from email clients and webmail (Attack Surface Reduction rule)
- Block Office applications from injecting code into other processes (Attack Surface Reduction rule)

These three all fall under **Attack Surface Reduction (ASR) rules** — a Defender capability that blocks specific behaviors commonly used in malware/ransomware execution chains, independent of signature-based detection. Prioritizing ASR rule gaps first (before individual CVE patching) is generally the highest-leverage move in a low exposure-score environment, since ASR rules block entire classes of attack technique rather than one vulnerability at a time.

## Remediation Actions Taken

- Enabled the missing ASR rules identified above via Defender's recommendation flow (one-click "Remediate" from the recommendation card, which pushes an Intune/GPO-backed policy — in this lab's case applied locally per host given the small scale)
- Verified real-time antivirus protection status corrected on the affected host
- Re-checked exposure score after remediation to confirm the trend line moved in the right direction

## Interview / Portfolio Framing

> "Since I'd already Arc-onboarded my lab hosts for Sentinel telemetry, I flipped on Defender for Servers Plan 2 and got Microsoft Defender Vulnerability Management running with zero extra scanner infrastructure — same MDE agent, same Arc connection, additional capability. I found real gaps: real-time AV wasn't fully enforced on one host, and none of my Attack Surface Reduction rules were configured. I remediated all three top findings and watched the exposure score move. I also made a deliberate cost call — ran it inside the 30-day trial, captured the findings, then disabled it before billing started, since a home lab doesn't need standing production spend to prove the capability."

## Notes for Future Iteration

- Consider re-enabling for a short window closer to interview season to capture a fresh before/after exposure-score screenshot pair
- MDVM findings are a natural complement to the Sentinel detection rules — a host with a known CVE plus a live Kerberoasting detection on the same box tells a more complete "vulnerability + detection + response" story than either alone
- Worth exploring whether Defender for Cloud's exportable reports (PDF/CSV) give a cleaner artifact than portal screenshots for a written case study
