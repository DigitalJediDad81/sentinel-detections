# Intentional Vulnerability Lab: Nessus Detection Validation

## Objective

Stand up an isolated, deliberately unpatched Azure VM within the Nessus scanning environment to validate detection coverage — confirming Nessus Essentials correctly identifies known-bad configurations rather than trusting a "0 findings" result on a hardened box. Structured as a before/after (baseline vs. aged) comparison to demonstrate the NIST CSF **Detect** function in a reproducible way.

---

## 1. Architecture

| Component | Purpose |
|---|---|
| Nessus scanner VM | Existing Azure VM running Nessus Essentials, private-only access |
| Isolated target VNet | New, dedicated VNet for the vulnerable target — no route to any other lab resource |
| Network Security Group (NSG) | Locks inbound access to the target subnet down to the Nessus scanner's private IP only |
| VNet Peering (cross-region) | Connects the target VNet to the Nessus VNet at the network layer |
| Just-In-Time (JIT) access | Microsoft Defender for Cloud JIT rule restricting SSH management access to an approved source IP, time-boxed |
| Target VM (`vuln-test-vm`) | Ubuntu 20.04, no public IP, intentionally left unpatched with specific outdated/misconfigured services |

Design principle: the vulnerable target has **no public IP** and is reachable only via the scanner's peered network path — the deliberately weak box is never internet-facing.

---

## 2. Environment Setup (Azure CLI)

### 2.1 Resource group and isolated VNet

```bash
az group create --name rg-vuln-lab --location eastus

az network vnet create \
  --resource-group rg-vuln-lab \
  --name vnet-vulnlab \
  --address-prefix 10.10.0.0/24 \
  --subnet-name subnet-vulnlab \
  --subnet-prefix 10.10.0.0/24
```

### 2.2 Network Security Group — deny-by-default, explicit allow

```bash
az network nsg create --resource-group rg-vuln-lab --name nsg-vulnlab

# Allow inbound SSH only from the Nessus scanner's private IP
az network nsg rule create \
  --resource-group rg-vuln-lab \
  --nsg-name nsg-vulnlab \
  --name Allow-Nessus-SSH \
  --priority 100 \
  --source-address-prefixes <NESSUS_SCANNER_PRIVATE_IP> \
  --destination-port-ranges 22 \
  --access Allow \
  --protocol Tcp \
  --direction Inbound

# Explicit deny for everything else
az network nsg rule create \
  --resource-group rg-vuln-lab \
  --nsg-name nsg-vulnlab \
  --name Deny-All-Else \
  --priority 4096 \
  --source-address-prefixes '*' \
  --destination-port-ranges '*' \
  --access Deny \
  --protocol '*'
```

### 2.3 Target VM — no public IP, sized to available subscription quota

```bash
az vm create \
  --resource-group rg-vuln-lab \
  --name vuln-test-vm \
  --image "Canonical:0001-com-ubuntu-server-focal:20_04-lts:<version>" \
  --size Standard_D2s_v3 \
  --vnet-name vnet-vulnlab \
  --subnet subnet-vulnlab \
  --nsg nsg-vulnlab \
  --public-ip-address "" \
  --admin-username labadmin \
  --ssh-key-values ~/.ssh/id_rsa.pub
```

> **Note:** Initial attempts used `Standard_B1s`/`Standard_B1ms` (unavailable capacity in region) and Arm64 `Standard_B2pts_v2` (zero approved quota on this subscription tier). `Standard_D2s_v3` was selected because it matched a size already confirmed to have approved quota via the existing Nessus VM deployment.

### 2.4 Cross-region VNet peering

The Nessus scanner and the new target VNet sit in different Azure regions, requiring Global VNet Peering (bidirectional):

```bash
# Target VNet -> Nessus VNet
az network vnet peering create \
  --name peer-vulnlab-to-nessus \
  --resource-group rg-vuln-lab \
  --vnet-name vnet-vulnlab \
  --remote-vnet <NESSUS_VNET_RESOURCE_ID> \
  --allow-vnet-access

# Nessus VNet -> Target VNet
az network vnet peering create \
  --name peer-nessus-to-vulnlab \
  --resource-group <NESSUS_RESOURCE_GROUP> \
  --vnet-name <NESSUS_VNET_NAME> \
  --remote-vnet <VULNLAB_VNET_RESOURCE_ID> \
  --allow-vnet-access
```

Verified `PeeringState: Connected` / `FullyInSync` on both sides before proceeding. No address-space overlap between the two VNets (`10.10.0.0/24` vs. the Nessus VNet's `/16`), so peering succeeded without conflict.

---

## 3. Access Path

Since the target has no public IP, it's reached via SSH jump through the Nessus scanner VM, which itself sits behind a Defender for Cloud JIT rule scoping SSH access to a specific approved source IP.

**SSH client config** (`~/.ssh/config`):

```
Host nessus-jump
    HostName <NESSUS_PUBLIC_IP>
    User socadmin
    IdentityFile <path-to-nessus-key>

Host vuln-test-vm
    HostName 10.10.0.4
    User labadmin
    IdentityFile <path-to-vulnlab-key>
    ProxyJump nessus-jump
```

Connection: `ssh vuln-test-vm`

**Lesson learned:** the `-J` (ProxyJump) command-line flag does not reliably propagate `-i` identity file arguments to the jump host itself — an SSH config file with explicit `IdentityFile` per `Host` block resolved this cleanly and is the recommended pattern for any future multi-hop lab access.

---

## 4. Deliberate Vulnerability Introduction

Rather than a general `apt update && apt upgrade`, specific outdated/misconfigured services were installed to produce known, plugin-detectable findings:

```bash
# Outdated Samba — historically CVE-rich version line
sudo apt install samba=2:4.11.6* -y --allow-downgrades

# vsftpd with anonymous access enabled
sudo apt install vsftpd -y
sudo sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf
sudo systemctl restart vsftpd

# Weakened SSH daemon config
sudo sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Weak-password local account, for credentialed-scan demonstration
sudo useradd -m -p $(openssl passwd -1 'password123') testuser
```

| Change | Expected Nessus finding category |
|---|---|
| Downgraded Samba | Outdated software / known CVEs (version-specific) |
| Anonymous FTP enabled | Insecure service configuration |
| Root login + password auth permitted | SSH hardening / authentication misconfiguration |
| Weak local account password | Credentialed weak-password finding |

---

## 5. Scan Methodology

1. **Baseline scan** — run against the target *before* the aging steps above, to confirm a relatively clean starting posture and validate scan mechanics (target reachability, port discovery, plugin execution) end to end.
2. **Aging steps applied** (Section 4).
3. **Post-change scan** — re-run against the same target to confirm the specific introduced weaknesses are surfaced.

Scan template: **Basic Network Scan**. Discovery phase (host alive check → port scan → service fingerprinting) precedes vulnerability plugin execution.

Credentials: SSH credentials for `labadmin` (and optionally `testuser`) added under the scan's **Credentials** tab to enable authenticated scanning — necessary to surface local package-version and configuration findings that an unauthenticated network scan would miss entirely.

---

## 6. Findings

*(To be completed once the post-change scan finishes — fill in with actual Nessus plugin IDs, severities, and CVE references pulled from the scan report.)*

| Finding | Severity | Plugin/CVE ref | Notes |
|---|---|---|---|
| — | — | — | — |

---

## 7. NIST CSF Mapping

| Function | Category | Applied here |
|---|---|---|
| **Identify** | Asset & vulnerability management | Target VM defined, scoped, and isolated prior to testing |
| **Protect** | Access control | NSG deny-by-default + JIT + SSH key-based auth on all hops |
| **Detect** | Continuous monitoring | Nessus scan (baseline + post-change) surfaces introduced weaknesses |
| **Respond** | (Optional next phase) | Remediate findings, document fix, re-scan to confirm closure |
| **Recover** | (Optional next phase) | Re-harden target or tear down lab resources post-exercise |

---

## 8. Next Steps

- [ ] Complete post-change scan, populate findings table with real plugin/CVE data
- [ ] Remediate one or more findings (e.g., disable anonymous FTP, revert SSH config) and re-scan to demonstrate closure — completes the Respond/Recover mapping
- [ ] Fold this exercise into the detections-as-code repo as a documented before/after case study
- [ ] Apply the same JIT-scoping pattern used on the Nessus VM to `vuln-test-vm` if the lab is kept running beyond this exercise, rather than relying solely on the static NSG allow rule
- [ ] Tear down `rg-vuln-lab` resources (or explicitly schedule teardown) once the writeup is finalized, to avoid ongoing cost/exposure from an intentionally weakened VM

---

*IP addresses, resource group names tied to production lab identity, and public endpoints have been redacted or replaced with placeholders in this document.*
