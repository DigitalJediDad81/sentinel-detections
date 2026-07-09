# Sentinel Detection Engineering: 5 MITRE ATT&CK-Mapped Analytics Rules

**Author:** Juan Rojas
**Environment:** Hybrid detection lab — Azure Sentinel, fed by Azure Arc + Azure Monitor Agent across 2 Windows domain controllers and 2 Linux hosts (Proxmox, `casa.lab` domain)
**Workspace:** `law-casalab-sentinel` | Resource Group `rg-sentinel` | East US 2

## Architecture

```
Windows DCs (WINDC1, WINDC2) ─┐
                               ├─→ Azure Arc → Azure Monitor Agent → Data Collection Rules → Log Analytics → Sentinel Analytics Rules → Incidents
Linux hosts (linuxcore1/2) ───┘
```

**Data Collection Rules:**
- `dcr-casalab-security` — Windows Security Event IDs 4624, 4625, 4768, 4769, 4776
- `dcr-casalab-linux-syslog` — Linux `auth`, `authpriv` facilities

**Seeded lab conditions** (intentional attack surface for validation):
- `svc-c3po` — RC4-only service account (`msDS-SupportedEncryptionTypes=4`) → Kerberoastable
- `svc-ig88`, `svc-kyloren`, `svc-boba` — pre-authentication disabled → AS-REP roastable

Every rule below was not just written — it was **validated against real attack traffic** generated in the lab (Parrot OS red-team box running Impacket/NetExec), confirmed to fire, then tuned for false-positive reduction.

---

## Rule 1 — Kerberoasting Detection

| Field | Value |
|---|---|
| **MITRE Technique** | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| **Data Source** | Windows Security Event ID 4769 (Kerberos Service Ticket Request) |
| **Severity** | High |
| **What it catches** | Abnormal volume of TGS requests for service accounts using weak (RC4) encryption — the precursor to offline hash cracking |
| **Validation** | Fired against `svc-c3po` using `impacket-GetUserSPNs -request-user svc-c3po`; encryption type `0x17` (RC4) confirmed in raw event data |
| **Status** | Live incident confirmed |

**Key engineering detail:** Azure Monitor Agent leaves the named `SecurityEvent` columns empty for this event type — the rule parses the raw `EventData` XML directly (`extract(@'"Field">([^<]+)<', 1, EventData)`) to pull ticket encryption type and target account.

## Rule 2 — AS-REP Roasting Detection

| Field | Value |
|---|---|
| **MITRE Technique** | T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting |
| **Data Source** | Windows Security Event ID 4768 (Kerberos Authentication Ticket Request) |
| **Severity** | High |
| **What it catches** | Accounts with "Do not require Kerberos preauthentication" enabled being targeted for offline AS-REP hash extraction |
| **Validation** | Fired against `svc-ig88`, `svc-kyloren`, `svc-boba` using `impacket-GetNPUsers` |
| **Status** | Live incident confirmed |

## Rule 3 — Password Spray Detection

| Field | Value |
|---|---|
| **MITRE Technique** | T1110.003 — Brute Force: Password Spraying |
| **Data Source** | Windows Security Event ID 4776 (NTLM credential validation) |
| **Severity** | Medium/High (volume-dependent) |
| **What it catches** | Low-and-slow failed authentication attempts spread across many distinct usernames from a single source, within a rolling window |
| **Validation** | Fired using a scripted loop (`smbclient`/NetExec) iterating credentials against the DC **by IP address** |
| **Status** | Live incident confirmed |

**Key engineering detail:** the spray must target the DC by IP, not hostname — hitting by hostname forces Kerberos preauth (Event 4771), which isn't in the collected event set. By IP forces an NTLM fallback (Event 4776), which is. Tooling that authenticates by hostname (e.g., `kerbrute`, plain `net use`) produces zero signal against this rule — a real-world tuning lesson, not just a lab quirk.

## Rule 4 — SSH Brute Force Detection

| Field | Value |
|---|---|
| **MITRE Technique** | T1110.001 — Brute Force: Password Guessing |
| **Data Source** | Linux `auth.log` / sshd events via AMA (Syslog table) |
| **Severity** | Medium |
| **What it catches** | High-frequency failed SSH authentication attempts from a single source IP within a short window |
| **Validation** | Confirmed by query against `linuxcore1` (sshd target) |
| **Status** | Validated by query (not yet incident-triggered in this pass) |

## Rule 5 — Linux Account Lifecycle Abuse

| Field | Value |
|---|---|
| **MITRE Techniques** | T1136.001 (Create Account: Local Account), T1548.003 (Abuse Elevation Control Mechanism: Sudo/Sudo Caching), T1070 (Indicator Removal) |
| **Data Source** | Linux audit logs — `useradd`, `userdel`, `passwd`, sudo events |
| **Severity** | Medium/High |
| **What it catches** | Unusual account creation → privilege escalation → deletion sequences outside expected change windows — a classic "create a backdoor account, use it, clean up" pattern |
| **Validation** | Live incident confirmed |

**Key engineering detail:** this rule matches on `SyslogMessage` text content rather than `ProcessName`, since `ProcessName` is frequently blank in the raw Linux audit stream depending on the logging path.

---

## Summary Table

| Rule | Technique(s) | Data Source | Status |
|---|---|---|---|
| Kerberoasting | T1558.003 | Windows 4769 | Incident confirmed |
| AS-REP Roasting | T1558.004 | Windows 4768 | Incident confirmed |
| Password Spray | T1110.003 | Windows 4776 | Incident confirmed |
| SSH Brute Force | T1110.001 | Linux auth.log | Validated by query |
| Linux Account Lifecycle | T1136.001 / T1548.003 / T1070 | Linux audit logs | Incident confirmed |

## Engineering Lessons (worth keeping — these are the details that separate "ran a tutorial" from "built a detection capability")

1. **AMA's raw XML quirk**: `SecurityEvent` named columns come back empty from Azure Monitor Agent for several event types — queries have to parse `EventData` XML directly rather than relying on pre-parsed fields.
2. **Lookback vs. ingestion lag**: AMA ingestion lag runs 5–15 minutes. Setting rule lookback equal to query frequency (e.g., both at 5 minutes) silently misses events that land just outside the window. Rules use ~1 hour lookback with 5–10 minute frequency and suppression enabled.
3. **Attack path forces protocol choice**: the password spray rule only works if the attack traffic is generated in a way that forces the expected authentication protocol (NTLM via IP-based access) — a mismatch between attack tooling and detection logic produces a rule that looks broken but is actually just untested against the right traffic.
4. **Linux log field reliability**: don't assume structured fields like `ProcessName` are populated — validate against actual log samples before building match logic around a field that might be empty in production.

## Repo Structure (for version control)

```
sentinel-detections/
├── README.md
├── rules/
│   ├── kerberoasting/
│   │   ├── rule.yaml
│   │   └── query.kql
│   ├── asrep-roasting/
│   │   ├── rule.yaml
│   │   └── query.kql
│   ├── password-spray/
│   │   ├── rule.yaml
│   │   └── query.kql
│   ├── ssh-bruteforce/
│   │   ├── rule.yaml
│   │   └── query.kql
│   └── linux-account-lifecycle/
│       ├── rule.yaml
│       └── query.kql
└── docs/
    └── architecture.md
```

Metadata (`rule.yaml`) is kept separate from query logic (`query.kql`) so query changes show as clean git diffs rather than buried inside a JSON blob — the same convention used in Microsoft's own public Azure-Sentinel GitHub repository.
