# Sentinel Detection Workbook — casa.lab

**Author:** Juan Rojas
**Workspace:** `law-casalab-sentinel` | `rg-sentinel` | East US 2
**Artifact:** `casalab-detections-workbook.json` — 19 panels, portable, importable via Advanced Editor

## Objective

Most of the value in five well-built detection rules is invisible unless someone can *see* them fire — raw incidents in a queue don't tell a story on their own. This workbook turns the five MITRE-mapped Sentinel rules into a single interactive dashboard: one overview of everything at a glance, then a dedicated chart + detail table for each detection, all driven by a shared time-range selector.

It also solves a practical portfolio problem: a workbook is hard to explain with a static screenshot alone. Documenting *why* each panel exists — not just what it shows — makes it usable as a narrated walkthrough in an interview, not just a picture.

## What a Workbook Is (and isn't)

Worth stating plainly since the terminology gets confused: a Sentinel **workbook** is an interactive, queryable dashboard — distinct from a **runbook** (a scripted, tactical set of steps for one specific task, like the Automation Account runbook used in the managed identity lab) and a **playbook** (Sentinel's term for an automated response workflow, built on Logic Apps, that runs when an incident fires). This workbook doesn't take action — it visualizes. Response automation is a separate, not-yet-built layer.

## Structure — 19 panels

| # | Panel | Type | Purpose |
|---|---|---|---|
| 1 | Title | Text | Workbook header/context |
| 2 | Time range parameter | Parameter (pills) | Global filter — every query panel below respects this selection |
| 3 | Overview | Text | Section intro |
| 4 | Detections → MITRE → Platform → Hits | Table | Single-glance summary: all 5 rules, their ATT&CK technique, Windows/Linux platform, and hit count in the selected window |
| 5 | Kerberoasting section header | Text | Context for the two panels below |
| 6 | RC4 service-ticket requests over time | Time chart | Visualizes Kerberoasting attempt volume/timing — spikes are immediately visible |
| 7 | Roasting events | Table | Row-level detail: account targeted, source, timestamp |
| 8 | AS-REP Roasting section header | Text | Context |
| 9 | AS-REP requests over time | Time chart | Timing/volume of AS-REP attempts |
| 10 | Pre-auth-disabled accounts targeted | Table | Which specific accounts (the seeded `svc-ig88`, Kylo Ren, Boba Fett) were hit |
| 11 | Password Spray section header | Text | Context |
| 12 | Distinct accounts failed per source | Bar chart | The core spray signature — one source IP touching many different accounts |
| 13 | Spray sources (≥5 distinct accounts) | Table | Sources that crossed the detection threshold |
| 14 | SSH Brute Force section header | Text | Context |
| 15 | Failed SSH attempts over time | Time chart | Volume/timing of SSH auth failures |
| 16 | Brute-force sources (≥5 attempts) | Table | Sources that crossed threshold against `linuxcore1` |
| 17 | Linux Account Lifecycle section header | Text | Context |
| 18 | Account actions by type | Bar chart | Breakdown of create/modify/delete events |
| 19 | Account lifecycle events | Table | Row-level detail on the create→privesc→delete pattern |

The pattern repeats deliberately for each of the five detections: **header → trend visualization → detail table**. That consistency means anyone looking at the workbook cold — an interviewer, a client — can predict where to look for what, without needing it explained panel-by-panel.

## Design Decisions Worth Noting

- **A shared time-range parameter drives every panel.** Built once as a single parameter (`param-timerange`) rather than hardcoding a window into each query — narrowing to "last hour" during a live attack demo, or widening to "last 30 days" for a trend review, updates all 19 panels at once.
- **Chart + table pairing, not chart-only or table-only.** The chart answers "when and how much," the table answers "which specific account/host/IP." Attackers and incident responders need both — a chart alone can't answer "was it Han Solo or Kylo Ren," and a table alone buries the timing pattern that makes spray/brute-force attacks visually obvious.
- **Overview table first.** Before drilling into any one detection, the top table answers "what's actually firing right now, across all five rules" in one row-per-rule view — the same shape an actual SOC triage screen would use.
- **Built and exported programmatically**, not hand-clicked in the portal UI. The workbook JSON was generated from a Python script assembling text/parameter/query items into the Azure Workbook schema, then validated by round-tripping the JSON before import. This makes the workbook itself version-controllable and reproducible — rebuildable from source rather than a one-off portal artifact that can't be diffed or restored if accidentally broken.

## Import Steps (for reproducing in a new workspace)

1. Sentinel → **Workbooks** → **+ Add workbook**
2. Open in edit mode → click the **Advanced Editor** icon (`</>`) in the toolbar
3. Paste the contents of `casalab-detections-workbook.json`
4. Apply, then save with a name (e.g., "casa.lab Detection Overview")
5. Verify all 19 panels render and the time-range parameter correctly filters every query panel

## Interview / Portfolio Framing

> "Five detection rules are only as useful as your ability to see what they're catching. I built a 19-panel Sentinel workbook — one overview table showing all five rules against their MITRE mapping and hit counts, then a dedicated trend chart and detail table for each detection, all driven by a single shared time-range filter. I generated it programmatically rather than clicking through the portal UI, so the whole thing is reproducible and version-controlled, not a one-off dashboard I'd have to rebuild by hand if it broke."

## Next Steps

- Add a panel cross-referencing MDVM exposure findings against hosts with live detections firing — ties the vulnerability management work and the detection engineering work into one combined risk view
- Consider a drill-down link from the overview table directly into each detection's incident queue in Sentinel, if supported by the current workbook schema version
- Export a static PDF/image snapshot periodically as a point-in-time portfolio artifact, since the live workbook itself isn't easily shareable outside the tenant
