# UI reference lock — IT4US EASM

**Brief:** build a web application for IT4US SOC analysts and customer viewers. The core job is to inventory internet-facing assets, review changes, triage exposures, and share a project-scoped report.

## Research used

- **Censys ASM Inventory** (official docs, screenshot and inventory guidance): compact asset taxonomy, source/risk/date columns, filtering and CSV export.
- **Microsoft Defender EASM dashboards** (official Microsoft Learn): separate inventory changes from posture insights and provide time filters.
- **runZero inventory guide** (official help): searchable inventory, service/software pivots, asset detail, and exports.
- **Refero MCP** was attempted for style/screen/flow research; service returned `NO_SUBSCRIPTION`. Local `refero-design` craft rules were used for the visual constraints below.

## Reference lock

- **Primary product pattern:** Censys inventory and asset details; adapt the inventory-first hierarchy, not its visual assets or branding.
- **Secondary pattern:** Defender EASM changes and posture summaries; preserve separate time-based change and current-risk views.
- **Borrowed detail:** runZero-style filtering and source-aware asset records.
- **Visual direction:** light operations workspace, compact typography, deep navy navigation, cool gray canvas, crisp table dividers, turquoise accent reserved for primary action/focus, semantic amber/red for risk states.
- **Product signature:** a persistent evidence strip on asset/finding details showing source, last observed time, ownership confidence, and validation state.
- **Reject:** dark-mode-by-default, decorative gradients, card grid for every metric, fake live charts, unqualified “vulnerable” labels, or one-click active scans.
- **Density:** desktop-first SOC console, responsive below 960px with collapsible navigation and horizontally scrollable tables; readable customer view on tablet.
- **Tokens:** `--navy-950 #0C1B2A`, `--navy-800 #173247`, `--canvas #F4F7F8`, `--surface #FFFFFF`, `--line #DCE4E8`, `--ink #182A37`, `--muted #657684`, `--teal #0C938B` (primary action/selected), `--red #B54745` (high risk only), `--amber #B7791F` (needs review), `--green #277A5B` (validated/healthy).

## Decision ledger

| Decision | Source and role | Why |
|---|---|---|
| Inventory table is the primary work surface | Censys and runZero inventory docs | SOC work needs filtering and triage across many assets. |
| Overview separates counts, changes, and observations | Microsoft Defender EASM dashboards | Keeps trends distinct from actionable posture signals. |
| Use restrained light workspace with navy navigation | IT4US SOC use case + local anti-AI-slop craft guidance | Supports long sessions and dense reading without generic dark/indigo styling. |
| Evidence state stays visible in detail and table rows | User requirement for client-visible EASM; project governance | Prevents provider observations from being mistaken for confirmed ownership or vulnerabilities. |
| Client view is a separate permissioned surface | User request for customer visibility | Gives clients useful evidence without analyst-only triage notes or cross-project data. |
