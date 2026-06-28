# 🛡️ Nessus Conector for GLPI

[English](README.md) / [Português do Brasil](readme_pt-br.md)

![Nessus Conector](images/nessus-logo.png)

**Nessus Conector** is a GLPI 11 plugin that pulls vulnerability data from **Tenable** products, links every finding to the matching GLPI asset, keeps a full synchronization history, and turns vulnerabilities into actionable GLPI tickets — automatically opening them when a flaw appears and resolving them when it is gone.

🏷️ Version: `1.4.0` · Authors: celsocaninde / Claude (fork of [magaiverpr/NessusConector](https://github.com/magaiverpr/NessusConector))

It supports two Tenable sources out of the box:

| Source | What it imports | API family |
| --- | --- | --- |
| 🖥️ **Nessus / Tenable VM** | scans, hosts and vulnerability plugins | `/scans` |
| 🌐 **Tenable WAS** | web application scan executions and findings | `/was/v2` |

---

## ✨ Features

### 🔌 Connectivity & configuration
- 🔐 Configure the Tenable **API URL**, **access key** and **secret key** right inside GLPI.
- 🔒 **Secrets are encrypted at rest** with GLPI's own security key (`GLPIKey`) — no more plaintext API keys in the database.
- 🧪 **One-click connection test** per provider (Nessus VM and WAS), with live latency feedback and friendly error messages.
- ⏱️ Configurable HTTP timeout shared by both providers.

### 📥 Importing
- 🔎 **Browse** available Nessus / Tenable VM scans directly from GLPI.
- 🌐 **Browse** Tenable WAS configurations and their scan executions directly from GLPI.
- 🎚️ **Per-scan severity filter** — import only the severities you care about (Critical → Info).
- 🧩 **Asset matching** of imported targets against GLPI item types (Computer, Network equipment, Printer, Phone, Unmanaged).
- 🕰️ **First-seen / last-seen** tracking and `is_current` staleness flag per finding.

### 📊 Visibility
- 📊 **Severity dashboards** per scan and consolidated across all scans, with clickable severity cards and a distribution bar.
- 🔬 **Vulnerability detail view** with synopsis, description, remediation, CVSS/VPR, plugin output, affected ports and **CVE chips that link to the NVD**.
- 🧱 **Asset tab** — every matched GLPI asset shows its current vulnerabilities inline.
- 🗂️ **Synchronization history** with status, duration and host/vulnerability counts.
- 📋 **Activity log** recording syncs, failures and automatic ticket resolutions.

### 🎫 Tickets
- 🎫 **Individual tickets** from a single vulnerability, with a rich, styled HTML body (severity hero, target context, CVE links, risk table, affected ports, remediation).
- 🌳 **Grouped tickets as a parent → child hierarchy**: one **parent** ticket per affected host plus one **child** ticket per vulnerability, linked through GLPI's native `SON_OF` relationship so the *Linked tickets* panel shows the whole tree.
- 🖥️ **Pending-host tickets** when a target is imported but not yet matched to a GLPI asset.
- ♻️ **Smart de-duplication** — existing tickets/parents are reused instead of creating duplicates.

### 🤖 Automation
- ⚙️ **Background sync worker (cron)** — synchronization no longer depends on keeping a browser tab open:
  - `queue` (every 5 min): drains pending synchronization jobs unattended.
  - `autosync` (daily): re-queues active scans that are due for a refresh.
- ✅ **Automatic ticket resolution** — when a vulnerability stops being detected on its asset, the linked ticket is **automatically solved** (reversible) with an explanatory note. A parent ticket is only resolved once *all* of its findings have cleared.

### 🎨 Experience
- 💎 Modern, premium UI across every screen (cards, chips, toasts, modals) with **dark-mode** support.
- 🔄 **Live sync queue** with a progress bar, per-row "syncing…" indicators and toast notifications.
- 👤 **Per-profile rights** management.
- 🧪 **Automated test suite** for the ticket-content builders.

---

## 📊 Executive Report (v1.4.0 — NEW)

A premium, board-ready report page built with full Tenable branding.

Access via **Plugins → Nessus Conector → Scans → Executive Report** button, or directly at `front/report.php`.

| Section | Description |
| --- | --- |
| 🎯 Risk Index gauge | `conic-gradient` donut showing weighted exposure score (0–100 %) with semantic label |
| 📅 Period selector | **7 / 30 / 90 day** pill buttons — **all data queries filter by `first_seen_at`** |
| 📦 KPI cards | Total vulns in period, Risk Index, affected hosts, linked tickets |
| 📊 Severity bars | Colour-coded bars (Critical → Info) with Tenable official palette |
| 🖥️ Top 10 hosts | Most exposed hosts ranked by critical → high → total, with per-row severity breakdown |
| 🔬 Top 8 critical/high vulns | Plugin names grouped and counted across the fleet |
| 📈 Discovery trend | Daily bar chart for the selected period |
| 📡 Scans status | Last scan date and status for every configured scan |

**Risk Index** = weighted vuln score (critical×10 + high×3 + medium) ÷ max possible × 100

| Range | Colour | Label |
| --- | --- | --- |
| ≤ 25 % | 🟢 Green | Low Exposure |
| ≤ 50 % | 🟡 Amber | Moderate Exposure |
| ≤ 75 % | 🔴 Red | High Exposure |
| > 75 % | 🟥 Dark Red | Critical Exposure |

**Print / PDF**: all GLPI navigation is hidden via `@media print`, so `Ctrl+P` / browser print produces a clean multi-page report.

---

## 🆕 What this fork adds

On top of the original dual-source (VM + WAS) plugin, this fork focuses on production-readiness:

- 📊 **Executive report** (`v1.4.0`) — full-width Tenable-branded page with Risk Index gauge, period filter, top hosts and discovery trend.
- 🔐 **Encrypted API secrets** (`GLPIKey`), with transparent fallback for pre-existing plaintext values.
- ⏱️ **Persistent cron worker** for unattended synchronization (`queue` + `autosync`).
- ✅ **Auto-resolution** of tickets whose vulnerability is no longer detected.
- 📋 **Activity / audit log** with a read-only viewer in the plugin menu.
- 🧪 **Test suite** (PHPUnit-compatible + a zero-dependency runner).

---

## 🖼️ Screenshots

![Nessus Conector screen 1](images/print1.png)

![Nessus Conector screen 2](images/print2.png)

![Nessus Conector configuration](images/print3.png)

---

## ✅ Requirements

- GLPI **11.0.x** (declared compatibility: `>= 11.0.0` and `< 11.1.0`)
- PHP **cURL** extension enabled
- A GLPI security key present (standard on every GLPI install — required for secret encryption)
- Tenable API credentials (access key + secret key)
- A user profile with the **Nessus Conector** rights enabled

Tested with **PHP 8.5**.

---

## 🚀 Installation

Place the plugin directory inside GLPI:

```text
plugins/nessusglpi
```

Then install and activate it from GLPI, or via the CLI:

```bash
php bin/console glpi:plugin:install --force --username=glpi --no-interaction nessusglpi
php bin/console glpi:plugin:activate --no-interaction nessusglpi
php bin/console cache:clear
```

> ⬆️ **Upgrading from an earlier version?** Open **Setup → Plugins** and click **Update** on *Nessus Conector* so the new background cron tasks are registered.

After installing, open your GLPI profile and enable the **Nessus Conector** rights.

---

## 🔑 Configuration

Go to **Plugins → Nessus Conector → Configuration** and fill in:

| Field | Example |
| --- | --- |
| API URL (Tenable Cloud) | `https://cloud.tenable.com` |
| API URL (local Nessus) | `https://nessus.example.local:8834` |
| Access key | your Tenable access key |
| Secret key | your Tenable secret key 🔐 *(stored encrypted)* |
| Timeout | `30` |
| Asset types for matching | Computer, Network equipment, Printer, Phone, Unmanaged |

Use the matching test button — **Test Nessus/VM connection** or **Test WAS connection** — to validate credentials before saving.

---

## 🖥️ Nessus / Tenable VM workflow

1. Go to **Plugins → Nessus Conector → Scans**.
2. Click **Browse Nessus / Tenable VM scans**.
3. Pick a scan and click **Use this scan** (the form is filled with the numeric scan ID).
4. Choose the severities to import and **save**.
5. The sync is queued and processed by the background worker. 🎉

> For VM scans, use the numeric `id` returned by `/scans`.

## 🌐 Tenable WAS workflow

1. Go to **Plugins → Nessus Conector → Scans**.
2. Click **Browse Tenable WAS scans**.
3. Select a WAS **configuration**, then a **scan execution**.
4. Click **Use this scan** (the form is filled with the WAS execution UUID).
5. Choose the severities to import and **save**.

> For WAS, use the scan **execution UUID**, not the configuration ID.

---

## 🔄 Synchronization & background worker

Synchronization is **queue-based**: creating or syncing a scan enqueues a job, and the job imports hosts and vulnerabilities into the plugin tables.

Two GLPI automatic actions (cron tasks) keep things running **without an open browser tab**:

| Task | Default frequency | What it does |
| --- | --- | --- |
| `queue` | every 5 minutes | Drains pending synchronization jobs (bounded per run). |
| `autosync` | daily | Re-queues active scans whose last sync is older than the task frequency. |

Manage them under **Setup → Automatic actions**. They run in GLPI's internal cron mode by default; for heavy or fully unattended use, switch them to **external** (system cron). The scan list page also still drains the queue live while it is open.

---

## ✅ Automatic ticket resolution

After every successful synchronization, the plugin checks the tickets it created:

- If a vulnerability is **no longer detected** on its asset (no current finding with the same identity), the linked ticket is moved to **Solved** with an explanatory follow-up.
- Resolution is **reversible** — the requester can reopen the ticket.
- A **parent** ticket is only resolved once **every** child finding has cleared.

---

## 🧩 Asset matching

Imported targets are matched to GLPI assets using:

- hostname
- FQDN
- IP address
- GLPI asset `name`

For Tenable WAS, the web application URL is reduced to a hostname/domain before matching.

---

## 👤 Profile rights

| Right | Purpose |
| --- | --- |
| `plugin_nessusglpi_scan` | View/create/update scans and run synchronization |
| `plugin_nessusglpi_config` | View/update API configuration and the activity log |
| `plugin_nessusglpi_vulnerability` | View vulnerabilities and imported hosts |
| `plugin_nessusglpi_ticket` | Ticket-link rights declared by the plugin |

> If permissions change while a user is logged in, log out and back in to refresh GLPI session rights.

---

## 🧪 Tests

Pure (database-free) ticket-content builders are covered by an automated suite.

```bash
# Zero-dependency runner (no PHPUnit needed)
php tests/run.php

# Or, in a dev environment with PHPUnit available
vendor/bin/phpunit -c phpunit.xml.dist
```

---

## ⚠️ Data retention notice

Do **not** uninstall the plugin if you want to keep imported data. Uninstalling drops the plugin tables (scans, hosts, vulnerabilities, sync history, ticket links, configuration and activity log) and removes its cron tasks. To temporarily disable it, use **deactivation** instead.

---

## 🧰 Useful CLI commands

```bash
php bin/console glpi:plugin:list
php bin/console glpi:plugin:install --force --username=glpi --no-interaction nessusglpi
php bin/console glpi:plugin:activate --no-interaction nessusglpi
php bin/console cache:clear

# Validate a PHP file
php -l plugins/nessusglpi/src/TenableWasClient.php
```

A detailed step-by-step technical guide is available in [`COMO_FUNCIONA.md`](COMO_FUNCIONA.md).

---

## 📅 Changelog

### v1.4.0
- 📊 New executive report (`front/report.php`) with full Tenable branding, Risk Index donut gauge, period selector (7/30/90 days) and all queries filtered by `first_seen_at`
- 🖥️ Top 10 most exposed hosts table with per-severity breakdown
- 🔬 Top 8 critical/high vulnerabilities across the fleet
- 📈 Vulnerability discovery trend chart (daily bars)
- 🎯 Risk Index: weighted score (critical×10 + high×3 + medium) relative to host count
- 🔘 "Executive Report" button added to the scan list page
- 🛠️ `overflow: hidden` applied on all chart containers to prevent label overflow

### v1.3.x
- ⚙️ Background sync worker (`queue` cron, every 5 min)
- ✅ Automatic ticket resolution when vulnerability clears
- 🔐 Encrypted API secrets with `GLPIKey`
- 📋 Activity / audit log viewer
- 🧪 Automated test suite

### v1.0.0
- 🚀 Initial dual-source release (Nessus VM + Tenable WAS)

---

## 🙏 Credits

This plugin stands on the work of the original authors — please keep crediting them:

- 🏁 **Original project:** [**magaiverpr**](https://github.com/magaiverpr/NessusConector) — the upstream *NessusConector* this work is forked from.
- 🧱 **Dual-source (VM + WAS) plugin author:** **Daniel Berton**.
- 🔧 **This fork** adds the executive report, background cron worker, secret encryption, automatic ticket resolution, the activity log and the test suite.

Upstream repository: <https://github.com/magaiverpr/NessusConector>

---

## 🤝 Contributing

Contributions are welcome via forks and pull requests:

1. Fork the repository.
2. Create a feature branch.
3. Commit focused changes.
4. Open a pull request with clear testing notes.

---

## 📄 License

Distributed under the **AGPL-3.0** license. See the repository license file for details.
