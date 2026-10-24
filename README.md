# Faedra

**Modular security assessment toolkit for authorized reconnaissance.**

[Features](#features) · [Architecture](#architecture) · [Installation](#installation) · [Usage](#usage) · [Configuration](#configuration) · [Responsible use](#responsible-use)

---

## Overview

Faedra connects common assessment stages into a single workflow: passive and active reconnaissance, asset inventory, web and API checks, secrets detection, prioritization, and reporting.

Results are stored as structured data and exported to **HTML**, **PDF**, and **JSON**. An interactive CLI menu is available for day-to-day use; subcommands remain available for scripting.

> **Project scope**  
> This is an experimental security assessment framework. Tool availability, target configuration, permissions, and individual module behavior can affect results. Always validate findings independently.

**Author:** [Uras AKAS](https://urasakas.com) · **Lab:** [urasec-labs](https://github.com/urasec-labs)

---

## Demo

<video src="docs/faedra_intro.mp4" controls width="100%"></video>

---
## Features

| Area | Capabilities |
|------|----------------|
| **Passive recon** | DNS, Certificate Transparency (crt.sh), HackerTarget, AlienVault OTX, Wayback CDX, WHOIS; optional **subfinder** / **amass** |
| **Asset inventory** | Persistent tracking of discovered assets with new / disappeared detection |
| **Bug bounty pipeline** | Live host probing (**httpx**), light path discovery, optional **ffuf** and **nuclei** |
| **OSINT & footprint** | WAF/CDN hints, security headers, tech disclosure; optional **wafw00f** / **whatweb** |
| **Pentest** | Controlled **nmap** scanning; optional **naabu** fallback |
| **Cloud & secrets** | High-signal secret patterns, optional **gitleaks**, sensitive path checks |
| **API security** | OpenAPI/Swagger discovery, GraphQL + introspection checks |
| **Auth & session** | Login form discovery, cookie flag analysis |
| **Container & config** | Header/misconfig checks, exposure paths; optional **nikto** |
| **Analysis** | Severity-based prioritization, OWASP-oriented mapping |
| **Reporting** | HTML + PDF + JSON reports; local web dashboard |
| **Operations** | Safe mode by default, interactive menu, profile presets, stealth helpers |

---

## Architecture

```
                    TARGET
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
   PASSIVE RECON            STEALTH / CONFIG
   (CT, OTX, subfinder…)           │
          │                       │
          └───────────┬───────────┘
                      ▼
              ASSET INVENTORY
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   BUG BOUNTY    OSINT/WAF     PENTEST (nmap)
   (httpx/ffuf/  (headers/     API / AUTH
    nuclei)       wafw00f)     SECRETS / CONFIG
        │             │             │
        └─────────────┴─────────────┘
                      ▼
            PRIORITIZATION + COMPLIANCE
                      │
                      ▼
              HTML / PDF / JSON
                 + DASHBOARD
```

### Project structure

```
Faedra-Pro/
├── faedra.py                 # CLI entry (interactive menu + subcommands)
├── dashboard.py              # Local report dashboard
├── config/default.yaml       # Profiles, scan, stealth, notifications
├── requirements.txt
├── core/
│   ├── orchestrator.py       # Module runner and job aggregation
│   ├── models.py             # Asset, Finding, ScanJob schemas
│   ├── plugin_base.py        # Module interface
│   ├── config.py             # Config loader
│   └── report.py             # HTML + PDF generators
├── modules/                  # Built-in analysis modules
├── utils/                    # HTTP helpers, external tool detection
├── data/
│   ├── assets/               # Persistent inventories
│   ├── reports/              # Generated reports
│   └── logs/
├── DISCLAIMER.md
└── LICENSE
```

---

## Installation

### 1. Get the project

```bash
git clone https://github.com/urasec-labs/Faedra
cd Faedra
```

If you use a source archive, extract it and enter the project directory.

### 2. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

Requires **Python 3.10+** (3.12 tested).

### 3. Optional external tools

Faedra runs without them; missing tools are skipped. Install only what you need:

| Tool | Role |
|------|------|
| nmap | Port / service scan |
| naabu | Port scan fallback |
| subfinder / amass | Subdomain enumeration |
| httpx (ProjectDiscovery) | HTTP probing |
| ffuf | Directory discovery |
| nuclei | Template-based checks |
| gitleaks | Secrets scanning |
| wafw00f / whatweb | WAF / tech fingerprint |
| nikto | Web misconfiguration scan |

Check what is available:

```bash
python faedra.py tools
```

---

## Usage

**Only test systems you own or have explicit authorization to assess.**

### Interactive menu (recommended)

```bash
python faedra.py
```

```
Ana Menü

1  Hızlı Recon          (quick)
2  Bug Bounty Tarama    (bugbounty)
3  Derin Analiz         (deep)
4  Sürekli İzleme       (monitor)
5  Modülleri Listele
6  Dış Araç Durumu
7  Web Dashboard
8  Özel Modül Seçimi
0  Çıkış
```

### Command-line mode

```bash
# Quick passive + light footprint
python faedra.py recon example.com

# Bug bounty oriented pipeline
python faedra.py full example.com --profile bugbounty

# Deep assessment (authorized targets only)
python faedra.py full example.com --profile deep --no-safe

# List modules / tools
python faedra.py modules
python faedra.py tools

# Local dashboard for reports
python faedra.py dashboard
# → http://127.0.0.1:8787
```

### Profiles

| Profile | Intent |
|---------|--------|
| `quick` | Passive recon + inventory + footprint |
| `bugbounty` | Full recon, live hosts, API, secrets, config |
| `deep` | Includes controlled port scanning |
| `monitor` | Periodic inventory / change detection |

Safe mode is **enabled by default**. Aggressive steps (full ffuf, nikto, broad port scans) stay limited until you explicitly disable it with authorization.

---

## Configuration

Primary config: `config/default.yaml`

| Section | Purpose |
|---------|---------|
| `app.safe_mode` | Global safe-mode default |
| `scan` | Timeouts, concurrency, user-agent |
| `profiles` | Module lists per profile |
| `stealth` | UA rotation, rate limit, proxy |
| `notification` | Discord / webhook hooks |
| `apis` | Optional API keys (Shodan, Censys, …) |
| `paths` | assets / reports / logs / db locations |

### Outputs

| Path | Content |
|------|---------|
| `data/reports/` | HTML, PDF, JSON reports |
| `data/assets/` | Persistent asset inventories |
| `data/logs/` | Runtime logs |

Treat reports and inventories as sensitive. They may contain hostnames, paths, and vulnerability details.

---

## Responsible use

Faedra is intended for **authorized security testing, controlled labs, and education**.

- Test only systems you own or have **explicit written permission** to assess.
- Confirm scope, permitted techniques, and testing window before starting.
- Prefer non-invasive options first; understand each module before enabling aggressive modes.
- Do not disable safe mode unless you understand the impact and are authorized.
- Validate findings manually — automation produces false positives and false negatives.
- Follow applicable laws, program rules, and [`DISCLAIMER.md`](DISCLAIMER.md).

**You are responsible for your use of this software.** The presence of a feature does not imply permission to use it against a given target.

---

## Project status

Faedra is provided as-is for learning, lab work, and authorized assessments. It is not a certified scanner and is not a substitute for a professional security review.

Before any production-facing use: review third-party tool invocations, confirm safe-mode enforcement, and validate results on known targets.

---

## Contributing

Improvements to reliability, documentation, tests, and safe defaults are welcome.

1. Open an issue describing the problem or proposal.
2. Keep changes focused; document behavior changes.
3. Add tests where practical.
4. Never include real credentials, private targets, or sensitive scan output in issues or PRs.

---

## License

See [`LICENSE`](LICENSE) for terms (MIT). Review it before redistribution or modification.

---

**FAEDRA** · Reconnaissance with context. Findings with purpose.

[urasakas.com](https://urasakas.com) · [urasec-labs](https://github.com/urasec-labs)
