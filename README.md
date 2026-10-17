<div align="center">

<a href="https://github.com/urasec-labs">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:101820,45:243B53,100:00D4AA&height=220&section=header&text=FAEDRA&fontSize=72&fontColor=F4F7FA&fontAlignY=38&desc=Recon%20%2F%20Security%20Assessment%20Framework&descSize=17&descAlignY=60&animation=fadeIn" width="100%" alt="Faedra — Recon and Security Assessment Framework banner"/>
</a>

<br/>

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=500&size=17&duration=2800&pause=900&color=00D4AA&center=true&vCenter=true&width=700&lines=Map+the+surface.+Understand+the+risk.;A+modular+Python-based+security+assessment+toolkit.;Built+for+authorized+testing+and+learning." alt="Animated Faedra tagline"/>

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-24292F?style=for-the-badge&logo=linux&logoColor=white)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-00D4AA?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Project-Experimental-F0B429?style=for-the-badge)](#project-status)

**Faedra** is a modular Python toolkit for authorized reconnaissance and security assessment. It brings network scanning, web vulnerability checks, CVE lookups, risk prioritization, result storage, and PDF reporting into one CLI workflow.

[Features](#features) · [Architecture](#workflow) · [Installation](#installation) · [Usage](#usage) · [Safety](#responsible-use)

</div>

---

## Overview

Security findings are easier to act on when they are collected, organized, and explained in one place. Faedra aims to connect common assessment stages in a single command-line workflow, with results stored for later review and reports generated for documentation.

> **Project scope:** this is an experimental security assessment framework. Tool availability, target configuration, permissions, and individual module behavior can affect results. Always validate findings independently.

## Features

<table>
<tr>
<td width="50%" valign="top">

### Network reconnaissance
- Nmap integration for host, port, and service discovery
- Service and version information collection
- Scan options exposed through the CLI

</td>
<td width="50%" valign="top">

### Web checks and CVE context
- Optional Nikto and SQLMap integration
- CVE lookup through configured public APIs
- Cached lookup results where supported

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Risk and reporting
- Risk scoring with configurable thresholds
- PDF assessment report generation
- SQLite storage for scan history and findings

</td>
<td width="50%" valign="top">

### Operational visibility
- Console status output and logs
- Configurable safe-mode defaults
- Separate modules for scanning, risk, CVEs, storage, and reporting

</td>
</tr>
</table>

## Workflow

<div align="center">

```text
  TARGET
    │
    ▼
  RECONNAISSANCE ──► WEB CHECKS (optional)
    │                       │
    └───────────┬───────────┘
                ▼
          CVE ENRICHMENT
                │
                ▼
          RISK PRIORITIZATION
                │
                ▼
        SQLITE + PDF REPORT
```

</div>

### Project structure

```text
Faedra/
├── main.py                 # CLI entry point and workflow orchestration
├── faedra.sh               # Shell launcher
├── install.sh              # Setup helper
├── config.json             # Scan, risk, reporting, and logging settings
├── requirements.txt        # Python dependencies
├── modules/
│   ├── scanner.py          # Network scanning integration
│   ├── vuln_scanner.py     # Web vulnerability checks
│   ├── cve_lookup.py       # CVE information lookup
│   ├── risk_engine.py      # Risk prioritization
│   ├── exploit_engine.py   # Exploitation-related module
│   ├── database.py         # SQLite persistence
│   └── pdf_report.py       # PDF report generation
├── reports/                # Generated reports
├── logs/                   # Runtime logs
└── DISCLAIMER.md            # Legal and safety notes
```

## Installation

### 1. Get the project

```bash
git clone <YOUR_REPOSITORY_URL>
cd Faedra
```

Replace `<YOUR_REPOSITORY_URL>` with the actual repository URL. If you downloaded the source archive, extract it and enter the `Faedra` directory.

### 2. Install system tools

Faedra integrates with external security utilities. Install only the tools you intend to use and follow their official installation instructions. Depending on your chosen modules, this may include:

- Python 3.8 or newer
- Nmap
- Nikto (optional web checks)
- SQLMap (optional web checks)
- Metasploit Framework (optional; review the module's behavior before enabling it)

### 3. Create an isolated Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Check the CLI

```bash
python3 main.py --help
python3 main.py --version
```

If your copy includes the installation helper, review its contents before running it. Do not execute scripts from a repository you have not inspected.

## Usage

**Start with a system you own or a deliberately configured lab target.** `127.0.0.1` refers to your own machine.

```bash
# Basic assessment against your own local machine
python3 main.py --target 127.0.0.1
```

```bash
# Skip web checks
python3 main.py --target 127.0.0.1 --skip-web
```

```bash
# Skip the exploitation-related stage
python3 main.py --target 127.0.0.1 --skip-exploit
```

```bash
# Add an assessor label to generated output
python3 main.py --target 127.0.0.1 --tester-name "Local Lab"
```

View all available arguments:

```bash
python3 main.py --help
```

### CLI options

| Option | Purpose |
|---|---|
| `-t`, `--target` | Required target IP address or domain |
| `-n`, `--tester-name` | Assessor label used in output |
| `--skip-web` | Skip web vulnerability scanning |
| `--skip-exploit` | Skip the exploitation-related stage |
| `--no-safe-mode` | Disables safe mode; **not recommended** |
| `--version` | Print the application version |

Exact behavior depends on the current code and installed external tools. Review `config.json`, `DISCLAIMER.md`, and the relevant module before running an assessment.

## Configuration and outputs

`config.json` contains settings for scan behavior, CVE lookups, risk thresholds, reporting, database storage, and logging.

| Path | Purpose |
|---|---|
| `reports/` | Generated reports |
| `logs/` | Runtime logs |
| `database/` | SQLite data (created as needed) |
| `exploits/` | Exploit-related artifacts, if generated |

Treat reports, logs, and databases as sensitive: they may contain hostnames, IP addresses, service details, and vulnerability information. Store and share them only with authorized people.

## Responsible use

Faedra is intended for **authorized security testing, controlled labs, and education**.

- Test only systems you own or have explicit permission to assess.
- Confirm the written scope, permitted techniques, and testing window before starting.
- Start with non-invasive options and understand what each module does.
- Do not disable safe mode unless you understand the consequences and have explicit authorization.
- Validate findings manually; automated checks can produce false positives and false negatives.
- Follow applicable laws, program rules, and the repository's `DISCLAIMER.md`.

**You are responsible for your use of this software.** The presence of a feature does not imply permission to use it against a particular target.

## Project status

Faedra is provided as-is for learning and experimentation. It should not be treated as a certified scanner or a substitute for a professional security review. Before production use, add and run automated tests, review third-party tool invocation and input validation, and verify that safe-mode behavior is enforced consistently.

## Contributing

Contributions that improve reliability, documentation, test coverage, accessibility, and safe defaults are welcome.

1. Open an issue describing the problem or proposed improvement.
2. Keep changes focused and document any behavior changes.
3. Add tests where practical.
4. Never include real credentials, private targets, customer data, or sensitive scan results in issues or pull requests.

## License

This project includes a `LICENSE` file. Review it for the exact license terms before redistributing or modifying the project.

---

<div align="center">

**FAEDRA** · Reconnaissance with context. Findings with purpose.

<sub>Animated header and typing text are loaded from external services; GitHub may not render every animation in every context.</sub>

</div>
