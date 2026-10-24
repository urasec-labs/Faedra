FaedraModular security assessment toolkit for authorized reconnaissance.Features · Demo · Architecture · Installation · Usage · Configuration · Responsible useOverviewFaedra connects common assessment stages into a single workflow: passive and active reconnaissance, asset inventory, web and API checks, secrets detection, prioritization, and reporting.Results are stored as structured data and exported to HTML, PDF, and JSON. An interactive CLI menu is available for day-to-day use; subcommands remain available for scripting.Project scopeThis is an experimental security assessment framework. Tool availability, target configuration, permissions, and individual module behavior can affect results. Always validate findings independently.Author: Uras AKAS · Lab: urasec-labsDemo🎬 Tanıtım Videosunu Orijinal Kalitede İzle / İndirFeaturesAreaCapabilitiesPassive reconDNS, Certificate Transparency (crt.sh), HackerTarget, AlienVault OTX, Wayback CDX, WHOIS; optional subfinder / amassAsset inventoryPersistent tracking of discovered assets with new / disappeared detectionBug bounty pipelineLive host probing (httpx), light path discovery, optional ffuf and nucleiOSINT & footprintWAF/CDN hints, security headers, tech disclosure; optional wafw00f / whatwebPentestControlled nmap scanning; optional naabu fallbackCloud & secretsHigh-signal secret patterns, optional gitleaks, sensitive path checksAPI securityOpenAPI/Swagger discovery, GraphQL + introspection checksAuth & sessionLogin form discovery, cookie flag analysisContainer & configHeader/misconfig checks, exposure paths; optional niktoAnalysisSeverity-based prioritization, OWASP-oriented mappingReportingHTML + PDF + JSON reports; local web dashboardOperationsSafe mode by default, interactive menu, profile presets, stealth helpersArchitecture                    TARGET
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
   PASSIVE RECON           STEALTH / CONFIG
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
Project structureFaedra-Pro/
├── faedra.py               # CLI entry (interactive menu + subcommands)
├── dashboard.py            # Local report dashboard
├── config/default.yaml     # Profiles, scan, stealth, notifications
├── requirements.txt
├── core/
│   ├── orchestrator.py     # Module runner and job aggregation
│   ├── models.py           # Asset, Finding, ScanJob schemas
│   ├── plugin_base.py      # Module interface
│   ├── config.py           # Config loader
│   └── report.py           # HTML + PDF generators
├── modules/                # Built-in analysis modules
├── utils/                  # HTTP helpers, external tool detection
├── data/
│   ├── assets/             # Persistent inventories
│   ├── reports/            # Generated reports
│   └── logs/
├── docs/
│   ├── faedra_intro.mp4    # Demo video
│   └── faedra_intro.gif    # Animated preview
├── DISCLAIMER.md
└── LICENSE
Installation1. Get the projectgit clone https://github.com/urasec-labs/Faedra
cd Faedra
If you use a source archive, extract it and enter the project directory.2. Python environmentpython3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
Requires Python 3.10+ (3.12 tested).3. Optional external toolsFaedra runs without them; missing tools are skipped. Install only what you need:ToolRolenmapPort / service scannaabuPort scan fallbacksubfinder / amassSubdomain enumerationhttpx (ProjectDiscovery)HTTP probingffufDirectory discoverynucleiTemplate-based checksgitleaksSecrets scanningwafw00f / whatwebWAF / tech fingerprintniktoWeb misconfiguration scanCheck what is available:python faedra.py tools
UsageOnly test systems you own or have explicit authorization to assess.Interactive menu (recommended)python faedra.py
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
Command-line mode# Quick passive + light footprint
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
ProfilesProfileIntentquickPassive recon + inventory + footprintbugbountyFull recon, live hosts, API, secrets, configdeepIncludes controlled port scanningmonitorPeriodic inventory / change detectionSafe mode is enabled by default. Aggressive steps (full ffuf, nikto, broad port scans) stay limited until you explicitly disable it with authorization.ConfigurationPrimary config: config/default.yamlSectionPurposeapp.safe_modeGlobal safe-mode defaultscanTimeouts, concurrency, user-agentprofilesModule lists per profilestealthUA rotation, rate limit, proxynotificationDiscord / webhook hooksapisOptional API keys (Shodan, Censys, …)pathsassets / reports / logs / db locationsOutputsPathContentdata/reports/HTML, PDF, JSON reportsdata/assets/Persistent asset inventoriesdata/logs/Runtime logsTreat reports and inventories as sensitive. They may contain hostnames, paths, and vulnerability details.Responsible useFaedra is intended for authorized security testing, controlled labs, and education.Test only systems you own or have explicit written permission to assess.Confirm scope, permitted techniques, and testing window before starting.Prefer non-invasive options first; understand each module before enabling aggressive modes.Do not disable safe mode unless you understand the impact and are authorized.Validate findings manually — automation produces false positives and false negatives.Follow applicable laws, program rules, and DISCLAIMER.md.You are responsible for your use of this software. The presence of a feature does not imply permission to use it against a given target.Project statusFaedra is provided as-is for learning, lab work, and authorized assessments. It is not a certified scanner and is not a substitute for a professional security review.Before any production-facing use: review third-party tool invocations, confirm safe-mode enforcement, and validate results on known targets.ContributingImprovements to reliability, documentation, tests, and safe defaults are welcome.Open an issue describing the problem or proposal.Keep changes focused; document behavior changes.Add tests where practical.Never include real credentials, private targets, or sensitive scan output in issues or PRs.LicenseSee LICENSE for terms (MIT). Review it before redistribution or modification.FAEDRA · Reconnaissance with context. Findings with purpose.urasakas.com · urasec-labs
