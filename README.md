# Faedra

**Modular security assessment toolkit for authorized reconnaissance.**

[Features](#features) · [Demo](#demo) · [Architecture](#architecture) · [Installation](#installation) · [Usage](#usage) · [Configuration](#configuration) · [Responsible use](#responsible-use)

---

## Overview

Faedra connects common assessment stages into a single workflow: passive and active reconnaissance, asset inventory, web and API checks, secrets detection, prioritization, and reporting.

Results are stored as structured data and exported to **HTML**, **PDF**, and **JSON**. An interactive CLI menu is available for day-to-day use; subcommands remain available for scripting.

> **Project scope**  
> This is an experimental security assessment framework. Tool availability, target configuration, permissions, and individual module behavior can affect results. Always validate findings independently.

**Author:** [Uras AKAS](https://urasakas.com) · **Lab:** [urasec-labs](https://github.com/urasec-labs)

---

## Demo

![Faedra Demo](docs/faedra_intro.gif)

[🎬 Tanıtım Videosunu Orijinal Kalitede İzle / İndir](docs/faedra_intro.mp4)

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
