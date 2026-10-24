"""
Faedra Pro - External tool detection helpers
Author: Uras AKAS | urasakas.com
"""

from __future__ import annotations
import shutil
from typing import Dict, Optional


TOOLS = {
    "nmap": "Network port scanner",
    "nuclei": "Template-based vulnerability scanner",
    "gitleaks": "Secrets scanner",
    "ffuf": "Web fuzzer / directory discovery",
    "subfinder": "Passive subdomain enumeration",
    "amass": "In-depth subdomain enumeration",
    "httpx": "HTTP probe (ProjectDiscovery)",
    "wafw00f": "WAF fingerprinting",
    "nikto": "Web server scanner",
    "whatweb": "Web technology identifier",
    "naabu": "Port scanner (ProjectDiscovery)",
}


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def is_available(name: str) -> bool:
    return which(name) is not None


def detect_all() -> Dict[str, bool]:
    return {name: is_available(name) for name in TOOLS}


def status_table() -> str:
    lines = []
    for name, desc in TOOLS.items():
        ok = is_available(name)
        mark = "OK" if ok else "—"
        lines.append(f"  [{mark}] {name:12} {desc}")
    return "\n".join(lines)
