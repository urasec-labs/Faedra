"""
Faedra Pro - Compliance Mapping Module
Author: Uras AKAS | urasakas.com

Maps findings to high-level control frameworks (simplified).
"""

from __future__ import annotations
from typing import List, Optional, Dict

from core.plugin_base import BaseModule
from core.models import ModuleResult, Finding, Severity


# Simplified mapping keywords → controls
OWASP_MAP = {
    "injection": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "broken access": "A01:2021 – Broken Access Control",
    "auth": "A07:2021 – Identification and Authentication Failures",
    "header": "A05:2021 – Security Misconfiguration",
    "misconfig": "A05:2021 – Security Misconfiguration",
    "sensitive": "A02:2021 – Cryptographic Failures",
    "secret": "A02:2021 – Cryptographic Failures",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
}


class ComplianceModule(BaseModule):
    name = "compliance"
    description = "Compliance Mapping (OWASP focused)"
    version = "1.0.0"
    categories = ["analysis", "compliance"]
    is_active = False

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        findings: List[Finding] = context.get("findings", [])

        mapped = 0
        for f in findings:
            controls = self._map_finding(f)
            if controls:
                mapped += 1
                enriched = f.model_copy()
                enriched.tags = list(set(enriched.tags + ["compliance"]))
                enriched.raw["compliance_controls"] = controls
                self.add_finding(result, enriched)

        result.stats = {"findings_mapped": mapped}
        self.log(f"Mapped {mapped} findings to compliance controls", "success")
        return result

    def _map_finding(self, f: Finding) -> List[str]:
        text = (f.title + " " + f.description + " " + " ".join(f.tags)).lower()
        hits = []
        for keyword, control in OWASP_MAP.items():
            if keyword in text:
                hits.append(control)
        return list(set(hits))
