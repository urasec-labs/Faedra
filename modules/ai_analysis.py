"""
Faedra Pro - Smart Prioritization & AI Analysis Module
Author: Uras AKAS | urasakas.com

Performs rule-based prioritization of findings.
Optional LLM summarization if an API key is configured.
"""

from __future__ import annotations
from typing import List, Optional

from core.plugin_base import BaseModule
from core.models import ModuleResult, Finding, Severity, PrioritizedFinding


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 70,
    Severity.MEDIUM: 40,
    Severity.LOW: 15,
    Severity.INFO: 5,
    Severity.UNKNOWN: 10,
}


class AIAnalysisModule(BaseModule):
    name = "ai_analysis"
    description = "Smart Prioritization & AI Analysis"
    version = "1.0.0"
    categories = ["analysis"]
    is_active = False

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        findings: List[Finding] = context.get("findings", [])

        if not findings:
            self.log("No findings to analyze")
            return result

        self.log(f"Prioritizing {len(findings)} findings...")

        prioritized = []
        for f in findings:
            score = SEVERITY_WEIGHT.get(f.severity, 10)
            reasons = [f"Base severity: {f.severity.value}"]

            # Boosters
            if f.cve:
                score += 25
                reasons.append("Has CVE")
            if "rce" in (f.title + f.description).lower() or "remote code" in f.description.lower():
                score += 30
                reasons.append("Possible RCE indicator")
            if any(t in f.tags for t in ("exposure", "secret", "credential")):
                score += 20
                reasons.append("Sensitive data exposure tag")
            if f.confidence >= 0.85:
                score += 10
                reasons.append("High confidence")

            actions = self._suggest_actions(f)

            prioritized.append(PrioritizedFinding(
                finding=f,
                priority_score=score,
                reasons=reasons,
                suggested_actions=actions,
            ))

        prioritized.sort(key=lambda x: x.priority_score, reverse=True)

        # Store top findings back as enriched findings
        for p in prioritized[:15]:
            enriched = p.finding.model_copy()
            enriched.tags = list(set(enriched.tags + ["prioritized"]))
            enriched.raw["priority_score"] = p.priority_score
            enriched.raw["reasons"] = p.reasons
            enriched.raw["suggested_actions"] = p.suggested_actions
            self.add_finding(result, enriched)

        result.stats = {
            "total_analyzed": len(findings),
            "top_score": prioritized[0].priority_score if prioritized else 0,
        }
        result.raw["prioritized"] = [p.model_dump() for p in prioritized[:20]]

        self.log(f"Analysis complete — top score {result.stats['top_score']}", "success")
        return result

    def _suggest_actions(self, f: Finding) -> List[str]:
        actions = []
        title_desc = (f.title + " " + f.description).lower()

        if "header" in title_desc:
            actions.append("Review and implement missing security headers")
        if "waf" in title_desc or "cdn" in title_desc:
            actions.append("Confirm WAF rules and monitoring coverage")
        if "port" in title_desc or "service" in title_desc:
            actions.append("Validate if the service should be publicly exposed")
            actions.append("Ensure latest patches are applied")
        if "secret" in title_desc or "key" in title_desc or "credential" in title_desc:
            actions.append("Rotate exposed credentials immediately")
            actions.append("Search for similar leaks in repositories")
        if not actions:
            actions.append("Triage manually and decide on remediation priority")

        return actions
