"""
Faedra Pro - Container & Config Automation
Author: Uras AKAS | urasakas.com

Capabilities:
- Deep security header analysis
- Common web server misconfiguration patterns
- Exposed container / orchestration endpoints (Docker, Kubernetes)
- robots.txt / security.txt review
- Information disclosure via server banners & error pages
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set

import httpx

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity
from utils.tools import is_available


SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.MEDIUM,
        "desc": "HSTS missing — browsers will not enforce HTTPS",
    },
    "content-security-policy": {
        "severity": Severity.MEDIUM,
        "desc": "CSP missing — increases XSS impact",
    },
    "x-content-type-options": {
        "severity": Severity.LOW,
        "desc": "X-Content-Type-Options missing (nosniff recommended)",
    },
    "x-frame-options": {
        "severity": Severity.LOW,
        "desc": "X-Frame-Options missing — clickjacking risk",
    },
    "referrer-policy": {
        "severity": Severity.INFO,
        "desc": "Referrer-Policy not set",
    },
    "permissions-policy": {
        "severity": Severity.INFO,
        "desc": "Permissions-Policy not set",
    },
    "x-xss-protection": {
        "severity": Severity.INFO,
        "desc": "X-XSS-Protection legacy header absent (modern browsers rely on CSP)",
    },
}

CONTAINER_PATHS = [
    # Docker
    "/version",
    "/v1.24/version",
    "/v1.41/version",
    "/containers/json",
    "/images/json",
    # Kubernetes
    "/api",
    "/api/v1",
    "/apis",
    "/healthz",
    "/livez",
    "/readyz",
    "/version",
    # Generic debug / actuator
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/info",
    "/server-status",
    "/server-info",
    "/.git/HEAD",
    "/debug",
    "/debug/pprof/",
    "/metrics",
    "/prometheus",
]


class ContainerConfigModule(BaseModule):
    name = "container_config"
    description = "Container & Config Automation (headers, misconfig, nikto, exposure)"
    version = "1.2.0"
    categories = ["config", "container"]
    is_active = True

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        assets: List[Asset] = context.get("assets", [])

        hosts: Set[str] = set([target])
        for a in assets:
            if a.alive and a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                hosts.add(a.value)

        self.log(f"Config & exposure analysis on {len(hosts)} hosts")

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": self.config.scan.user_agent},
        ) as client:
            for host in list(hosts)[:12]:
                await self._analyze_host(client, host, result)

        # Nikto on primary target (if available, and not in ultra-safe silence)
        if not self.safe_mode and is_available("nikto"):
            await self._run_nikto(target, result)
        elif not is_available("nikto"):
            self.log("nikto not installed — skip", "debug")

        result.stats = {
            "hosts_checked": min(len(hosts), 12),
            "header_issues": len([f for f in result.findings if "header" in f.tags]),
            "exposure_findings": len([f for f in result.findings if "exposure" in f.tags]),
            "nikto": result.raw.get("nikto_ran", False),
        }
        self.log(
            f"Config module finished — header_issues={result.stats['header_issues']} "
            f"exposures={result.stats['exposure_findings']}",
            "success",
        )
        return result

    async def _analyze_host(self, client: httpx.AsyncClient, host: str, result: ModuleResult):
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}"
            try:
                resp = await client.get(base)
            except Exception:
                continue

            headers = {k.lower(): v for k, v in resp.headers.items()}

            # 1. Security headers
            self._check_security_headers(host, headers, result)

            # 2. Server banner / tech disclosure
            self._check_banner(host, headers, result)

            # 3. robots.txt & security.txt
            await self._check_policy_files(client, base, host, result)

            # 4. Container / orchestration / debug endpoints
            if not self.safe_mode:
                await self._check_exposure_paths(client, base, host, result)
            else:
                self.log("Safe mode ON — skipping active exposure path checks", "debug")

            return

    def _check_security_headers(self, host: str, headers: Dict[str, str], result: ModuleResult):
        missing = []
        for header, meta in SECURITY_HEADERS.items():
            if header not in headers:
                missing.append(header)
                self.add_finding(result, Finding(
                    title=f"Missing security header: {header}",
                    description=meta["desc"],
                    severity=meta["severity"],
                    confidence=0.9,
                    module=self.name,
                    asset=host,
                    evidence=header,
                    tags=["header", "misconfig", "security"],
                ))

        # HSTS specifically on HTTP is less relevant; we already grade it
        if missing:
            result.raw.setdefault("missing_headers", {})[host] = missing

    def _check_banner(self, host: str, headers: Dict[str, str], result: ModuleResult):
        server = headers.get("server")
        powered = headers.get("x-powered-by")
        via = headers.get("via")

        disclosures = []
        if server:
            disclosures.append(f"Server: {server}")
        if powered:
            disclosures.append(f"X-Powered-By: {powered}")
        if via:
            disclosures.append(f"Via: {via}")

        if disclosures:
            # Version numbers increase risk slightly
            severity = Severity.INFO
            joined = " | ".join(disclosures)
            if any(c.isdigit() for c in joined):
                severity = Severity.LOW

            self.add_finding(result, Finding(
                title="Server technology disclosure",
                description=joined,
                severity=severity,
                confidence=0.85,
                module=self.name,
                asset=host,
                evidence=joined,
                tags=["fingerprint", "banner", "misconfig"],
            ))

    async def _check_policy_files(self, client: httpx.AsyncClient, base: str, host: str, result: ModuleResult):
        # robots.txt
        try:
            r = await client.get(f"{base}/robots.txt")
            if r.status_code == 200 and "user-agent" in r.text.lower():
                # Look for interesting disallows
                interesting = []
                for line in r.text.splitlines():
                    line_l = line.lower().strip()
                    if line_l.startswith("disallow:") and any(
                        x in line_l for x in ("admin", "backup", "api", "internal", "debug", "config", ".git")
                    ):
                        interesting.append(line.strip())
                if interesting:
                    self.add_finding(result, Finding(
                        title="robots.txt discloses sensitive paths",
                        description="; ".join(interesting[:6]),
                        severity=Severity.LOW,
                        confidence=0.8,
                        module=self.name,
                        asset=host,
                        evidence=f"{base}/robots.txt",
                        tags=["robots", "disclosure"],
                    ))
        except Exception:
            pass

        # security.txt
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                r = await client.get(f"{base}{path}")
                if r.status_code == 200 and ("contact:" in r.text.lower() or "expires:" in r.text.lower()):
                    self.add_finding(result, Finding(
                        title="security.txt present",
                        description="Security contact policy file found (good practice)",
                        severity=Severity.INFO,
                        confidence=0.9,
                        module=self.name,
                        asset=host,
                        evidence=f"{base}{path}",
                        tags=["security-txt"],
                    ))
                    break
            except Exception:
                continue

    async def _check_exposure_paths(self, client: httpx.AsyncClient, base: str, host: str, result: ModuleResult):
        for path in CONTAINER_PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                body = resp.text[:3000].lower()
                ct = resp.headers.get("content-type", "").lower()

                # Docker
                if "docker" in body or ("apiVersion" in resp.text and "minAPIVersion" in resp.text):
                    self.add_finding(result, Finding(
                        title="Possible Docker API exposure",
                        description=f"{url} returned data consistent with Docker API",
                        severity=Severity.CRITICAL,
                        confidence=0.7,
                        module=self.name,
                        asset=host,
                        evidence=url,
                        tags=["exposure", "docker", "container"],
                    ))
                    continue

                # Kubernetes
                if "kubernetes" in body or ("kind" in body and "apiVersion" in body and "selfLink" in body):
                    self.add_finding(result, Finding(
                        title="Possible Kubernetes API exposure",
                        description=f"{url} returned data consistent with Kubernetes API",
                        severity=Severity.CRITICAL,
                        confidence=0.7,
                        module=self.name,
                        asset=host,
                        evidence=url,
                        tags=["exposure", "kubernetes", "container"],
                    ))
                    continue

                # Spring Actuator / metrics
                if path.startswith("/actuator") and ("status" in body or "components" in body or "env" in body):
                    sev = Severity.HIGH if "env" in path else Severity.MEDIUM
                    self.add_finding(result, Finding(
                        title=f"Actuator endpoint exposed: {path}",
                        description="Spring Boot Actuator (or similar) appears accessible",
                        severity=sev,
                        confidence=0.75,
                        module=self.name,
                        asset=host,
                        evidence=url,
                        tags=["exposure", "actuator", "misconfig"],
                    ))
                    continue

                # .git
                if path == "/.git/HEAD" and "ref:" in body:
                    self.add_finding(result, Finding(
                        title="Git repository metadata exposed",
                        description=f"{url} leaks .git/HEAD",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        module=self.name,
                        asset=host,
                        evidence=url,
                        tags=["exposure", "git", "source"],
                    ))
                    continue

                # Generic metrics
                if path in ("/metrics", "/prometheus") and (
                    "http_" in body or "# HELP" in resp.text or "process_" in body
                ):
                    self.add_finding(result, Finding(
                        title="Metrics endpoint exposed",
                        description=f"{url} appears to expose internal metrics",
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        module=self.name,
                        asset=host,
                        evidence=url,
                        tags=["exposure", "metrics"],
                    ))
            except Exception:
                continue
