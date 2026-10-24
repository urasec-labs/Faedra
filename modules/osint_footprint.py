"""
Faedra Pro - OSINT & Footprint Module
Author: Uras AKAS | urasakas.com

- WAF/CDN detection (built-in + wafw00f)
- Security headers
- Technology fingerprint (headers + whatweb if available)
"""

from __future__ import annotations
import asyncio
from typing import Dict, List, Optional, Set

import httpx

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity
from utils.tools import is_available


WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare"],
    "akamai": ["akamai", "x-akamai"],
    "aws-waf": ["x-amzn-requestid", "awselb"],
    "sucuri": ["sucuri", "x-sucuri"],
    "incapsula": ["incap_ses", "visid_incap", "incapsula"],
    "modsecurity": ["mod_security", "modsecurity"],
    "f5-bigip": ["bigipserver", "f5"],
}


class OSINTFootprintModule(BaseModule):
    name = "osint_footprint"
    description = "OSINT & Footprint (WAF, CDN, headers, whatweb, wafw00f)"
    version = "1.2.0"
    categories = ["recon", "osint"]
    is_active = True

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        assets: List[Asset] = context.get("assets", [])

        hosts: Set[str] = set([target])
        for a in assets:
            if a.alive and a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                hosts.add(a.value)

        host_list = list(hosts)[:25]
        self.log(f"Fingerprinting {len(host_list)} hosts...")

        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=True,
            headers={"User-Agent": self.config.scan.user_agent},
        ) as client:
            for host in host_list:
                await self._analyze_host(client, host, result)

        # External tools
        await self._run_wafw00f(host_list[:10], result)
        await self._run_whatweb(host_list[:8], result)

        result.stats = {"hosts_analyzed": len(host_list)}
        self.log("OSINT footprint complete", "success")
        return result

    async def _analyze_host(self, client: httpx.AsyncClient, host: str, result: ModuleResult):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                resp = await client.get(url)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                detected = self._detect_waf(headers, resp.text)
                if detected:
                    self.add_finding(result, Finding(
                        title=f"WAF/CDN detected: {detected}",
                        description=f"{host} appears behind {detected}",
                        severity=Severity.INFO, module=self.name, asset=host,
                        tags=["waf", "cdn", detected],
                    ))

                missing = self._check_security_headers(headers)
                if missing:
                    self.add_finding(result, Finding(
                        title="Missing security headers",
                        description=f"Missing: {', '.join(missing)}",
                        severity=Severity.LOW if len(missing) < 3 else Severity.MEDIUM,
                        module=self.name, asset=host, evidence=", ".join(missing),
                        tags=["headers", "security"],
                    ))

                server = headers.get("server")
                powered = headers.get("x-powered-by")
                if server or powered:
                    tech = []
                    if server:
                        tech.append(f"Server: {server}")
                    if powered:
                        tech.append(f"X-Powered-By: {powered}")
                    self.add_finding(result, Finding(
                        title="Technology disclosure via headers",
                        description="; ".join(tech),
                        severity=Severity.INFO, module=self.name, asset=host,
                        tags=["fingerprint", "headers"],
                    ))
                return
            except Exception:
                continue

    def _detect_waf(self, headers: Dict[str, str], body: str) -> Optional[str]:
        combined = " ".join(headers.keys()) + " " + " ".join(headers.values()) + " " + body[:2000]
        combined = combined.lower()
        for name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    return name
        return None

    def _check_security_headers(self, headers: Dict[str, str]) -> List[str]:
        recommended = [
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy",
        ]
        return [h for h in recommended if h not in headers]

    async def _run_wafw00f(self, hosts: List[str], result: ModuleResult):
        if not is_available("wafw00f"):
            self.log("wafw00f not installed — skip", "debug")
            return
        self.log(f"Running wafw00f on {len(hosts)} hosts...")
        for host in hosts:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "wafw00f", url, "-a",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                    text = stdout.decode(errors="ignore")
                    if "is behind" in text or "WAF" in text:
                        # Extract WAF name roughly
                        waf_name = "unknown"
                        for line in text.splitlines():
                            if "is behind" in line:
                                parts = line.split("is behind")
                                if len(parts) > 1:
                                    waf_name = parts[1].strip().strip(".")
                                    break
                        self.add_finding(result, Finding(
                            title=f"wafw00f: {waf_name}",
                            description=f"WAF detected on {url}",
                            severity=Severity.INFO, confidence=0.85,
                            module=self.name, asset=host, evidence=url,
                            tags=["waf", "wafw00f"],
                        ))
                        break
                except Exception:
                    continue

    async def _run_whatweb(self, hosts: List[str], result: ModuleResult):
        if not is_available("whatweb"):
            self.log("whatweb not installed — skip", "debug")
            return
        self.log(f"Running whatweb on {len(hosts)} hosts...")
        for host in hosts:
            url = f"https://{host}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "whatweb", url, "--color=never", "-a", "1",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
                text = stdout.decode(errors="ignore").strip()
                if text and host in text:
                    self.add_finding(result, Finding(
                        title="whatweb technology fingerprint",
                        description=text[:300],
                        severity=Severity.INFO, confidence=0.8,
                        module=self.name, asset=host, evidence=url,
                        tags=["fingerprint", "whatweb"],
                    ))
            except Exception:
                continue
