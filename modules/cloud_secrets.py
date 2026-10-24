"""
Faedra Pro - Cloud & Secrets Automation
Author: Uras AKAS | urasakas.com

Capabilities:
- Gitleaks integration (if installed)
- High-signal regex based secret detection on discovered content
- Common cloud metadata / credential exposure patterns
- Safe-by-default: only analyzes content already obtained by previous modules
"""

from __future__ import annotations
import asyncio
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Tuple

import httpx

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity


SECRET_PATTERNS: List[Tuple[str, Pattern, Severity]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("AWS Secret Key", re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,20}?['\"][0-9a-zA-Z\/+]{40}['\"]"), Severity.CRITICAL),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), Severity.CRITICAL),
    ("GitHub Fine-grained", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), Severity.HIGH),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"), Severity.HIGH),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), Severity.CRITICAL),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), Severity.HIGH),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), Severity.MEDIUM),
    ("Password in URL", re.compile(r"[a-zA-Z]{3,10}://[^/\s:]+:[^/\s@]+@"), Severity.HIGH),
]

CLOUD_METADATA_PATHS = [
    "/latest/meta-data/",
    "/latest/user-data",
    "/metadata/v1/",
    "/computeMetadata/v1/",
]


class CloudSecretsModule(BaseModule):
    name = "cloud_secrets"
    description = "Cloud & Secrets Automation (Gitleaks + pattern detection)"
    version = "1.1.0"
    categories = ["secrets", "cloud"]
    is_active = True

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        assets: List[Asset] = context.get("assets", [])

        self.log("Starting secrets & cloud exposure analysis")

        await self._scan_collected_content(assets, result)
        await self._run_gitleaks(context, result)

        if self._looks_like_cloud_target(target, assets):
            await self._check_cloud_metadata(target, result)

        live_hosts = [a.value for a in assets if a.alive]
        if live_hosts and not self.safe_mode:
            await self._probe_secret_paths(live_hosts[:10], result)
        elif self.safe_mode:
            self.log("Safe mode ON — skipping active secret path probing", "warning")

        result.stats = {
            "secrets_found": len([f for f in result.findings if "secret" in f.tags or "credential" in f.tags]),
            "gitleaks_ran": result.raw.get("gitleaks_ran", False),
        }
        self.log(f"Secrets module finished — {result.stats['secrets_found']} potential secrets", "success")
        return result

    async def _scan_collected_content(self, assets: List[Asset], result: ModuleResult):
        texts_to_scan: List[Tuple[str, str]] = []
        for asset in assets:
            if asset.headers:
                header_blob = "\n".join(f"{k}: {v}" for k, v in asset.headers.items())
                texts_to_scan.append((asset.value, header_blob))
            if asset.metadata:
                texts_to_scan.append((asset.value, str(asset.metadata)))

        for source, text in texts_to_scan:
            self._apply_patterns(source, text, result)

    def _apply_patterns(self, source: str, text: str, result: ModuleResult):
        if not text:
            return
        for name, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                snippet = match.group(0)
                evidence = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 12 else snippet[:4] + "..."
                self.add_finding(result, Finding(
                    title=f"Potential {name} detected",
                    description=f"Pattern match for {name} near asset {source}",
                    severity=severity,
                    confidence=0.75,
                    module=self.name,
                    asset=source,
                    evidence=evidence,
                    tags=["secret", "credential", name.lower().replace(" ", "-")],
                ))

    async def _run_gitleaks(self, context: dict, result: ModuleResult):
        if not shutil.which("gitleaks"):
            self.log("gitleaks not found in PATH — skipping", "debug")
            result.raw["gitleaks_ran"] = False
            return

        local_paths = context.get("local_paths", [])
        if not local_paths:
            self.log("No local paths provided for gitleaks", "debug")
            result.raw["gitleaks_ran"] = False
            return

        result.raw["gitleaks_ran"] = True
        for path in local_paths[:3]:
            path = Path(path)
            if not path.exists():
                continue
            self.log(f"Running gitleaks on {path}")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "gitleaks", "detect", "--source", str(path), "--no-git", "-v",
                    "--report-format", "json", "--report-path", "/dev/stdout",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                if stdout:
                    import json
                    try:
                        data = json.loads(stdout.decode(errors="ignore") or "[]")
                        if isinstance(data, list):
                            for item in data[:50]:
                                self.add_finding(result, Finding(
                                    title=f"Gitleaks: {item.get('RuleID', 'secret')}",
                                    description=str(item.get("Match", ""))[:200],
                                    severity=Severity.HIGH,
                                    confidence=0.9,
                                    module=self.name,
                                    asset=item.get("File", str(path)),
                                    evidence=str(item.get("Secret", ""))[:20] + "...",
                                    tags=["secret", "gitleaks"],
                                    raw=item,
                                ))
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                result.errors.append(f"gitleaks: {e}")

    def _looks_like_cloud_target(self, target: str, assets: List[Asset]) -> bool:
        import re as _re
        if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return True
        for a in assets:
            techs = " ".join(a.technologies).lower()
            if any(x in techs for x in ("amazon", "aws", "google", "azure", "digitalocean")):
                return True
        return False

    async def _check_cloud_metadata(self, target: str, result: ModuleResult):
        self.log("Checking for exposed cloud metadata endpoints (conservative)")
        headers = {"User-Agent": self.config.scan.user_agent}
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False, headers=headers) as client:
            for path in CLOUD_METADATA_PATHS:
                url = f"http://{target}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        self.add_finding(result, Finding(
                            title="Possible cloud metadata service exposure",
                            description=f"{url} returned HTTP 200",
                            severity=Severity.HIGH,
                            confidence=0.6,
                            module=self.name,
                            asset=target,
                            evidence=url,
                            tags=["cloud", "metadata", "ssrf"],
                        ))
                except Exception:
                    continue

    async def _probe_secret_paths(self, hosts: List[str], result: ModuleResult):
        paths = [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/config.json",
            "/credentials.json",
            "/.git/config",
            "/.aws/credentials",
        ]
        headers = {"User-Agent": self.config.scan.user_agent}

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False, headers=headers) as client:
            for host in hosts:
                for path in paths:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{host}{path}"
                        try:
                            resp = await client.get(url)
                            if resp.status_code == 200 and len(resp.text) > 20:
                                self._apply_patterns(url, resp.text, result)
                                self.add_finding(result, Finding(
                                    title=f"Sensitive path accessible: {path}",
                                    description=f"{url} returned 200 with content",
                                    severity=Severity.HIGH,
                                    confidence=0.8,
                                    module=self.name,
                                    asset=host,
                                    evidence=url,
                                    tags=["secret", "exposure", "path"],
                                ))
                                break
                        except Exception:
                            continue
