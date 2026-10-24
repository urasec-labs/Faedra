"""
Faedra Pro - Bug Bounty Automation
Author: Uras AKAS | urasakas.com

- Live host checking (httpx binary or python httpx)
- Light path discovery + optional ffuf
- Nuclei integration
"""

from __future__ import annotations
import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Set

import httpx

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity
from utils.tools import is_available


class BugBountyModule(BaseModule):
    name = "bug_bounty"
    description = "Bug Bounty Automation (live hosts, ffuf, nuclei, httpx)"
    version = "1.3.0"
    categories = ["active", "bugbounty"]
    is_active = True

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        assets: List[Asset] = context.get("assets", [])

        candidates: Set[str] = set([target])
        for a in assets:
            if a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                candidates.add(a.value)

        self.log(f"Probing {len(candidates)} hosts...")

        # Prefer ProjectDiscovery httpx if available
        if is_available("httpx"):
            live_hosts = await self._probe_httpx(list(candidates), result)
        else:
            live_hosts = await self._check_live(list(candidates), result)

        if live_hosts:
            if self.safe_mode:
                self.log("Safe mode ON — limited path discovery", "warning")
                await self._light_path_probe(live_hosts[:10], result, aggressive=False)
            else:
                await self._light_path_probe(live_hosts[:20], result, aggressive=True)
                await self._run_ffuf(live_hosts[:8], result)

        if live_hosts and is_available("nuclei"):
            await self._run_nuclei(live_hosts, result)
        elif not is_available("nuclei"):
            self.log("nuclei not found — skip", "debug")

        if live_hosts:
            export_path = Path(self.config.paths.assets_dir) / f"{self._safe(target)}_live.txt"
            export_path.parent.mkdir(parents=True, exist_ok=True)
            export_path.write_text("\n".join(sorted(live_hosts)) + "\n", encoding="utf-8")
            result.raw["live_hosts_file"] = str(export_path)

        result.stats = {
            "candidates": len(candidates),
            "live_hosts": len(live_hosts),
            "nuclei": result.raw.get("nuclei_ran", False),
            "ffuf": result.raw.get("ffuf_ran", False),
            "httpx_bin": is_available("httpx"),
        }
        self.log(f"Bug bounty finished — {len(live_hosts)} live hosts", "success")
        return result

    async def _probe_httpx(self, hosts: List[str], result: ModuleResult) -> List[str]:
        """Use ProjectDiscovery httpx for fast probing."""
        self.log("Using ProjectDiscovery httpx for probing...")
        live = []
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hosts))
            targets_file = f.name
        try:
            proc = await asyncio.create_subprocess_exec(
                "httpx", "-l", targets_file, "-silent", "-status-code", "-title",
                "-tech-detect", "-json", "-timeout", "8", "-threads", "25",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            for line in stdout.decode(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = item.get("host") or item.get("input") or ""
                # normalize host
                host = host.replace("https://", "").replace("http://", "").split("/")[0]
                if not host:
                    continue
                live.append(host)
                techs = item.get("tech", []) or item.get("technologies", []) or []
                if isinstance(techs, str):
                    techs = [techs]
                self.add_asset(result, Asset(
                    value=host,
                    type=AssetType.SUBDOMAIN if host.count(".") >= 2 else AssetType.DOMAIN,
                    source="httpx",
                    alive=True,
                    technologies=list(techs)[:10],
                    metadata={
                        "status_code": item.get("status_code") or item.get("status-code"),
                        "title": item.get("title"),
                        "url": item.get("url"),
                        "webserver": item.get("webserver"),
                    },
                ))
        except Exception as e:
            result.errors.append(f"httpx: {e}")
            self.log(f"httpx binary failed, falling back: {e}", "warning")
            return await self._check_live(hosts, result)
        finally:
            Path(targets_file).unlink(missing_ok=True)
        return list(dict.fromkeys(live))

    async def _check_live(self, hosts: List[str], result: ModuleResult) -> List[str]:
        live = []
        timeout = httpx.Timeout(8.0, connect=4.0)
        headers = {"User-Agent": self.config.scan.user_agent}
        sem = asyncio.Semaphore(self.config.scan.max_concurrent)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
            async def probe(host: str):
                async with sem:
                    for scheme in ("https", "http"):
                        try:
                            resp = await client.get(f"{scheme}://{host}")
                            asset = Asset(
                                value=host,
                                type=AssetType.SUBDOMAIN if host.count(".") >= 2 else AssetType.DOMAIN,
                                source=self.name, alive=True,
                                metadata={
                                    "scheme": scheme,
                                    "status_code": resp.status_code,
                                    "final_url": str(resp.url),
                                    "server": resp.headers.get("server"),
                                    "title": self._extract_title(resp.text),
                                },
                                headers={k.lower(): v for k, v in resp.headers.items()},
                            )
                            techs = []
                            if resp.headers.get("server"):
                                techs.append(resp.headers["server"])
                            if resp.headers.get("x-powered-by"):
                                techs.append(resp.headers["x-powered-by"])
                            asset.technologies = techs
                            self.add_asset(result, asset)
                            live.append(host)
                            return
                        except Exception:
                            continue
            await asyncio.gather(*(probe(h) for h in hosts))
        return live

    async def _light_path_probe(self, hosts: List[str], result: ModuleResult, aggressive: bool = False):
        paths = [
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/favicon.ico", "/crossdomain.xml",
        ]
        if aggressive:
            paths.extend(["/admin", "/api", "/api/v1", "/graphql", "/swagger", "/docs",
                          "/actuator/health", "/.env", "/backup"])
        headers = {"User-Agent": self.config.scan.user_agent}
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False, headers=headers) as client:
            for host in hosts:
                for path in paths:
                    url = f"https://{host}{path}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code in (200, 301, 302, 401, 403):
                            sev = Severity.MEDIUM if path in ("/.env", "/backup") and resp.status_code == 200 else Severity.INFO
                            self.add_finding(result, Finding(
                                title=f"Path responded: {path}",
                                description=f"{url} → HTTP {resp.status_code}",
                                severity=sev, confidence=0.7, module=self.name,
                                asset=host, evidence=url, tags=["path", "discovery"],
                            ))
                    except Exception:
                        continue

    async def _run_ffuf(self, hosts: List[str], result: ModuleResult):
        if not is_available("ffuf"):
            self.log("ffuf not installed — skip", "debug")
            return
        self.log(f"Running ffuf on {len(hosts)} hosts (small wordlist)...")
        result.raw["ffuf_ran"] = True

        # Minimal built-in wordlist for common paths
        wordlist = [
            "admin", "api", "login", "dashboard", "backup", "config", "test",
            "dev", "staging", "internal", "swagger", "docs", "graphql",
            "actuator", "metrics", "debug", "console", ".git", ".env",
            "robots.txt", "sitemap.xml", "wp-admin", "phpmyadmin",
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(wordlist) + "\n")
            wl_path = wf.name

        try:
            for host in hosts:
                url = f"https://{host}/FUZZ"
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ffuf", "-u", url, "-w", wl_path,
                        "-mc", "200,204,301,302,401,403",
                        "-t", "20", "-timeout", "5",
                        "-of", "json", "-o", "/dev/stdout",
                        "-s",  # silent
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                    text = stdout.decode(errors="ignore").strip()
                    if not text:
                        continue
                    # ffuf may print JSON object
                    try:
                        data = json.loads(text)
                        results = data.get("results", []) if isinstance(data, dict) else data
                    except json.JSONDecodeError:
                        continue
                    for item in results[:30]:
                        status = item.get("status", 0)
                        path = item.get("input", {}).get("FUZZ") or item.get("url", "")
                        self.add_finding(result, Finding(
                            title=f"ffuf hit: {path}",
                            description=f"HTTP {status} on {host}",
                            severity=Severity.INFO if status in (301, 302, 403) else Severity.LOW,
                            confidence=0.75, module=self.name, asset=host,
                            evidence=item.get("url") or path,
                            tags=["ffuf", "path"],
                            raw=item,
                        ))
                except Exception as e:
                    result.errors.append(f"ffuf {host}: {e}")
        finally:
            Path(wl_path).unlink(missing_ok=True)

    async def _run_nuclei(self, hosts: List[str], result: ModuleResult):
        self.log(f"Running nuclei on {len(hosts)} hosts...")
        result.raw["nuclei_ran"] = True
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            for h in hosts:
                f.write(f"https://{h}\n")
            targets_file = f.name
        try:
            cmd = [
                "nuclei", "-l", targets_file,
                "-tags", "exposure,misconfig,cve,tech",
                "-severity", "medium,high,critical",
                "-silent", "-jsonl",
                "-rate-limit", "30", "-c", "10", "-timeout", "8",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            sev_map = {
                "critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
            }
            for line in stdout.decode(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    info = item.get("info", {})
                    severity_str = str(info.get("severity", "info")).lower()
                    self.add_finding(result, Finding(
                        title=info.get("name", item.get("template-id", "nuclei")),
                        description=str(info.get("description", ""))[:300],
                        severity=sev_map.get(severity_str, Severity.INFO),
                        confidence=0.8, module=self.name,
                        asset=item.get("host") or item.get("matched-at", ""),
                        evidence=item.get("matched-at") or item.get("url"),
                        references=info.get("reference") or [],
                        tags=["nuclei", severity_str] + list(info.get("tags") or []),
                        raw=item,
                    ))
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            result.errors.append(f"nuclei: {e}")
        finally:
            Path(targets_file).unlink(missing_ok=True)

    def _extract_title(self, html: str) -> Optional[str]:
        try:
            start = html.lower().find("<title")
            if start == -1:
                return None
            start = html.find(">", start) + 1
            end = html.lower().find("</title>", start)
            return html[start:end].strip()[:120] if end != -1 else None
        except Exception:
            return None

    def _safe(self, name: str) -> str:
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:80]
