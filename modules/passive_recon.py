"""
Faedra Pro - Passive Recon & Intelligence Module
Author: Uras AKAS | urasakas.com

Sources:
- DNS, crt.sh, HackerTarget, AlienVault OTX, Wayback, WHOIS
- subfinder / amass (if installed)
"""

from __future__ import annotations
import asyncio
import json
import re
from datetime import datetime
from typing import List, Optional, Set
from urllib.parse import urlparse, quote

import httpx

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity
from utils.tools import is_available


class PassiveReconModule(BaseModule):
    name = "passive_recon"
    description = "Passive Recon & Intelligence (DNS, CT, OTX, Wayback, subfinder, amass)"
    version = "1.3.0"
    categories = ["recon", "passive"]
    is_active = False

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        self.log(f"Starting passive recon on {target}")

        domain = self._extract_domain(target)
        if not domain:
            result.success = False
            result.errors.append("Could not extract a valid domain from target")
            return result

        subdomains: Set[str] = set()

        await asyncio.gather(
            self._collect_dns(domain, result),
            self._collect_ct_logs(domain, subdomains, result),
            self._collect_hackertarget(domain, subdomains, result),
            self._collect_otx(domain, subdomains, result),
            self._collect_wayback(domain, subdomains, result),
            self._collect_whois(domain, result),
            self._run_subfinder(domain, subdomains, result),
            self._run_amass(domain, subdomains, result),
        )

        self.add_asset(result, Asset(
            value=domain, type=AssetType.DOMAIN, source=self.name, tags=["root"],
        ))

        for sub in sorted(subdomains):
            if sub == domain:
                continue
            self.add_asset(result, Asset(
                value=sub, type=AssetType.SUBDOMAIN, parent=domain,
                source=self.name, tags=["passive"],
            ))

        result.stats = {
            "subdomains": len(subdomains),
            "dns_ips": len([a for a in result.assets if a.type == AssetType.IP]),
        }
        self.log(f"Passive recon complete — {len(subdomains)} subdomains", "success")
        return result

    def _extract_domain(self, target: str) -> Optional[str]:
        target = target.strip().lower()
        if target.startswith("http://") or target.startswith("https://"):
            return urlparse(target).hostname
        return target.split("/")[0].split(":")[0]

    def _normalize_host(self, value: str, root: str) -> Optional[str]:
        value = value.strip().lower().rstrip(".").lstrip("*.")
        if not value or " " in value:
            return None
        if (value.endswith("." + root) or value == root) and re.match(r"^[a-z0-9._-]+$", value):
            return value
        return None

    async def _collect_dns(self, domain: str, result: ModuleResult):
        self.log("Resolving DNS records...")
        if not HAS_DNSPYTHON:
            try:
                import socket
                ip = socket.gethostbyname(domain)
                self.add_asset(result, Asset(
                    value=ip, type=AssetType.IP, parent=domain, source=self.name,
                    metadata={"record_type": "A"},
                ))
            except Exception:
                pass
            return
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    value = str(rdata).rstrip(".")
                    if rtype in ("A", "AAAA"):
                        self.add_asset(result, Asset(
                            value=value, type=AssetType.IP, parent=domain,
                            source=self.name, metadata={"record_type": rtype},
                        ))
                    else:
                        result.raw.setdefault("dns", {}).setdefault(rtype, []).append(value)
            except Exception:
                continue

    async def _collect_ct_logs(self, domain: str, subdomains: Set[str], result: ModuleResult):
        self.log("Certificate Transparency (crt.sh)...")
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        try:
            async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": self.config.scan.user_agent})
                if resp.status_code == 200:
                    for entry in resp.json():
                        for line in str(entry.get("name_value", "")).split("\n"):
                            host = self._normalize_host(line, domain)
                            if host:
                                subdomains.add(host)
        except Exception as e:
            result.errors.append(f"crt.sh: {e}")

    async def _collect_hackertarget(self, domain: str, subdomains: Set[str], result: ModuleResult):
        self.log("HackerTarget...")
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers={"User-Agent": self.config.scan.user_agent})
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.splitlines():
                        parts = line.split(",")
                        if parts:
                            host = self._normalize_host(parts[0], domain)
                            if host:
                                subdomains.add(host)
        except Exception as e:
            result.errors.append(f"hackertarget: {e}")

    async def _collect_otx(self, domain: str, subdomains: Set[str], result: ModuleResult):
        self.log("AlienVault OTX...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers={"User-Agent": self.config.scan.user_agent})
                if resp.status_code == 200:
                    for rec in resp.json().get("passive_dns", [])[:500]:
                        host = self._normalize_host(str(rec.get("hostname", "")), domain)
                        if host:
                            subdomains.add(host)
        except Exception as e:
            result.errors.append(f"otx: {e}")

    async def _collect_wayback(self, domain: str, subdomains: Set[str], result: ModuleResult):
        self.log("Wayback Machine...")
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{quote(domain)}/*&output=json&fl=original&collapse=urlkey&limit=2000"
        )
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": self.config.scan.user_agent})
                if resp.status_code == 200:
                    data = resp.json()
                    for row in data[1:]:
                        if not row:
                            continue
                        try:
                            host = self._normalize_host(urlparse(row[0]).hostname or "", domain)
                            if host:
                                subdomains.add(host)
                        except Exception:
                            continue
        except Exception as e:
            result.errors.append(f"wayback: {e}")

    async def _run_subfinder(self, domain: str, subdomains: Set[str], result: ModuleResult):
        if not is_available("subfinder"):
            self.log("subfinder not installed — skip", "debug")
            return
        self.log("Running subfinder...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent", "-timeout", "30",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
            for line in stdout.decode(errors="ignore").splitlines():
                host = self._normalize_host(line.strip(), domain)
                if host:
                    subdomains.add(host)
            result.raw["subfinder"] = True
        except Exception as e:
            result.errors.append(f"subfinder: {e}")

    async def _run_amass(self, domain: str, subdomains: Set[str], result: ModuleResult):
        if not is_available("amass"):
            self.log("amass not installed — skip", "debug")
            return
        # Passive mode only — faster and quieter
        self.log("Running amass (passive)...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-d", domain, "-timeout", "2",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=150)
            for line in stdout.decode(errors="ignore").splitlines():
                host = self._normalize_host(line.strip(), domain)
                if host:
                    subdomains.add(host)
            result.raw["amass"] = True
        except Exception as e:
            result.errors.append(f"amass: {e}")

    async def _collect_whois(self, domain: str, result: ModuleResult):
        self.log("WHOIS...")
        try:
            import whois
            w = whois.whois(domain)
            if not w:
                return
            result.raw["whois"] = {
                "registrar": str(getattr(w, "registrar", None)),
                "creation_date": str(getattr(w, "creation_date", None)),
                "expiration_date": str(getattr(w, "expiration_date", None)),
                "name_servers": [str(ns) for ns in (getattr(w, "name_servers", []) or [])],
            }
            exp = getattr(w, "expiration_date", None)
            if exp:
                if isinstance(exp, list):
                    exp = exp[0]
                if isinstance(exp, datetime):
                    days_left = (exp - datetime.utcnow()).days
                    if 0 < days_left < 30:
                        self.add_finding(result, Finding(
                            title="Domain nearing expiration",
                            description=f"{domain} expires in {days_left} days",
                            severity=Severity.MEDIUM, module=self.name, asset=domain,
                            tags=["whois", "expiration"],
                        ))
        except Exception as e:
            self.log(f"WHOIS failed: {e}", "debug")
