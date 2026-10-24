"""
Faedra Pro - Stealth & Evasion Layer
Author: Uras AKAS | urasakas.com

Provides shared stealth capabilities used by other modules:
- User-Agent rotation
- Configurable delay / rate limiting
- Optional HTTP proxy support
- Basic header normalization

This module can also run standalone to validate stealth settings.
"""

from __future__ import annotations
import asyncio
import random
from typing import Dict, List, Optional

import httpx

from core.plugin_base import BaseModule
from core.models import ModuleResult, Finding, Severity


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]


class StealthModule(BaseModule):
    name = "stealth"
    description = "Stealth & Evasion Layer (UA rotation, rate-limit, proxy)"
    version = "1.1.0"
    categories = ["support"]
    is_active = False

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        cfg = self.config.stealth

        self.log("Applying / validating stealth configuration")

        result.raw["stealth_config"] = {
            "enabled": cfg.enabled,
            "randomize_ua": cfg.randomize_ua,
            "proxy": cfg.proxy,
            "max_rps": cfg.max_requests_per_second,
        }

        # Inject helpers into context so downstream modules can use them
        if context is not None:
            context["stealth"] = {
                "get_headers": self.get_headers,
                "get_client_kwargs": self.get_client_kwargs,
                "delay": self.adaptive_delay,
            }

        # Optional live check: can we reach the target with current settings?
        if cfg.enabled:
            ok = await self._probe_with_stealth(target)
            result.stats["stealth_probe_ok"] = ok
            if not ok:
                self.add_finding(result, Finding(
                    title="Stealth probe could not reach target",
                    description="Proxy or network settings may be blocking outbound requests",
                    severity=Severity.INFO,
                    module=self.name,
                    asset=target,
                    tags=["stealth", "connectivity"],
                ))

        result.stats.update({
            "enabled": cfg.enabled,
            "proxy_configured": bool(cfg.proxy),
        })
        self.log(
            f"Stealth ready — enabled={cfg.enabled} proxy={'yes' if cfg.proxy else 'no'}",
            "success",
        )
        return result

    def get_headers(self) -> Dict[str, str]:
        """Return a stealth-aware header set."""
        ua = self.config.scan.user_agent
        if self.config.stealth.randomize_ua:
            ua = random.choice(USER_AGENTS)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def get_client_kwargs(self) -> dict:
        """Return kwargs suitable for httpx.AsyncClient."""
        kwargs = {
            "headers": self.get_headers(),
            "timeout": 15.0,
            "follow_redirects": True,
        }
        if self.config.stealth.proxy:
            kwargs["proxies"] = self.config.stealth.proxy
        return kwargs

    async def adaptive_delay(self):
        """Sleep according to configured max RPS (with small jitter)."""
        rps = max(self.config.stealth.max_requests_per_second, 0.5)
        base = 1.0 / rps
        jitter = random.uniform(0, base * 0.3)
        await asyncio.sleep(base + jitter)

    async def _probe_with_stealth(self, target: str) -> bool:
        kwargs = self.get_client_kwargs()
        # httpx proxies argument changed across versions; handle both
        proxy = kwargs.pop("proxies", None)
        try:
            async with httpx.AsyncClient(**kwargs, proxy=proxy) as client:
                for scheme in ("https", "http"):
                    try:
                        resp = await client.head(f"{scheme}://{target}", timeout=8.0)
                        if resp.status_code < 500:
                            return True
                    except Exception:
                        continue
        except Exception:
            # Fallback without proxy kw
            try:
                async with httpx.AsyncClient(headers=self.get_headers(), timeout=8.0) as client:
                    resp = await client.head(f"https://{target}")
                    return resp.status_code < 500
            except Exception:
                return False
        return False
