"""
Faedra Pro - Shared HTTP helpers
Author: Uras AKAS | urasakas.com
"""

from __future__ import annotations
import random
from typing import Dict, Optional

import httpx

from core.config import FaedraConfig

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


def build_headers(config: FaedraConfig) -> Dict[str, str]:
    ua = config.scan.user_agent
    if config.stealth.enabled and config.stealth.randomize_ua:
        ua = random.choice(USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "DNT": "1",
        "Connection": "keep-alive",
    }


def make_client(config: FaedraConfig, timeout: float = 12.0) -> httpx.AsyncClient:
    kwargs = {
        "headers": build_headers(config),
        "timeout": timeout,
        "follow_redirects": True,
    }
    proxy = config.stealth.proxy if config.stealth.enabled else None
    if proxy:
        try:
            return httpx.AsyncClient(**kwargs, proxy=proxy)
        except TypeError:
            return httpx.AsyncClient(**kwargs, proxies=proxy)
    return httpx.AsyncClient(**kwargs)
