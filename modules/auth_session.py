"""
Faedra Pro - Authentication & Session Testing
Author: Uras AKAS | urasakas.com

Capabilities:
- Login form / auth endpoint discovery
- Cookie security attribute analysis (Secure, HttpOnly, SameSite)
- Basic session token pattern detection
- Default / weak credential awareness (informational only, no brute force)
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity


LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/user/login",
    "/admin/login",
    "/account/login",
    "/wp-login.php",
    "/admin",
    "/administrator",
    "/user/sign_in",
]

# Common default credential pairs (only reported as informational risk, never sprayed)
DEFAULT_CREDS_NOTE = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("test", "test"),
]


class AuthSessionModule(BaseModule):
    name = "auth_session"
    description = "Authentication & Session Testing"
    version = "1.1.0"
    categories = ["auth", "active"]
    is_active = True

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        assets: List[Asset] = context.get("assets", [])

        hosts: Set[str] = set([target])
        for a in assets:
            if a.alive and a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                hosts.add(a.value)

        self.log(f"Authentication & session analysis on {len(hosts)} hosts")

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": self.config.scan.user_agent},
        ) as client:
            for host in list(hosts)[:12]:
                await self._analyze_host(client, host, result)

        result.stats = {
            "login_forms_found": len([f for f in result.findings if "login-form" in f.tags]),
            "cookie_issues": len([f for f in result.findings if "cookie" in f.tags]),
        }
        self.log(
            f"Auth module finished — forms={result.stats['login_forms_found']} "
            f"cookie_issues={result.stats['cookie_issues']}",
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

            # Cookie security analysis on any response
            self._check_cookies(host, resp, result)

            # Look for login forms on homepage
            self._find_login_forms(host, base, resp.text, result)

            # Probe common login paths
            for path in LOGIN_PATHS:
                url = urljoin(base + "/", path.lstrip("/"))
                try:
                    r = await client.get(url)
                    if r.status_code == 200 and self._looks_like_login(r.text):
                        self.add_finding(result, Finding(
                            title=f"Login interface found: {path}",
                            description=f"Possible authentication page at {url}",
                            severity=Severity.INFO,
                            confidence=0.75,
                            module=self.name,
                            asset=host,
                            evidence=url,
                            tags=["auth", "login-form"],
                        ))
                        self._find_login_forms(host, url, r.text, result)
                        self._check_cookies(host, r, result)
                except Exception:
                    continue

            return  # prefer first successful scheme

    def _check_cookies(self, host: str, resp: httpx.Response, result: ModuleResult):
        # httpx exposes cookies; also parse Set-Cookie headers for flags
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            # Fallback
            raw = resp.headers.get("set-cookie")
            if raw:
                set_cookie_headers = [raw]

        for header in set_cookie_headers:
            header_l = header.lower()
            name = header.split("=")[0].strip() if "=" in header else "unknown"

            issues = []
            if "secure" not in header_l and resp.url.scheme == "https":
                issues.append("Missing Secure flag")
            if "httponly" not in header_l:
                issues.append("Missing HttpOnly flag")
            if "samesite" not in header_l:
                issues.append("Missing SameSite attribute")

            if issues:
                self.add_finding(result, Finding(
                    title=f"Cookie security issue: {name}",
                    description="; ".join(issues),
                    severity=Severity.LOW if len(issues) == 1 else Severity.MEDIUM,
                    confidence=0.85,
                    module=self.name,
                    asset=host,
                    evidence=name,
                    tags=["auth", "cookie", "session"],
                ))

            # Session-like cookie names
            if any(x in name.lower() for x in ("session", "sess", "token", "auth", "jwt", "sid")):
                if "httponly" not in header_l or "secure" not in header_l:
                    self.add_finding(result, Finding(
                        title=f"Session cookie with weak flags: {name}",
                        description="Session-related cookie lacks recommended security attributes",
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        module=self.name,
                        asset=host,
                        evidence=name,
                        tags=["auth", "cookie", "session"],
                    ))

    def _find_login_forms(self, host: str, page_url: str, html: str, result: ModuleResult):
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return

        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            input_types = [i.get("type", "text").lower() for i in inputs]
            input_names = [str(i.get("name", "")).lower() for i in inputs]

            has_password = "password" in input_types
            has_user = any(
                n in input_names or t in ("email", "text")
                for n, t in zip(input_names, input_types)
            )

            if has_password:
                action = form.get("action") or page_url
                method = (form.get("method") or "get").upper()
                self.add_finding(result, Finding(
                    title="Login form detected",
                    description=f"Form method={method} action={action}",
                    severity=Severity.INFO,
                    confidence=0.8,
                    module=self.name,
                    asset=host,
                    evidence=page_url,
                    tags=["auth", "login-form"],
                    raw={"method": method, "action": str(action)},
                ))

                # Informational note about default credentials (never auto-tested)
                self.add_finding(result, Finding(
                    title="Default credential risk surface",
                    description=(
                        "Login form present. Ensure default/vendor credentials are changed. "
                        "This module does not perform credential spraying."
                    ),
                    severity=Severity.INFO,
                    confidence=0.5,
                    module=self.name,
                    asset=host,
                    evidence=page_url,
                    tags=["auth", "default-creds"],
                ))

    def _looks_like_login(self, html: str) -> bool:
        html_l = html.lower()
        indicators = [
            "password",
            "type=\"password\"",
            "type='password'",
            "forgot password",
            "sign in",
            "log in",
            "login",
            "username",
            "user name",
        ]
        score = sum(1 for i in indicators if i in html_l)
        return score >= 2
