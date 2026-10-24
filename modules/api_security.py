"""
Faedra Pro - API Security Automation
Author: Uras AKAS | urasakas.com

Capabilities:
- OpenAPI / Swagger discovery (common paths)
- GraphQL endpoint detection
- Basic API misconfiguration checks (verbose errors, missing auth indicators)
- Endpoint inventory from discovered specs
"""

from __future__ import annotations
import asyncio
import json
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity


SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/docs",
    "/redoc",
    "/graphql",
    "/api/graphql",
    "/graphiql",
]


class APISecurityModule(BaseModule):
    name = "api_security"
    description = "API Security Automation (OpenAPI/Swagger, GraphQL, misconfig)"
    version = "1.1.0"
    categories = ["api", "active"]
    is_active = True

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        assets: List[Asset] = context.get("assets", [])

        hosts: Set[str] = set()
        hosts.add(target)
        for a in assets:
            if a.alive and a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                hosts.add(a.value)

        self.log(f"API discovery on {len(hosts)} hosts")

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": self.config.scan.user_agent},
        ) as client:
            for host in list(hosts)[:15]:
                await self._discover_api(client, host, result)

        result.stats = {
            "apis_found": len([f for f in result.findings if "api" in f.tags or "swagger" in f.tags]),
            "hosts_checked": min(len(hosts), 15),
        }
        self.log(f"API module finished — {result.stats['apis_found']} API-related findings", "success")
        return result

    async def _discover_api(self, client: httpx.AsyncClient, host: str, result: ModuleResult):
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}"
            found_any = False

            for path in SWAGGER_PATHS:
                url = urljoin(base + "/", path.lstrip("/"))
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue

                    content_type = resp.headers.get("content-type", "").lower()
                    body = resp.text[:50000]

                    # OpenAPI / Swagger JSON
                    if "json" in content_type or path.endswith((".json", "api-docs")):
                        try:
                            data = resp.json()
                            if self._looks_like_openapi(data):
                                found_any = True
                                self._process_openapi(host, url, data, result)
                                continue
                        except Exception:
                            pass

                    # GraphQL
                    if "graphql" in path.lower() or "graphiql" in path.lower():
                        if self._looks_like_graphql(body, resp.headers):
                            found_any = True
                            self.add_finding(result, Finding(
                                title="GraphQL endpoint discovered",
                                description=f"Possible GraphQL interface at {url}",
                                severity=Severity.MEDIUM,
                                confidence=0.75,
                                module=self.name,
                                asset=host,
                                evidence=url,
                                tags=["api", "graphql"],
                            ))
                            # Basic introspection check (informational)
                            await self._check_graphql_introspection(client, url, host, result)
                            continue

                    # Swagger UI / Redoc HTML
                    if any(x in body.lower() for x in ("swagger-ui", "redoc", "openapi")):
                        found_any = True
                        self.add_finding(result, Finding(
                            title="API documentation UI exposed",
                            description=f"Swagger/ReDoc style UI at {url}",
                            severity=Severity.LOW,
                            confidence=0.7,
                            module=self.name,
                            asset=host,
                            evidence=url,
                            tags=["api", "swagger", "docs"],
                        ))

                except Exception:
                    continue

            if found_any:
                return  # prefer https results

    def _looks_like_openapi(self, data: dict) -> bool:
        if not isinstance(data, dict):
            return False
        return any(k in data for k in ("openapi", "swagger", "paths", "info"))

    def _looks_like_graphql(self, body: str, headers: dict) -> bool:
        body_l = body.lower()
        if "graphql" in body_l or "__schema" in body_l:
            return True
        if "json" in headers.get("content-type", "").lower() and "errors" in body_l:
            return True
        return False

    def _process_openapi(self, host: str, url: str, data: dict, result: ModuleResult):
        version = data.get("openapi") or data.get("swagger") or "unknown"
        title = (data.get("info") or {}).get("title", "Unknown API")
        paths = data.get("paths") or {}

        self.add_finding(result, Finding(
            title=f"OpenAPI specification found: {title}",
            description=f"Version {version} — {len(paths)} paths defined",
            severity=Severity.MEDIUM,
            confidence=0.9,
            module=self.name,
            asset=host,
            evidence=url,
            tags=["api", "openapi", "swagger"],
            raw={"version": version, "path_count": len(paths), "title": title},
        ))

        # Inventory interesting endpoints
        interesting = []
        for path, methods in list(paths.items())[:40]:
            for method, details in (methods or {}).items():
                if method.lower() in ("get", "post", "put", "patch", "delete"):
                    interesting.append(f"{method.upper()} {path}")
                    # Flag potentially sensitive operations
                    path_l = path.lower()
                    if any(x in path_l for x in ("admin", "user", "login", "token", "password", "reset", "internal", "debug")):
                        self.add_finding(result, Finding(
                            title=f"Sensitive API path in spec: {method.upper()} {path}",
                            description=f"Discovered via OpenAPI at {url}",
                            severity=Severity.LOW,
                            confidence=0.7,
                            module=self.name,
                            asset=host,
                            evidence=f"{method.upper()} {path}",
                            tags=["api", "sensitive-path"],
                        ))

        if interesting:
            self.add_asset(result, Asset(
                value=url,
                type=AssetType.URL,
                parent=host,
                source=self.name,
                metadata={"openapi_paths": interesting[:30]},
                tags=["openapi"],
            ))

        # Security schemes check
        components = data.get("components") or data.get("securityDefinitions") or {}
        if not components and not data.get("security"):
            self.add_finding(result, Finding(
                title="OpenAPI spec appears to lack security schemes",
                description="No securityDefinitions / components.securitySchemes / root security found",
                severity=Severity.MEDIUM,
                confidence=0.6,
                module=self.name,
                asset=host,
                evidence=url,
                tags=["api", "auth", "misconfig"],
            ))

    async def _check_graphql_introspection(self, client: httpx.AsyncClient, url: str, host: str, result: ModuleResult):
        query = {"query": "{ __schema { types { name } } }"}
        try:
            resp = await client.post(url, json=query, headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data", {}).get("__schema"):
                    self.add_finding(result, Finding(
                        title="GraphQL introspection enabled",
                        description="Full schema introspection is possible — information disclosure risk",
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        module=self.name,
                        asset=host,
                        evidence=url,
                        tags=["api", "graphql", "introspection"],
                    ))
        except Exception:
            pass
