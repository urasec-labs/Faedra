"""
Faedra Pro - Notification & Integration Hub
Author: Uras AKAS | urasakas.com
"""

from __future__ import annotations
from typing import Optional
import httpx

from core.plugin_base import BaseModule
from core.models import ModuleResult, Finding, Severity


class NotificationModule(BaseModule):
    name = "notification"
    description = "Notification & Integration Hub"
    version = "1.0.0"
    categories = ["support"]
    is_active = False

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        findings = context.get("findings", [])

        if not self.config.notification.enabled:
            self.log("Notifications disabled in config", "debug")
            return result

        # Only notify on medium+ findings
        important = [f for f in findings if f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        if not important:
            self.log("No medium+ findings to notify")
            return result

        summary = self._build_summary(target, important)
        sent = 0

        if self.config.notification.discord_webhook:
            if await self._send_discord(summary):
                sent += 1

        # Telegram / Slack can be added similarly

        result.stats = {"notifications_sent": sent, "important_findings": len(important)}
        self.log(f"Sent {sent} notification(s)", "success")
        return result

    def _build_summary(self, target: str, findings: list) -> str:
        lines = [
            f"**Faedra Pro Alert** — `{target}`",
            f"Author: Uras AKAS | urasakas.com",
            f"Important findings: {len(findings)}",
            "",
        ]
        for f in findings[:8]:
            lines.append(f"• [{f.severity.value.upper()}] {f.title}")
        if len(findings) > 8:
            lines.append(f"... and {len(findings)-8} more")
        return "\n".join(lines)

    async def _send_discord(self, content: str) -> bool:
        url = self.config.notification.discord_webhook
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json={"content": content[:1900]})
                return resp.status_code in (200, 204)
        except Exception as e:
            self.log(f"Discord notification failed: {e}", "warning")
            return False
