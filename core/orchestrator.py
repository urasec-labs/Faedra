"""
Faedra Pro - Main Orchestrator
Author: Uras AKAS | urasakas.com
"""

from __future__ import annotations
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Type
from pathlib import Path

from core.config import FaedraConfig, get_profile_modules, load_config
from core.models import ScanJob, ModuleResult, Asset, Finding
from core.plugin_base import BaseModule


class Orchestrator:
    """
    Coordinates module execution, asset inventory, and result aggregation.
    """

    def __init__(self, config: Optional[FaedraConfig] = None):
        self.config = config or load_config()
        self.modules: Dict[str, BaseModule] = {}
        self._register_builtin_modules()

    def _register_builtin_modules(self):
        """Import and register built-in modules."""
        try:
            from modules.passive_recon import PassiveReconModule
            from modules.asset_inventory import AssetInventoryModule
            from modules.bug_bounty import BugBountyModule
            from modules.osint_footprint import OSINTFootprintModule
            from modules.pentest import PentestModule
            from modules.ai_analysis import AIAnalysisModule
            from modules.notification import NotificationModule
            from modules.compliance import ComplianceModule
            # Skeletons
            from modules.cloud_secrets import CloudSecretsModule
            from modules.api_security import APISecurityModule
            from modules.auth_session import AuthSessionModule
            from modules.stealth import StealthModule
            from modules.container_config import ContainerConfigModule

            candidates = [
                PassiveReconModule,
                AssetInventoryModule,
                BugBountyModule,
                OSINTFootprintModule,
                PentestModule,
                AIAnalysisModule,
                NotificationModule,
                ComplianceModule,
                CloudSecretsModule,
                APISecurityModule,
                AuthSessionModule,
                StealthModule,
                ContainerConfigModule,
            ]

            for cls in candidates:
                try:
                    instance = cls(self.config)
                    self.modules[instance.name] = instance
                except Exception as e:
                    print(f"[!] Failed to load module {cls}: {e}")
        except ImportError as e:
            print(f"[!] Some modules could not be imported: {e}")

    def list_modules(self) -> List[str]:
        return sorted(self.modules.keys())

    def get_module(self, name: str) -> Optional[BaseModule]:
        return self.modules.get(name)

    async def run_job(
        self,
        target: str,
        profile: str = "quick",
        module_names: Optional[List[str]] = None,
        operator: str = "Uras AKAS | urasakas.com",
    ) -> ScanJob:
        """
        Execute a full scan job using the selected profile or explicit module list.
        """
        if module_names is None:
            module_names = get_profile_modules(self.config, profile)
            if not module_names:
                # fallback to enabled modules in config
                module_names = [k for k, v in self.config.modules.items() if v]

        job = ScanJob(
            target=target,
            profile=profile,
            modules=module_names,
            operator=operator,
            status="running",
            started_at=datetime.utcnow(),
        )

        print(f"\n{'='*70}")
        print(f"  FAEDRA PRO  |  {self.config.app.version}")
        print(f"  Author     : {self.config.app.author}")
        print(f"  Target     : {target}")
        print(f"  Profile    : {profile}")
        print(f"  Modules    : {', '.join(module_names)}")
        print(f"  Safe Mode  : {self.config.app.safe_mode}")
        print(f"{'='*70}\n")

        context: dict = {
            "assets": [],
            "findings": [],
            "job_id": job.id,
        }

        for name in module_names:
            mod = self.modules.get(name)
            if not mod:
                print(f"[!] Module not found: {name}")
                continue

            if mod.is_active and self.config.app.safe_mode:
                # In safe mode we still allow active modules but they should
                # implement their own reduced aggressiveness.
                pass

            print(f"\n>>> Running module: {mod.name} — {mod.description}")
            try:
                result = await mod.run(target, context=context)
                result.finish()
                job.results.append(result)

                # Merge discovered assets into context for downstream modules
                context["assets"].extend(result.assets)
                context["findings"].extend(result.findings)

                print(f"[✓] {mod.name} finished — "
                      f"{len(result.assets)} assets, {len(result.findings)} findings "
                      f"({result.duration_seconds:.1f}s)")
            except Exception as e:
                print(f"[✗] Module {name} failed: {e}")
                err_result = ModuleResult(
                    module_name=name,
                    target=target,
                    success=False,
                    errors=[str(e)],
                )
                err_result.finish()
                job.results.append(err_result)

        job.status = "completed"
        job.finished_at = datetime.utcnow()
        job.summary = self._build_summary(job)

        return job

    def _build_summary(self, job: ScanJob) -> dict:
        total_assets = sum(len(r.assets) for r in job.results)
        total_findings = sum(len(r.findings) for r in job.results)
        by_severity = {}
        for r in job.results:
            for f in r.findings:
                by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

        return {
            "total_assets": total_assets,
            "total_findings": total_findings,
            "findings_by_severity": by_severity,
            "modules_run": len(job.results),
            "successful_modules": sum(1 for r in job.results if r.success),
        }
