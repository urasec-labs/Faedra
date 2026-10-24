"""
Faedra Pro - Asset Inventory & Continuous Monitoring Module
Author: Uras AKAS | urasakas.com

Maintains a persistent inventory of discovered assets and supports
simple change detection between runs.
"""

from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from core.plugin_base import BaseModule
from core.models import ModuleResult, Asset, Finding, AssetType, Severity


class AssetInventoryModule(BaseModule):
    name = "asset_inventory"
    description = "Asset Inventory & Continuous Monitoring"
    version = "1.0.0"
    categories = ["inventory", "monitoring"]
    is_active = False

    def __init__(self, config):
        super().__init__(config)
        self.inventory_dir = Path(config.paths.assets_dir)
        self.inventory_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        result = self.create_result(target)
        context = context or {}
        incoming_assets: List[Asset] = context.get("assets", [])

        self.log(f"Updating asset inventory for {target} ({len(incoming_assets)} new assets)")

        inventory_file = self.inventory_dir / f"{self._safe_name(target)}.json"
        previous = self._load_inventory(inventory_file)

        # Merge
        current_map: Dict[str, dict] = {a["value"]: a for a in previous.get("assets", [])}
        new_assets = []
        updated_assets = []

        for asset in incoming_assets:
            key = asset.value
            now = datetime.utcnow().isoformat()
            if key not in current_map:
                entry = asset.model_dump()
                entry["first_seen"] = now
                entry["last_seen"] = now
                current_map[key] = entry
                new_assets.append(asset)
            else:
                current_map[key]["last_seen"] = now
                # Merge extra metadata
                if asset.technologies:
                    existing_tech = set(current_map[key].get("technologies", []))
                    existing_tech.update(asset.technologies)
                    current_map[key]["technologies"] = sorted(existing_tech)
                updated_assets.append(asset)

        # Detect disappeared assets (simple heuristic)
        current_values = {a.value for a in incoming_assets}
        disappeared = []
        for val, data in current_map.items():
            if val not in current_values and data.get("parent") == target:
                disappeared.append(val)

        # Persist
        inventory = {
            "target": target,
            "updated_at": datetime.utcnow().isoformat(),
            "assets": list(current_map.values()),
        }
        self._save_inventory(inventory_file, inventory)

        # Findings
        if new_assets:
            self.add_finding(result, Finding(
                title=f"{len(new_assets)} new asset(s) discovered",
                description=f"New assets: {', '.join(a.value for a in new_assets[:10])}"
                            + ("..." if len(new_assets) > 10 else ""),
                severity=Severity.INFO,
                module=self.name,
                asset=target,
                tags=["inventory", "new-asset"],
            ))

        if disappeared:
            self.add_finding(result, Finding(
                title=f"{len(disappeared)} previously seen asset(s) no longer observed",
                description=f"Missing: {', '.join(disappeared[:8])}",
                severity=Severity.LOW,
                module=self.name,
                asset=target,
                tags=["inventory", "changed"],
            ))

        # Re-export current assets into result for downstream
        for data in current_map.values():
            try:
                self.add_asset(result, Asset(**{k: v for k, v in data.items() if k in Asset.model_fields}))
            except Exception:
                continue

        result.stats = {
            "total_tracked": len(current_map),
            "new": len(new_assets),
            "updated": len(updated_assets),
            "disappeared": len(disappeared),
        }
        self.log(
            f"Inventory updated — total={len(current_map)} new={len(new_assets)} disappeared={len(disappeared)}",
            "success",
        )
        return result

    def _safe_name(self, target: str) -> str:
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:80]

    def _load_inventory(self, path: Path) -> dict:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return {"assets": []}
        return {"assets": []}

    def _save_inventory(self, path: Path, data: dict):
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
