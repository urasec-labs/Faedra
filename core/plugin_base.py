"""
Faedra Pro - Plugin Base Interface
Author: Uras AKAS | urasakas.com
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from core.models import ModuleResult, Asset, Finding
from core.config import FaedraConfig


class BaseModule(ABC):
    """
    All Faedra modules must inherit from this class.
    This enforces a consistent interface across the framework.
    """

    name: str = "base"
    description: str = "Base module"
    version: str = "1.0.0"
    author: str = "Uras AKAS | urasakas.com"

    # Which categories this module belongs to
    categories: List[str] = []

    # Does this module perform active (potentially noisy) actions?
    is_active: bool = False

    # Requires root / privileged tools?
    requires_privileged: bool = False

    def __init__(self, config: FaedraConfig):
        self.config = config
        self.safe_mode = config.app.safe_mode

    @abstractmethod
    async def run(self, target: str, context: Optional[dict] = None) -> ModuleResult:
        """
        Execute the module against the given target.
        context can contain previously discovered assets, options, etc.
        Must return a ModuleResult.
        """
        ...

    def create_result(self, target: str) -> ModuleResult:
        return ModuleResult(module_name=self.name, target=target)

    def add_asset(self, result: ModuleResult, asset: Asset):
        result.assets.append(asset)

    def add_finding(self, result: ModuleResult, finding: Finding):
        result.findings.append(finding)

    def log(self, msg: str, level: str = "info"):
        # Simple console logging; can be replaced by structured logger later
        prefix = {
            "info": "[*]",
            "success": "[✓]",
            "warning": "[!]",
            "error": "[✗]",
            "debug": "[.]",
        }.get(level, "[*]")
        print(f"{prefix} [{self.name}] {msg}")
