"""
Faedra Pro - Core Data Models
Author: Uras AKAS | urasakas.com
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl
import uuid


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    REPOSITORY = "repository"
    OTHER = "other"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)
    module: str
    asset: str
    evidence: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cve: Optional[str] = None
    cvss: Optional[float] = None
    tags: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    value: str                          # domain, IP, URL etc.
    type: AssetType
    parent: Optional[str] = None
    source: str = "unknown"             # which module discovered it
    alive: Optional[bool] = None
    ports: List[int] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)


class ModuleResult(BaseModel):
    module_name: str
    target: str
    success: bool = True
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    assets: List[Asset] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)

    def finish(self):
        self.finished_at = datetime.utcnow()
        if self.started_at:
            self.duration_seconds = (self.finished_at - self.started_at).total_seconds()


class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    profile: str = "quick"
    modules: List[str] = Field(default_factory=list)
    status: str = "pending"             # pending, running, completed, failed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    results: List[ModuleResult] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    operator: str = "Uras AKAS | urasakas.com"


class PrioritizedFinding(BaseModel):
    finding: Finding
    priority_score: float
    reasons: List[str] = Field(default_factory=list)
    suggested_actions: List[str] = Field(default_factory=list)
