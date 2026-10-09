"""
TwinGuard — Shared Data Models
Pydantic schemas used across all modules.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --- Enums ---

class RiskLevel(str, Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    DESTRUCTIVE = "destructive"
    CRITICAL = "critical"


class ActionDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    VETOED = "vetoed"
    TIMEOUT = "timeout"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ModuleStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    ERROR = "error"
    DISABLED = "disabled"


class IntegrityStatus(str, Enum):
    INTACT = "intact"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"


# --- Context Integrity Models ---

class ProtectedInstruction(BaseModel):
    tag: str
    content: str
    hash: str
    registered_at: datetime = Field(default_factory=datetime.utcnow)


class IntegrityCheckResult(BaseModel):
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: IntegrityStatus
    instructions_total: int
    instructions_intact: int
    instructions_degraded: int
    degradation_percent: float
    details: list[dict[str, Any]] = []
    blocked: bool = False


class CompactionEvent(BaseModel):
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    before_hash: str
    after_hash: str
    integrity_preserved: bool
    tokens_before: int = 0
    tokens_after: int = 0


# --- Execution Gateway Models ---

class ToolCall(BaseModel):
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tool_name: str
    action: str
    parameters: dict[str, Any] = {}
    target: str = ""
    agent_id: str = ""
    session_id: str = ""


class ActionClassification(BaseModel):
    tool_call: ToolCall
    risk_level: RiskLevel
    confidence: float = 0.0
    reason: str = ""
    matched_pattern: str = ""


class GatewayDecision(BaseModel):
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tool_call: ToolCall
    risk_level: RiskLevel
    decision: ActionDecision
    reason: str = ""
    decided_by: str = ""  # "auto" | "operator" | "veto_engine"
    response_time_ms: float = 0.0


# --- ThreatFade Oracle Models ---

class ThreatFadeResult(BaseModel):
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    score: float
    z_score: float = 0.0
    entropy: float = 0.0
    drop_ratio: float = 0.0
    severity: Severity
    confidence: str = ""
    mitre_ttps: list[str] = []
    fade_detected: bool = False
    source_file: str = ""


class ParliamentVote(BaseModel):
    voter: str  # "claude" | "threatfade" | "grok" (phase 2)
    decision: ActionDecision
    confidence: float
    reasoning: str = ""


# --- System Health Models ---

class ModuleHealth(BaseModel):
    name: str
    status: ModuleStatus
    last_check: datetime = Field(default_factory=datetime.utcnow)
    uptime_seconds: float = 0.0
    error_message: str = ""
    metrics: dict[str, Any] = {}


class SystemHealth(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str = "0.1.0-alpha"
    modules: list[ModuleHealth] = []
    openshell_connected: bool = False
    overall_status: ModuleStatus = ModuleStatus.HEALTHY


# --- Alert Models ---

class Alert(BaseModel):
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity
    module: str
    title: str
    message: str
    data: dict[str, Any] = {}
    acknowledged: bool = False
