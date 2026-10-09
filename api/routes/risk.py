"""Versioned advisory risk contract for Tinlance Agent Platform integrations.

Auctaryn reports risk signals; it does not grant Platform authority, approve
actions, or execute tools through this endpoint.
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.routes.gateway import require_api_key
from core.models import RiskLevel, ToolCall
from modules.execution_gateway.data_guard import SensitiveDataGuard
from modules.execution_gateway.risk_classifier import RiskClassifier

router = APIRouter(dependencies=[Depends(require_api_key)])
CONTRACT_VERSION = "auctaryn-risk-assessment.v1"


class RiskAssessmentRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=256)
    parameters: dict = Field(default_factory=dict)
    target: str = Field(default="", max_length=512)
    agent_id: str = Field(default="", max_length=128)
    session_id: str = Field(default="", max_length=128)


class RiskAssessmentResponse(BaseModel):
    contract_version: Literal["auctaryn-risk-assessment.v1"] = CONTRACT_VERSION
    assessment_id: str
    assessed_at: datetime
    authority: Literal["advisory_only"] = "advisory_only"
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    matched_pattern: str
    input_fingerprint: str


@router.post("/assess", response_model=RiskAssessmentResponse)
async def assess_risk(request: RiskAssessmentRequest) -> RiskAssessmentResponse:
    """Return a bounded risk signal; never return an allow/deny decision."""
    call = ToolCall(
        tool_name=request.tool_name,
        action=request.action,
        parameters=request.parameters,
        target=request.target,
        agent_id=request.agent_id,
        session_id=request.session_id,
    )
    SensitiveDataGuard().validate_tool_call(call)
    classification = RiskClassifier().classify(call)
    canonical = json.dumps(
        {
            "tool_name": request.tool_name,
            "action": request.action,
            "parameters": request.parameters,
            "target": request.target,
            "agent_id": request.agent_id,
            "session_id": request.session_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return RiskAssessmentResponse(
        assessment_id=uuid4().hex,
        assessed_at=datetime.now(timezone.utc),
        risk_level=classification.risk_level,
        confidence=classification.confidence,
        reason=classification.reason,
        matched_pattern=classification.matched_pattern,
        input_fingerprint=sha256(canonical).hexdigest(),
    )
