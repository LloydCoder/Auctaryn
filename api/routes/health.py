"""Health and readiness endpoints for Auctaryn."""
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter

from api.security import credentials_are_distinct
from core.config import get_config
from core.models import ModuleHealth, ModuleStatus, SystemHealth

router = APIRouter()
_start_time = time.time()


def _check_module_health(name: str, enabled: bool) -> ModuleHealth:
    if not enabled:
        return ModuleHealth(name=name, status=ModuleStatus.DISABLED)
    # Module-specific dependency checks are added by each module's health adapter.
    return ModuleHealth(
        name=name,
        status=ModuleStatus.HEALTHY,
        uptime_seconds=time.time() - _start_time,
    )


@router.get("/health")
async def health_check() -> dict:
    """Liveness only: this endpoint does not claim the service is ready."""
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": get_config().branding.version,
    }


@router.get("/health/detailed")
async def detailed_health() -> SystemHealth:
    """Report known module state without claiming unverified runtime connectivity."""
    config = get_config()
    modules = [
        _check_module_health("context_integrity", config.context_integrity.enabled),
        _check_module_health("execution_gateway", config.execution_gateway.enabled),
        _check_module_health("threatfade_oracle", config.threatfade_oracle.enabled),
        ModuleHealth(
            name="openshell_runtime",
            status=ModuleStatus.DEGRADED,
            error_message="Runtime connectivity probe is not implemented; connection is unverified.",
        ),
    ]
    return SystemHealth(
        version=config.branding.version,
        modules=modules,
        openshell_connected=False,
        overall_status=ModuleStatus.DEGRADED,
    )


@router.get("/health/ready")
async def readiness_check() -> dict:
    """Fail readiness until credentials and the required runtime boundary are verified."""
    from api.routes.gateway import get_gateway

    credentials_ready = bool(
        os.getenv("AUCTARYN_API_KEY")
        and os.getenv("AUCTARYN_ADMIN_API_KEY")
        and credentials_are_distinct()
    )
    identity_ready = get_gateway().identity_manager is not None
    # OpenShell integration is not yet wired to a real connectivity probe.
    openshell_ready = False
    checks = {
        "api_credentials_configured": credentials_ready,
        "identity_enforcement_enabled": identity_ready,
        "openshell_connected": openshell_ready,
    }
    return {
        "ready": all(checks.values()),
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
