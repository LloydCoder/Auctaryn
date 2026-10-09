"""
TwinGuard — Health Check Routes
System health and module status endpoints.
"""

import time
from datetime import datetime, timezone

from fastapi import APIRouter

from core.config import get_config
from core.models import ModuleHealth, ModuleStatus, SystemHealth


router = APIRouter()

_start_time = time.time()


def _check_module_health(name: str, enabled: bool) -> ModuleHealth:
    """Check individual module health."""
    if not enabled:
        return ModuleHealth(name=name, status=ModuleStatus.DISABLED)

    # MVP: modules report healthy if enabled. Real checks come in Phase 2-3.
    return ModuleHealth(
        name=name,
        status=ModuleStatus.HEALTHY,
        uptime_seconds=time.time() - _start_time,
    )


@router.get("/health")
async def health_check() -> dict:
    """Basic liveness check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": get_config().branding.version,
    }


@router.get("/health/detailed")
async def detailed_health() -> SystemHealth:
    """Detailed health with per-module status."""
    config = get_config()

    modules = [
        _check_module_health("context_integrity", config.context_integrity.enabled),
        _check_module_health("execution_gateway", config.execution_gateway.enabled),
        _check_module_health("threatfade_oracle", config.threatfade_oracle.enabled),
    ]

    all_healthy = all(
        m.status in (ModuleStatus.HEALTHY, ModuleStatus.DISABLED)
        for m in modules
    )

    return SystemHealth(
        version=config.branding.version,
        modules=modules,
        openshell_connected=False,  # TODO: real OpenShell check in Phase 1 setup
        overall_status=ModuleStatus.HEALTHY if all_healthy else ModuleStatus.DEGRADED,
    )


@router.get("/health/ready")
async def readiness_check() -> dict:
    """Readiness probe — are all enabled modules operational?"""
    config = get_config()
    ready = True  # MVP: always ready if server is up

    return {
        "ready": ready,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
