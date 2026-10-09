"""Health and readiness endpoints for Auctaryn."""
import asyncio
import inspect
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter

from api.security import credentials_are_distinct
from core.config import get_config
from core.models import ModuleHealth, ModuleStatus, SystemHealth

router = APIRouter()
_start_time = time.time()
RUNTIME_PROBE_TIMEOUT_SECONDS = 6.0


def _check_module_health(name: str, enabled: bool) -> ModuleHealth:
    if not enabled:
        return ModuleHealth(name=name, status=ModuleStatus.DISABLED)
    # Enabled is not equivalent to healthy: no live probe exists for this module yet.
    return ModuleHealth(
        name=name,
        status=ModuleStatus.DEGRADED,
        error_message="No live module health probe is registered; status is unverified.",
        uptime_seconds=time.time() - _start_time,
    )


async def _runtime_probe_status() -> dict:
    """Use the same bounded trusted-runtime probe for readiness and detailed health."""
    from api.routes.gateway import get_execution_service

    adapter = get_execution_service().adapter
    configured = adapter is not None
    probe = getattr(adapter, "health_check", None) if configured else None
    available = callable(probe)
    passed = False
    connected = False
    error = None

    if not configured:
        error = "No trusted runtime adapter is configured."
    elif not available:
        error = "Configured runtime adapter has no health probe."
    else:
        try:
            result = probe()
            if inspect.isawaitable(result):
                result = await asyncio.wait_for(result, timeout=RUNTIME_PROBE_TIMEOUT_SECONDS)
            passed = result is True
            if not passed:
                error = "Runtime health probe did not return True."
        except asyncio.TimeoutError:
            error = "Runtime health probe timed out."
        except Exception as exc:
            # Do not return gateway exceptions or response bodies to health callers.
            error = f"Runtime health probe failed ({type(exc).__name__})."

    connected = bool(passed and getattr(adapter, "runtime_name", "") == "openshell")
    if passed and not connected:
        error = "Configured runtime adapter is not OpenShell."

    return {
        "adapter_configured": configured,
        "probe_available": available,
        "probe_passed": passed,
        "openshell_connected": connected,
        "error_message": error,
    }


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
    """Report module state and a bounded live OpenShell probe result."""
    config = get_config()
    runtime = await _runtime_probe_status()
    runtime_status = ModuleStatus.HEALTHY if runtime["openshell_connected"] else ModuleStatus.DEGRADED
    modules = [
        _check_module_health("context_integrity", config.context_integrity.enabled),
        _check_module_health("execution_gateway", config.execution_gateway.enabled),
        _check_module_health("threatfade_oracle", config.threatfade_oracle.enabled),
        ModuleHealth(
            name="openshell_runtime",
            status=runtime_status,
            error_message=runtime["error_message"],
            uptime_seconds=time.time() - _start_time,
        ),
    ]
    # Other enabled modules still lack registered live probes, so overall health
    # remains degraded until their probes are implemented and verified.
    overall_status = (
        ModuleStatus.HEALTHY
        if all(module.status in {ModuleStatus.HEALTHY, ModuleStatus.DISABLED} for module in modules)
        else ModuleStatus.DEGRADED
    )
    return SystemHealth(
        version=config.branding.version,
        modules=modules,
        openshell_connected=runtime["openshell_connected"],
        overall_status=overall_status,
    )


@router.get("/health/ready")
async def readiness_check() -> dict:
    """Readiness requires distinct credentials, identity enforcement, and a live runtime probe."""
    from api.routes.gateway import get_gateway

    credentials_ready = bool(
        os.getenv("AUCTARYN_API_KEY")
        and os.getenv("AUCTARYN_ADMIN_API_KEY")
        and credentials_are_distinct()
    )
    identity_ready = get_gateway().identity_manager is not None
    runtime = await _runtime_probe_status()
    checks = {
        "api_credentials_configured": credentials_ready,
        "identity_enforcement_enabled": identity_ready,
        "trusted_runtime_adapter_configured": runtime["adapter_configured"],
        "runtime_health_probe_available": runtime["probe_available"],
        "runtime_health_probe_passed": runtime["probe_passed"],
        "openshell_connected": runtime["openshell_connected"],
    }
    return {
        "ready": all(checks.values()),
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
