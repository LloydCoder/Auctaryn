"""
Auctaryn API entry point.
FastAPI application with authenticated REST and WebSocket surfaces.
"""

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import get_config
from core.logging import setup_logging
from api.security import configured_for, extract_bearer, token_role
from api.routes import health, context, gateway, threatfade, identity, skills, memory, risk
from api.websockets import actions, alerts
from modules.execution_gateway.openshell_adapter import create_openshell_adapter_from_environment
from modules.execution_gateway.runtime_adapter import RuntimeAdapterUnavailable
from modules.execution_gateway.data_guard import SensitiveDataBlocked


startup_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global startup_time
    startup_time = time.time()

    config = get_config()
    logger = setup_logging(level=config.logging.level, log_file=config.logging.file)
    logger.info("Auctaryn starting", extra={"event": "startup", "version": config.branding.version})

    Path("data").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)

    runtime_adapter = None
    try:
        runtime_adapter = create_openshell_adapter_from_environment()
        gateway.configure_runtime_adapter(runtime_adapter)
        if runtime_adapter is not None:
            logger.info(
                "OpenShell runtime adapter configured",
                extra={"event": "runtime_adapter_ready", "adapter": "nvidia-openshell"},
            )
    except RuntimeAdapterUnavailable as exc:
        gateway.configure_runtime_adapter(None)
        logger.error(
            "Runtime adapter unavailable; governed execution remains disabled (%s)",
            str(exc),
            extra={"event": "runtime_adapter_unavailable"},
        )

    try:
        yield
    finally:
        gateway.configure_runtime_adapter(None)
        if runtime_adapter is not None:
            try:
                runtime_adapter.close()
            except Exception as exc:
                logger.warning(
                    "Runtime adapter shutdown failed (%s)",
                    type(exc).__name__,
                    extra={"event": "runtime_adapter_shutdown_failed"},
                )
        logger.info("Auctaryn shutting down", extra={"event": "shutdown"})


def _requires_admin(path: str) -> bool:
    """Paths that expose privileged decisions, identity, or policy mutation."""
    if path.startswith("/api/v1/identity"):
        return True
    if path.startswith("/api/v1/gateway/decisions"):
        return True
    if path in {
        "/api/v1/gateway/approve",
        "/api/v1/gateway/pending",
        "/api/v1/gateway/identity-enforcement/enable",
        "/api/v1/context/register",
        "/api/v1/context/instructions",
    }:
        return True
    return path.startswith("/api/v1/context/instructions/")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    config = get_config()
    app = FastAPI(
        title="Auctaryn API",
        description="Runtime authority and containment for autonomous AI agents.",
        version=config.branding.version,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    @app.exception_handler(SensitiveDataBlocked)
    async def sensitive_data_blocked_handler(request: Request, exc: SensitiveDataBlocked):
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "sensitive_data_blocked",
                    "message": str(exc),
                    "paths": list(exc.paths),
                    "additional_count": exc.additional_count,
                }
            },
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.server.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )

    @app.middleware("http")
    async def authenticate_api_requests(request: Request, call_next):
        """Require explicit credentials for every non-health API operation."""
        path = request.url.path
        if request.method == "OPTIONS" or not path.startswith("/api/v1/"):
            return await call_next(request)

        role = token_role(extract_bearer(request.headers.get("authorization")))
        required_role = "admin" if _requires_admin(path) else "api"

        if not configured_for(required_role):
            return JSONResponse(
                status_code=503,
                content={"detail": f"{required_role.upper()} API credentials are not configured"},
            )
        if role is None:
            return JSONResponse(status_code=401, content={"detail": "Bearer API credential required"})
        if required_role == "admin" and role != "admin":
            return JSONResponse(status_code=403, content={"detail": "Administrator credential required"})
        return await call_next(request)

    app.include_router(health.router, tags=["Health"])
    app.include_router(context.router, prefix="/api/v1/context", tags=["Context Integrity"])
    app.include_router(gateway.router, prefix="/api/v1/gateway", tags=["Execution Gateway"])
    app.include_router(threatfade.router, prefix="/api/v1/threatfade", tags=["ThreatFade Oracle"])
    app.include_router(identity.router, prefix="/api/v1/identity", tags=["Agent Identity (ASI03)"])
    app.include_router(skills.router, prefix="/api/v1/skills", tags=["Skill Vetting (ASI04)"])
    app.include_router(memory.router, prefix="/api/v1/memory", tags=["Memory Defender (ASI06)"])
    app.include_router(risk.router, prefix="/api/v1/risk", tags=["Advisory Risk Assessment"])
    app.include_router(actions.router, tags=["WebSocket — Actions"])
    app.include_router(alerts.router, tags=["WebSocket — Alerts"])
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "api.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=config.server.debug,
    )
