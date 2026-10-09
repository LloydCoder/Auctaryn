"""
TwinGuard — API Entry Point
FastAPI application with WebSocket support.
"""

import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_config, load_config
from core.logging import setup_logging, get_logger
from api.routes import health, context, gateway, threatfade, identity, skills, memory
from api.websockets import actions, alerts


startup_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global startup_time
    startup_time = time.time()

    config = get_config()
    logger = setup_logging(
        level=config.logging.level,
        log_file=config.logging.file,
    )
    logger.info("TwinGuard starting", extra={"event": "startup", "version": config.branding.version})

    # Create data directories
    Path("data").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)

    yield

    logger.info("TwinGuard shutting down", extra={"event": "shutdown"})


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    config = get_config()

    app = FastAPI(
        title="TwinGuard API",
        description="AI Agent Containment & Security Platform",
        version=config.branding.version,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # REST routes
    app.include_router(health.router, tags=["Health"])
    app.include_router(context.router, prefix="/api/v1/context", tags=["Context Integrity"])
    app.include_router(gateway.router, prefix="/api/v1/gateway", tags=["Execution Gateway"])
    app.include_router(threatfade.router, prefix="/api/v1/threatfade", tags=["ThreatFade Oracle"])
    app.include_router(identity.router, prefix="/api/v1/identity", tags=["Agent Identity (ASI03)"])
    app.include_router(skills.router, prefix="/api/v1/skills", tags=["Skill Vetting (ASI04)"])
    app.include_router(memory.router, prefix="/api/v1/memory", tags=["Memory Defender (ASI06)"])

    # WebSocket routes
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
