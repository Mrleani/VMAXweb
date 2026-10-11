from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes.account import router as account_router
from app.api.routes.scan import router as scan_router
from app.core.config import get_settings
from app.services.scheduler import ScanScheduler

_scheduler = ScanScheduler()


@asynccontextmanager
async def lifespan(_: FastAPI):
    _scheduler.start()
    try:
        yield
    finally:
        await _scheduler.stop()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Maximum Web & API Security Engine - by StarNet",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    application.include_router(scan_router)
    application.include_router(account_router)

    @application.get("/healthz", tags=["system"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "engine": "operational"}

    return application


app = create_app()
