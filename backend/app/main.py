from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.api.routes.scans import router as scans_router
from app.api.routes.secure_access import router as secure_access_router
from app.api.routes.metrics import router as metrics_router
from app.core.config import settings
from app.core.logging import setup_logging
from app.db.session import Base, engine, SessionLocal
from app.workers.processor import worker

setup_logging()


@asynccontextmanager
async def lifespan(_: FastAPI):
    from app.db import models  # noqa: F401  (register tables)

    Base.metadata.create_all(bind=engine)
    # Best-effort maintenance sweep for stale secure-access requests (fail-closed).
    from app.secure_access import cleanup_expired

    try:
        with SessionLocal() as db:
            cleanup_expired(db)
    except Exception:  # noqa: BLE001 - startup must not fail on cleanup
        pass
    worker.start()
    yield
    worker.stop()


app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"service": settings.app_name, "version": settings.version, "docs": "/docs"}


app.include_router(health_router)
app.include_router(scans_router)
app.include_router(secure_access_router)
app.include_router(metrics_router)
