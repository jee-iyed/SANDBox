from fastapi import APIRouter
from sqlalchemy import text

from app.db.session import engine
from app.queue.client import get_redis

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("")
def health():
    db_ok = True
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    redis_ok = True
    try:
        get_redis().ping()
    except Exception:
        redis_ok = False

    return {
        "status": "ok" if (db_ok and redis_ok) else "degraded",
        "database": db_ok,
        "redis": redis_ok,
    }
