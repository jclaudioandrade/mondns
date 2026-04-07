"""
mondns — DNS DDoS Monitor
Entrypoint da aplicação FastAPI.
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from app.core.templating import templates as _templates

from app.config import settings
from app.db.session import engine
from app.db.base import Base

# ── Rotas API ────────────────────────────────────────────────
from app.api.v1 import collect, dashboard, attacks, users, config, servers, agent

# ── Rotas Web ────────────────────────────────────────────────
from app.web import auth as web_auth
from app.web import dashboard as web_dashboard
from app.web import attacks as web_attacks
from app.web import admin as web_admin
from app.web import about as web_about

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


async def _purge_metrics_loop():
    """Purge diário de dns_metrics mais antigas que metric_retention_days."""
    # Aguarda 60s no startup para o banco estar pronto
    await asyncio.sleep(60)
    while True:
        try:
            from app.db.session import SessionLocal
            from app.models.metric import DnsMetric
            from app.models.config import SystemConfig
            db = SessionLocal()
            try:
                cfg = db.query(SystemConfig).filter(
                    SystemConfig.config_key == "metric_retention_days"
                ).first()
                days = int(cfg.config_value) if cfg else 7
                cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
                deleted = db.query(DnsMetric).filter(DnsMetric.recorded_at < cutoff).delete()
                db.commit()
                if deleted:
                    logger.info("PURGE dns_metrics: %d registros removidos (retenção=%dd)", deleted, days)
            finally:
                db.close()
        except Exception as exc:
            logger.error("Erro no purge de métricas: %s", exc)
        # Roda a cada 24h
        await asyncio.sleep(86400)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("mondns v%s iniciando (env=%s)", settings.app_version, settings.app_env)
    _init_db()
    task = asyncio.create_task(_purge_metrics_loop())
    yield
    task.cancel()
    logger.info("mondns encerrando.")


def _init_db():
    """Cria tabelas e dados iniciais se necessário.
    Usa advisory lock do PostgreSQL para serializar entre workers.
    """
    from sqlalchemy import text
    from app.db.session import SessionLocal
    from app.models.user import User
    from app.models.config import SystemConfig, DEFAULT_CONFIGS
    from app.core.security import hash_password

    db = SessionLocal()
    try:
        # Advisory lock exclusivo — garante que só 1 worker inicializa
        db.execute(text("SELECT pg_advisory_lock(8003)"))

        # Criar tabelas
        Base.metadata.create_all(bind=engine)

        # Inserir configurações padrão se não existirem
        for cfg in DEFAULT_CONFIGS:
            exists = db.query(SystemConfig).filter(SystemConfig.config_key == cfg["key"]).first()
            if not exists:
                db.add(SystemConfig(
                    config_key=cfg["key"],
                    config_value=cfg["value"],
                    description=cfg["desc"],
                    config_group=cfg["group"],
                ))

        # Criar admin inicial se nenhum usuário existe
        if db.query(User).count() == 0:
            admin = User(
                username=settings.initial_admin_username,
                email=settings.initial_admin_email,
                full_name="Administrador",
                password_hash=hash_password(settings.initial_admin_password),
                group_name="admin",
            )
            db.add(admin)
            logger.info("Usuário admin inicial criado: %s", settings.initial_admin_username)

        db.commit()
    except Exception as exc:
        logger.error("Erro na inicialização do banco: %s", exc)
        db.rollback()
    finally:
        try:
            db.execute(text("SELECT pg_advisory_unlock(8003)"))
            db.commit()
        except Exception:
            pass
        db.close()


# ── Aplicação ────────────────────────────────────────────────
app = FastAPI(
    title="mondns",
    version=settings.app_version,
    description="DNS DDoS Monitor",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.app_env != "production" else None,
    redoc_url=None,
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ── API routes ───────────────────────────────────────────────
api_prefix = "/api/v1"
app.include_router(collect.router,   prefix=api_prefix)
app.include_router(dashboard.router, prefix=api_prefix)
app.include_router(attacks.router,   prefix=api_prefix)
app.include_router(users.router,     prefix=api_prefix)
app.include_router(config.router,    prefix=api_prefix)
app.include_router(servers.router,   prefix=api_prefix)
app.include_router(agent.router,     prefix=api_prefix)

# ── Web routes ───────────────────────────────────────────────
app.include_router(web_auth.router)
app.include_router(web_dashboard.router)
app.include_router(web_attacks.router)
app.include_router(web_admin.router)
app.include_router(web_about.router)


# ── Health check ─────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": settings.app_version}


# ── 404 handler ──────────────────────────────────────────────
templates = _templates


@app.exception_handler(404)
async def not_found(request: Request, exc):
    from app.core.security import get_current_user_from_request
    user = get_current_user_from_request(request)
    if request.url.path.startswith("/api/"):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Não encontrado."}, status_code=404)
    return templates.TemplateResponse(
        "404.html", {"request": request, "user": user}, status_code=404
    )
