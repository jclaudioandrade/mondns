from typing import Optional
from fastapi import Request, HTTPException, Depends, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import get_current_user_from_request


# ── Dependências de sessão web ────────────────────────────────────────────────

def get_session_user(request: Request) -> Optional[dict]:
    return get_current_user_from_request(request)


def require_login(request: Request) -> dict:
    user = get_current_user_from_request(request)
    if not user:
        # Para rotas web: redirecionar para login
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login_required")
    return user


def require_admin(request: Request) -> dict:
    user = require_login(request)
    if user.get("group") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso restrito a administradores.")
    return user


# ── Dependência de API Key (agentes) ─────────────────────────────────────────

def require_api_key(request: Request, db: Session = Depends(get_db)):
    from app.models.server import DnsServer
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key ausente.")
    server = db.query(DnsServer).filter(
        DnsServer.api_key == api_key,
        DnsServer.is_active == True,  # noqa: E712
    ).first()
    if not server:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key inválida.")
    return server


# ── Dependência de API autenticada (JWT/sessão para API JSON) ─────────────────

def require_api_user(request: Request) -> dict:
    user = get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Não autenticado.")
    return user


def require_api_admin(request: Request) -> dict:
    user = require_api_user(request)
    if user.get("group") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso restrito a administradores.")
    return user
