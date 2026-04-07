from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from app.core.templating import templates  # noqa: F401
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import get_current_user_from_request
from app.models.user import User
from app.models.server import DnsServer
from app.models.config import SystemConfig
from app.models.audit import AuditLog
from app.models.attack import AttackEvent

router = APIRouter(prefix="/admin")


def _require_admin(request: Request):
    user = get_current_user_from_request(request)
    if not user:
        return None, RedirectResponse("/login", status_code=302)
    if user.get("group") != "admin":
        return None, RedirectResponse("/dashboard", status_code=302)
    return user, None


@router.get("/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_admin(request)
    if redir:
        return redir
    users = db.query(User).filter(User.username != user.get("username")).order_by(User.username).all()
    return templates.TemplateResponse("admin/users.html", {
        "request": request, "user": user, "users": users, "page_title": "Gerenciar Usuários",
    })


@router.get("/config", response_class=HTMLResponse)
def admin_config(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_admin(request)
    if redir:
        return redir
    configs = db.query(SystemConfig).order_by(SystemConfig.config_group, SystemConfig.config_key).all()
    # Agrupar por grupo
    groups: dict = {}
    for c in configs:
        groups.setdefault(c.config_group, []).append(c)
    return templates.TemplateResponse("admin/config.html", {
        "request": request, "user": user, "config_groups": groups,
        "page_title": "Configurações do Sistema",
    })


@router.get("/thresholds", response_class=HTMLResponse)
def admin_thresholds(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_admin(request)
    if redir:
        return redir
    configs = db.query(SystemConfig).filter(SystemConfig.config_group == "detection").all()
    return templates.TemplateResponse("admin/thresholds.html", {
        "request": request, "user": user, "configs": configs,
        "page_title": "Thresholds de Detecção",
    })


@router.get("/servers", response_class=HTMLResponse)
def admin_servers(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_admin(request)
    if redir:
        return redir
    servers = db.query(DnsServer).order_by(DnsServer.hostname).all()
    return templates.TemplateResponse("admin/servers.html", {
        "request": request, "user": user, "servers": servers,
        "page_title": "Servidores DNS",
    })


@router.get("/audit", response_class=HTMLResponse)
def admin_audit(
    request: Request,
    page: int = Query(default=1, ge=1),
    db: Session = Depends(get_db),
):
    user, redir = _require_admin(request)
    if redir:
        return redir
    per_page = 50
    total = db.query(AuditLog).count()
    logs = (
        db.query(AuditLog)
        .order_by(desc(AuditLog.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return templates.TemplateResponse("admin/audit.html", {
        "request": request, "user": user, "logs": logs,
        "total": total, "page": page, "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "page_title": "Log de Auditoria",
    })


@router.get("/retention", response_class=HTMLResponse)
def admin_retention(
    request: Request,
    page: int = Query(default=1, ge=1),
    db: Session = Depends(get_db),
):
    user, redir = _require_admin(request)
    if redir:
        return redir
    per_page = 20
    q = (
        db.query(AttackEvent, DnsServer.hostname)
        .join(DnsServer, DnsServer.id == AttackEvent.server_id)
        .filter(AttackEvent.deleted_at == None)  # noqa
    )
    total = q.count()
    attacks = q.order_by(desc(AttackEvent.started_at)).offset((page - 1) * per_page).limit(per_page).all()

    return templates.TemplateResponse("admin/retention.html", {
        "request": request, "user": user,
        "attacks": [{"event": a, "hostname": h} for a, h in attacks],
        "total": total, "page": page, "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "page_title": "Retenção de Dados",
    })


@router.get("/active-sessions-badge", response_class=HTMLResponse)
def active_sessions_badge(request: Request):
    import html as _html
    from app.core.security import get_active_sessions
    user, redir = _require_admin(request)
    base = (
        '<span id="active-users-badge"'
        ' hx-get="/admin/active-sessions-badge"'
        ' hx-trigger="every 30s" hx-swap="outerHTML">'
    )
    if not redir:
        sessions = get_active_sessions()
        if sessions:
            names = _html.escape(", ".join(s["full_name"] for s in sessions))
            base += (
                f'<span class="badge rounded-pill bg-success ms-1"'
                f' data-bs-toggle="tooltip"'
                f' data-bs-title="{names}"'
                f' data-bs-placement="right"'
                f' style="font-size:.7rem">{len(sessions)}</span>'
            )
    base += "</span>"
    return HTMLResponse(base)


@router.get("/notifications", response_class=HTMLResponse)
def admin_notifications(request: Request, db: Session = Depends(get_db)):
    user, redir = _require_admin(request)
    if redir:
        return redir
    configs = db.query(SystemConfig).filter(SystemConfig.config_group == "notifications").all()
    return templates.TemplateResponse("admin/notifications.html", {
        "request": request, "user": user, "configs": configs,
        "page_title": "Configurações de Notificação",
    })
