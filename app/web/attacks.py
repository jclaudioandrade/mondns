from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import get_current_user_from_request
from app.models.attack import AttackEvent, AttackDetail
from app.models.server import DnsServer

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/attacks", response_class=HTMLResponse)
def attacks_list(
    request: Request,
    page: int = Query(default=1, ge=1),
    server_id: int | None = None,
    status_filter: str | None = None,
    db: Session = Depends(get_db),
):
    user = get_current_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    q = (
        db.query(AttackEvent, DnsServer.hostname)
        .join(DnsServer, DnsServer.id == AttackEvent.server_id)
        .filter(AttackEvent.deleted_at == None)  # noqa
    )
    if server_id:
        q = q.filter(AttackEvent.server_id == server_id)
    if status_filter:
        q = q.filter(AttackEvent.status == status_filter)

    per_page = 20
    total = q.count()
    items = q.order_by(desc(AttackEvent.started_at)).offset((page - 1) * per_page).limit(per_page).all()
    servers = db.query(DnsServer).filter(DnsServer.is_active == True).all()  # noqa

    return templates.TemplateResponse("attacks/index.html", {
        "request": request, "user": user,
        "attacks": [{"event": a, "hostname": h} for a, h in items],
        "servers": servers, "total": total, "page": page,
        "per_page": per_page, "pages": max(1, (total + per_page - 1) // per_page),
        "server_id": server_id, "status_filter": status_filter,
        "page_title": "Histórico de Ataques",
    })


@router.get("/attacks/{attack_id}", response_class=HTMLResponse)
def attack_detail(attack_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    row = (
        db.query(AttackEvent, DnsServer.hostname)
        .join(DnsServer, DnsServer.id == AttackEvent.server_id)
        .filter(AttackEvent.id == attack_id, AttackEvent.deleted_at == None)  # noqa
        .first()
    )
    if not row:
        return templates.TemplateResponse("404.html", {"request": request, "user": user}, status_code=404)

    attack, hostname = row
    details = (
        db.query(AttackDetail)
        .filter(AttackDetail.attack_event_id == attack_id)
        .order_by(AttackDetail.recorded_at)
        .all()
    )

    return templates.TemplateResponse("attacks/detail.html", {
        "request": request, "user": user,
        "attack": attack, "hostname": hostname,
        "details": details,
        "page_title": f"Ataque #{attack_id}",
    })
