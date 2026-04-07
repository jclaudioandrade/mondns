from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app.core.templating import templates  # noqa: F401
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import get_current_user_from_request
from app.models.server import DnsServer
from app.config import settings

router = APIRouter()


def _require_user(request: Request):
    user = get_current_user_from_request(request)
    if not user:
        return None
    return user


@router.get("/", response_class=HTMLResponse)
def root(request: Request):
    return RedirectResponse("/dashboard", status_code=302)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    servers = db.query(DnsServer).filter(DnsServer.is_active == True).all()  # noqa
    return templates.TemplateResponse("dashboard/index.html", {
        "request": request,
        "user": user,
        "servers": servers,
        "refresh_seconds": settings.app_env == "production" and 10 or 10,
        "page_title": "Dashboard",
    })
