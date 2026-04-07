from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from app.core.templating import templates  # noqa: F401
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import (
    authenticate_user, create_session, delete_session, SESSION_COOKIE
)
from app.core.audit import log_action, get_client_ip
from app.config import settings

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    # Se já logado, redirecionar para dashboard
    from app.core.security import get_current_user_from_request
    if get_current_user_from_request(request):
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse("auth/login.html", {"request": request, "error": None})


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, username, password)
    if not user:
        log_action(db, "login_failed", username=username,
                   ip_address=get_client_ip(request),
                   user_agent=request.headers.get("User-Agent"))
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Usuário ou senha inválidos."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Criar sessão
    session_data = {
        "id": user.id, "username": user.username,
        "group": user.group_name, "full_name": user.full_name or user.username,
    }
    session_id = create_session(session_data)

    # Atualizar last_login
    user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    log_action(db, "login_success", username=user.username, user_id=user.id,
               ip_address=get_client_ip(request),
               user_agent=request.headers.get("User-Agent"))

    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_id,
        httponly=True,
        secure=settings.app_env == "production",
        samesite="lax",
        max_age=settings.session_expire_seconds,
    )
    return response


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    from app.core.security import get_current_user_from_request
    user = get_current_user_from_request(request)
    session_id = request.cookies.get(SESSION_COOKIE)

    if session_id:
        delete_session(session_id)
    if user:
        log_action(db, "logout", username=user.get("username", ""),
                   user_id=user.get("id"), ip_address=get_client_ip(request))

    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response
