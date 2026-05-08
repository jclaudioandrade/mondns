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

# ── Forgot / Reset Password ───────────────────────────────────────────────────

@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse("auth/forgot_password.html", {"request": request})


@router.post("/forgot-password", response_class=HTMLResponse)
def forgot_password_submit(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    from app.models.user import User
    from app.core.security import create_password_reset_token
    from app.services.notifications import send_password_reset_email

    # Sempre retorna a mesma mensagem para não revelar se e-mail existe
    msg = "Se o e-mail estiver cadastrado, você receberá as instruções em breve."

    user = db.query(User).filter(
        User.email == email.strip().lower(),
        User.is_active == True,  # noqa: E712
    ).first()

    if user:
        token = create_password_reset_token(user.id)
        base_url = str(request.base_url).rstrip("/")
        reset_url = f"{base_url}/reset-password?token={token}"
        sent = send_password_reset_email(db, user.email, reset_url)
        log_action(db, "password_reset_requested", username=user.username,
                   user_id=user.id, ip_address=get_client_ip(request))
        if not sent:
            # SMTP não configurado — exibe o link direto apenas em dev
            if settings.app_env != "production":
                return templates.TemplateResponse("auth/forgot_password.html", {
                    "request": request,
                    "dev_link": reset_url,
                    "info": "SMTP não configurado. Link de reset (só visível em dev):",
                })

    return templates.TemplateResponse("auth/forgot_password.html", {
        "request": request, "success": msg,
    })


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str = ""):
    from app.core.security import verify_password_reset_token
    valid = bool(token and verify_password_reset_token(token))
    return templates.TemplateResponse("auth/reset_password.html", {
        "request": request, "token": token, "valid": valid,
    })


@router.post("/reset-password", response_class=HTMLResponse)
def reset_password_submit(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    db: Session = Depends(get_db),
):
    from app.models.user import User
    from app.core.security import consume_password_reset_token, hash_password

    error = None
    if len(password) < 8:
        error = "A senha deve ter pelo menos 8 caracteres."
    elif password != password2:
        error = "As senhas não coincidem."

    if error:
        return templates.TemplateResponse("auth/reset_password.html", {
            "request": request, "token": token, "valid": True, "error": error,
        })

    user_id = consume_password_reset_token(token)
    if not user_id:
        return templates.TemplateResponse("auth/reset_password.html", {
            "request": request, "token": token, "valid": False,
        })

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()  # noqa: E712
    if not user:
        return templates.TemplateResponse("auth/reset_password.html", {
            "request": request, "token": token, "valid": False,
        })

    user.password_hash = hash_password(password)
    db.commit()
    log_action(db, "password_reset_done", username=user.username,
               user_id=user.id, ip_address=get_client_ip(request))

    return templates.TemplateResponse("auth/reset_password.html", {
        "request": request, "token": "", "valid": False, "done": True,
    })


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
        "must_change_password": bool(user.must_change_password),
    }
    session_id = create_session(session_data)

    # Atualizar last_login
    user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    log_action(db, "login_success", username=user.username, user_id=user.id,
               ip_address=get_client_ip(request),
               user_agent=request.headers.get("User-Agent"))

    redirect_to = "/change-password" if user.must_change_password else "/dashboard"
    response = RedirectResponse(redirect_to, status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_id,
        httponly=True,
        secure=settings.app_env == "production",
        samesite="lax",
        max_age=settings.session_expire_seconds,
    )
    return response


@router.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request):
    from app.core.security import get_current_user_from_request
    user = get_current_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("auth/change_password.html", {
        "request": request, "user": user,
    })


@router.post("/change-password", response_class=HTMLResponse)
def change_password_submit(
    request: Request,
    password: str = Form(...),
    password2: str = Form(...),
    db: Session = Depends(get_db),
):
    from app.core.security import (
        get_current_user_from_request, get_session, SESSION_COOKIE, hash_password
    )
    from app.models.user import User

    current = get_current_user_from_request(request)
    if not current:
        return RedirectResponse("/login", status_code=302)

    error = None
    if len(password) < 8:
        error = "A senha deve ter pelo menos 8 caracteres."
    elif password != password2:
        error = "As senhas não coincidem."

    if error:
        return templates.TemplateResponse("auth/change_password.html", {
            "request": request, "user": current, "error": error,
        })

    u = db.query(User).filter(User.id == current["id"]).first()
    if not u:
        return RedirectResponse("/login", status_code=302)

    u.password_hash = hash_password(password)
    u.must_change_password = False
    db.commit()

    # Atualiza a sessão para remover a flag
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        from app.core.security import get_redis
        import json
        r = get_redis()
        from app.core.security import SESSION_PREFIX, SESSION_EXPIRE_SECONDS
        raw = r.get(f"{SESSION_PREFIX}{session_id}")
        if raw:
            data = json.loads(raw)
            data["must_change_password"] = False
            r.setex(f"{SESSION_PREFIX}{session_id}", SESSION_EXPIRE_SECONDS, json.dumps(data))

    log_action(db, "password_changed", username=u.username, user_id=u.id,
               ip_address=get_client_ip(request))

    return RedirectResponse("/dashboard", status_code=302)


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
