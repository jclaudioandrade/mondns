from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_admin, require_api_user
from app.core.audit import log_action, get_client_ip
from app.models.config import SystemConfig

router = APIRouter(prefix="/config", tags=["config"])


class ConfigUpdate(BaseModel):
    config_value: str


@router.get("")
def list_config(group: str | None = None, db: Session = Depends(get_db), _=Depends(require_api_user)):
    q = db.query(SystemConfig)
    if group:
        q = q.filter(SystemConfig.config_group == group)
    rows = q.order_by(SystemConfig.config_group, SystemConfig.config_key).all()
    return [
        {"key": r.config_key, "value": r.config_value,
         "description": r.description, "group": r.config_group,
         "updated_at": r.updated_at}
        for r in rows
    ]


@router.put("/{config_key}")
def update_config(
    config_key: str, data: ConfigUpdate, request: Request,
    db: Session = Depends(get_db), admin=Depends(require_api_admin),
):
    row = db.query(SystemConfig).filter(SystemConfig.config_key == config_key).first()
    if not row:
        raise HTTPException(status_code=404, detail="Configuração não encontrada.")

    old_value = row.config_value
    row.config_value = data.config_value
    row.updated_by = admin["id"]
    db.commit()

    log_action(db, "config_updated", username=admin["username"], user_id=admin["id"],
               resource_type="system_config", resource_id=config_key,
               details={"old": old_value, "new": data.config_value},
               ip_address=get_client_ip(request))
    return {"ok": True, "key": config_key, "value": data.config_value}


@router.get("/groups/list")
def list_groups(_=Depends(require_api_user), db: Session = Depends(get_db)):
    groups = db.query(SystemConfig.config_group).distinct().all()
    return [g[0] for g in groups]


@router.post("/test-email")
def test_email(request: Request, db: Session = Depends(get_db), admin=Depends(require_api_admin)):
    """Envia e-mail de teste usando a configuração SMTP atual."""
    from app.services.notifications import _cfg, _send_email
    import smtplib

    host = _cfg(db, "smtp_host")
    if not host:
        raise HTTPException(status_code=400, detail="SMTP não configurado. Preencha smtp_host antes de testar.")

    to_raw = _cfg(db, "alert_email_to")
    recipients = [r.strip() for r in to_raw.split(",") if r.strip()]
    if not recipients:
        raise HTTPException(status_code=400, detail="Nenhum destinatário configurado em alert_email_to.")

    try:
        _send_email(
            db,
            subject="[mondns] Teste de e-mail — configuração SMTP",
            html_body=(
                "<h2>Teste de Notificação mondns</h2>"
                "<p>Este é um e-mail de teste enviado pelo painel de administração do <b>mondns</b>.</p>"
                "<p>Se você recebeu esta mensagem, a configuração SMTP está correta.</p>"
            ),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falha ao enviar e-mail: {exc}")

    log_action(db, "test_email_sent", username=admin["username"], user_id=admin["id"],
               ip_address=get_client_ip(request),
               details={"recipients": recipients})
    return {"ok": True, "recipients": recipients}
