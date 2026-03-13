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
