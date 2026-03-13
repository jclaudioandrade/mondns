from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_admin, require_api_user
from app.core.security import generate_api_key
from app.core.audit import log_action, get_client_ip
from app.models.server import DnsServer

router = APIRouter(prefix="/servers", tags=["servers"])


class ServerCreate(BaseModel):
    hostname: str
    ip_internal: str | None = None
    ip_external: str | None = None
    role: str = "slave"
    description: str | None = None


class ServerUpdate(BaseModel):
    hostname: str | None = None
    ip_internal: str | None = None
    ip_external: str | None = None
    description: str | None = None
    is_active: bool | None = None


@router.get("")
def list_servers(db: Session = Depends(get_db), _=Depends(require_api_user)):
    servers = db.query(DnsServer).order_by(DnsServer.hostname).all()
    return [
        {"id": s.id, "hostname": s.hostname, "ip_internal": s.ip_internal,
         "ip_external": s.ip_external, "role": s.role, "is_active": s.is_active,
         "last_seen": s.last_seen, "has_key": bool(s.api_key)}
        for s in servers
    ]


@router.post("", status_code=201)
def create_server(
    data: ServerCreate, request: Request,
    db: Session = Depends(get_db), admin=Depends(require_api_admin),
):
    if data.role not in ("master", "slave"):
        raise HTTPException(status_code=400, detail="Role deve ser 'master' ou 'slave'.")
    key = generate_api_key()
    srv = DnsServer(
        hostname=data.hostname, ip_internal=data.ip_internal,
        ip_external=data.ip_external, role=data.role,
        description=data.description, api_key=key,
    )
    db.add(srv)
    db.commit()
    db.refresh(srv)
    log_action(db, "server_created", username=admin["username"], user_id=admin["id"],
               resource_type="dns_server", resource_id=srv.id,
               details={"hostname": data.hostname}, ip_address=get_client_ip(request))
    return {"id": srv.id, "hostname": srv.hostname, "api_key": key}


@router.post("/{server_id}/rotate-key")
def rotate_api_key(
    server_id: int, request: Request,
    db: Session = Depends(get_db), admin=Depends(require_api_admin),
):
    srv = db.query(DnsServer).filter(DnsServer.id == server_id).first()
    if not srv:
        raise HTTPException(status_code=404, detail="Servidor não encontrado.")
    new_key = generate_api_key()
    srv.api_key = new_key
    db.commit()
    log_action(db, "server_key_rotated", username=admin["username"], user_id=admin["id"],
               resource_type="dns_server", resource_id=server_id,
               ip_address=get_client_ip(request))
    return {"api_key": new_key}


@router.put("/{server_id}")
def update_server(
    server_id: int, data: ServerUpdate, request: Request,
    db: Session = Depends(get_db), admin=Depends(require_api_admin),
):
    srv = db.query(DnsServer).filter(DnsServer.id == server_id).first()
    if not srv:
        raise HTTPException(status_code=404, detail="Servidor não encontrado.")
    if data.hostname:
        srv.hostname = data.hostname
    if data.ip_internal is not None:
        srv.ip_internal = data.ip_internal
    if data.ip_external is not None:
        srv.ip_external = data.ip_external
    if data.description is not None:
        srv.description = data.description
    if data.is_active is not None:
        srv.is_active = data.is_active
    db.commit()
    log_action(db, "server_updated", username=admin["username"], user_id=admin["id"],
               resource_type="dns_server", resource_id=server_id,
               ip_address=get_client_ip(request))
    return {"ok": True}


@router.delete("/{server_id}", status_code=204)
def delete_server(
    server_id: int, request: Request,
    db: Session = Depends(get_db), admin=Depends(require_api_admin),
):
    srv = db.query(DnsServer).filter(DnsServer.id == server_id).first()
    if not srv:
        raise HTTPException(status_code=404, detail="Servidor não encontrado.")
    db.delete(srv)
    db.commit()
    log_action(db, "server_deleted", username=admin["username"], user_id=admin["id"],
               resource_type="dns_server", resource_id=server_id,
               ip_address=get_client_ip(request))
