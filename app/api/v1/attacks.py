from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_user, require_api_admin
from app.core.audit import log_action, get_client_ip
from app.models.attack import AttackEvent, AttackDetail
from app.models.server import DnsServer
from fastapi import Request

router = APIRouter(prefix="/attacks", tags=["attacks"])


@router.get("")
def list_attacks(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=5, le=100),
    server_id: int | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_api_user),
):
    q = (
        db.query(AttackEvent, DnsServer.hostname)
        .join(DnsServer, DnsServer.id == AttackEvent.server_id)
        .filter(AttackEvent.deleted_at == None)  # noqa
    )
    if server_id:
        q = q.filter(AttackEvent.server_id == server_id)
    if status:
        q = q.filter(AttackEvent.status == status)

    total = q.count()
    items = q.order_by(desc(AttackEvent.started_at)).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [
            {
                "id": a.id, "hostname": hostname, "severity": a.severity,
                "score": a.composite_score, "peak_qps": a.peak_qps,
                "peak_nxdomain_rate": a.peak_nxdomain_rate,
                "total_queries": a.total_queries,
                "started_at": a.started_at.isoformat(),
                "ended_at": a.ended_at.isoformat() if a.ended_at else None,
                "status": a.status, "triggered_algorithms": a.triggered_algorithms,
            }
            for a, hostname in items
        ],
    }


@router.get("/{attack_id}")
def get_attack(attack_id: int, db: Session = Depends(get_db), _=Depends(require_api_user)):
    row = (
        db.query(AttackEvent, DnsServer.hostname)
        .join(DnsServer, DnsServer.id == AttackEvent.server_id)
        .filter(AttackEvent.id == attack_id, AttackEvent.deleted_at == None)  # noqa
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Ataque não encontrado.")
    attack, hostname = row

    details = (
        db.query(AttackDetail)
        .filter(AttackDetail.attack_event_id == attack_id)
        .order_by(AttackDetail.recorded_at)
        .all()
    )

    return {
        "id": attack.id, "hostname": hostname, "severity": attack.severity,
        "score": attack.composite_score, "peak_qps": attack.peak_qps,
        "peak_nxdomain_rate": attack.peak_nxdomain_rate,
        "total_queries": attack.total_queries,
        "started_at": attack.started_at.isoformat(),
        "ended_at": attack.ended_at.isoformat() if attack.ended_at else None,
        "status": attack.status, "notes": attack.notes,
        "triggered_algorithms": attack.triggered_algorithms,
        "timeline": {
            "labels": [d.recorded_at.strftime("%H:%M:%S") for d in details],
            "qps": [round(d.qps or 0, 1) for d in details],
            "score": [round(d.composite_score or 0, 1) for d in details],
            "nxdomain_rate": [round(d.nxdomain_rate or 0, 1) for d in details],
        },
        "top_ips": details[-1].top_attacker_ips if details else [],
    }


@router.delete("/{attack_id}", status_code=204)
def delete_attack(
    attack_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_api_admin),
):
    """Remove permanentemente um evento de ataque. Apenas admin."""
    attack = db.query(AttackEvent).filter(
        AttackEvent.id == attack_id, AttackEvent.deleted_at == None  # noqa
    ).first()
    if not attack:
        raise HTTPException(status_code=404, detail="Ataque não encontrado.")

    attack.deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
    attack.deleted_by = user["id"]
    db.commit()

    log_action(db, "attack_deleted", username=user["username"], user_id=user["id"],
               resource_type="attack_event", resource_id=attack_id,
               ip_address=get_client_ip(request))
