"""
Endpoints de dados para o dashboard (retornam JSON, consumidos via HTMX/JS).
"""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_user
from app.models.server import DnsServer
from app.models.metric import DnsMetric
from app.models.attack import AttackEvent

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_summary(db: Session = Depends(get_db), _=Depends(require_api_user)):
    """Resumo geral: status dos servidores, ataques ativos, métricas recentes."""
    servers = db.query(DnsServer).filter(DnsServer.is_active == True).all()  # noqa
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(minutes=2)

    result = []
    for srv in servers:
        last_metric = (
            db.query(DnsMetric)
            .filter(DnsMetric.server_id == srv.id)
            .order_by(desc(DnsMetric.recorded_at))
            .first()
        )
        active_attack = (
            db.query(AttackEvent)
            .filter(AttackEvent.server_id == srv.id, AttackEvent.status == "active",
                    AttackEvent.deleted_at == None)  # noqa
            .first()
        )
        online = srv.last_seen and srv.last_seen >= cutoff

        result.append({
            "id": srv.id,
            "hostname": srv.hostname,
            "ip_external": srv.ip_external,
            "online": online,
            "last_seen": srv.last_seen.isoformat() if srv.last_seen else None,
            "current_qps": last_metric.qps if last_metric else 0,
            "current_score": last_metric.composite_score if last_metric else 0,
            "nxdomain_rate": last_metric.nxdomain_rate if last_metric else 0,
            "attack_active": active_attack is not None,
            "attack_severity": active_attack.severity if active_attack else None,
        })

    total_attacks_today = (
        db.query(func.count(AttackEvent.id))
        .filter(
            AttackEvent.started_at >= now - timedelta(hours=24),
            AttackEvent.deleted_at == None,  # noqa
        )
        .scalar()
    )
    active_attacks = (
        db.query(func.count(AttackEvent.id))
        .filter(AttackEvent.status == "active", AttackEvent.deleted_at == None)  # noqa
        .scalar()
    )

    return {
        "servers": result,
        "total_attacks_today": total_attacks_today,
        "active_attacks": active_attacks,
        "timestamp": now.isoformat(),
    }


@router.get("/metrics/{server_id}")
def get_server_metrics(
    server_id: int,
    minutes: int = Query(default=60, ge=5, le=1440),
    db: Session = Depends(get_db),
    _=Depends(require_api_user),
):
    """Série temporal de QPS e score para gráficos do dashboard."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes)
    rows = (
        db.query(DnsMetric)
        .filter(DnsMetric.server_id == server_id, DnsMetric.recorded_at >= cutoff)
        .order_by(DnsMetric.recorded_at)
        .all()
    )
    return {
        "server_id": server_id,
        "labels": [r.recorded_at.strftime("%H:%M:%S") for r in rows],
        "qps": [round(r.qps or 0, 1) for r in rows],
        "nxdomain_rate": [round(r.nxdomain_rate or 0, 1) for r in rows],
        "score": [round(r.composite_score or 0, 1) for r in rows],
    }


@router.get("/attacks/recent")
def get_recent_attacks(
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    _=Depends(require_api_user),
):
    attacks = (
        db.query(AttackEvent, DnsServer.hostname)
        .join(DnsServer, DnsServer.id == AttackEvent.server_id)
        .filter(AttackEvent.deleted_at == None)  # noqa
        .order_by(desc(AttackEvent.started_at))
        .limit(limit)
        .all()
    )
    return [
        {
            "id": a.id,
            "hostname": hostname,
            "severity": a.severity,
            "score": a.composite_score,
            "peak_qps": a.peak_qps,
            "started_at": a.started_at.isoformat(),
            "ended_at": a.ended_at.isoformat() if a.ended_at else None,
            "status": a.status,
        }
        for a, hostname in attacks
    ]
