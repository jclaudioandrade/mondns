"""
Endpoint receptor de métricas dos agentes mondns instalados nos slaves.
Autenticação: X-API-Key por servidor.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_key
from app.models.server import DnsServer
from app.models.metric import DnsMetric
from app.models.attack import AttackEvent, AttackDetail
from app.services.detection import DetectionInput, detect
from app.services.notifications import send_attack_alert

router = APIRouter(prefix="/collect", tags=["agent"])
logger = logging.getLogger(__name__)

ACTIVE_ATTACKS: dict[int, int] = {}   # server_id → attack_event_id


class MetricPayload(BaseModel):
    timestamp: datetime
    qps: float = Field(ge=0)
    query_count: int = Field(ge=0)
    nxdomain_count: int = Field(ge=0)
    nxdomain_rate: float = Field(ge=0, le=100)
    rx_pps: float = Field(ge=0, default=0)
    tx_pps: float = Field(ge=0, default=0)
    query_types: dict[str, int] = Field(default_factory=dict)
    top_source_ips: list[dict] = Field(default_factory=list)   # [{"ip": "...", "count": N}]
    top_queried_domains: list[str] = Field(default_factory=list)


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def receive_metrics(
    payload: MetricPayload,
    server: DnsServer = Depends(require_api_key),
    db: Session = Depends(get_db),
):
    # 1. Rodar detecção
    inp = DetectionInput(
        server_id=server.id,
        qps=payload.qps,
        nxdomain_rate=payload.nxdomain_rate,
        query_types=payload.query_types,
        top_source_ips=payload.top_source_ips,
        top_queried_domains=payload.top_queried_domains,
    )
    result = detect(inp, db)

    # 2. Persistir métrica
    metric = DnsMetric(
        server_id=server.id,
        recorded_at=payload.timestamp,
        qps=payload.qps,
        query_count=payload.query_count,
        nxdomain_count=payload.nxdomain_count,
        nxdomain_rate=payload.nxdomain_rate,
        rx_pps=payload.rx_pps,
        tx_pps=payload.tx_pps,
        query_types=payload.query_types,
        top_source_ips=payload.top_source_ips,
        composite_score=result.composite_score,
    )
    db.add(metric)

    # 3. Atualizar last_seen do servidor
    server.last_seen = payload.timestamp
    db.add(server)

    # 4. Gerenciar eventos de ataque
    _handle_attack(server, payload, result, db)

    db.commit()

    return {"status": "ok", "severity": result.severity, "score": result.composite_score}


def _handle_attack(server: DnsServer, payload: MetricPayload,
                   result, db: Session) -> None:
    sid = server.id
    is_attack = result.severity in ("suspect", "attack")

    if is_attack:
        if sid not in ACTIVE_ATTACKS:
            # Abrir novo evento
            severity = result.severity
            if result.composite_score >= 85:
                severity = "critical"
            elif result.composite_score >= 70:
                severity = "high"
            elif result.composite_score >= 50:
                severity = "medium"
            else:
                severity = "low"

            event = AttackEvent(
                server_id=sid,
                started_at=payload.timestamp,
                severity=severity,
                composite_score=result.composite_score,
                peak_qps=payload.qps,
                peak_nxdomain_rate=payload.nxdomain_rate,
                total_queries=payload.query_count,
                triggered_algorithms=result.triggered_algorithms,
                status="active",
            )
            db.add(event)
            db.flush()
            ACTIVE_ATTACKS[sid] = event.id
            logger.warning("ATTACK_OPEN server=%s event_id=%s score=%.1f",
                           server.hostname, event.id, result.composite_score)
            # Notificar
            try:
                send_attack_alert(db, server.hostname, severity,
                                  result.composite_score,
                                  result.triggered_algorithms, payload.qps)
            except Exception as exc:
                logger.error("Falha na notificação: %s", exc)
        else:
            # Atualizar evento existente
            event_id = ACTIVE_ATTACKS[sid]
            event = db.query(AttackEvent).filter(AttackEvent.id == event_id).first()
            if event:
                if payload.qps > (event.peak_qps or 0):
                    event.peak_qps = payload.qps
                if payload.nxdomain_rate > (event.peak_nxdomain_rate or 0):
                    event.peak_nxdomain_rate = payload.nxdomain_rate
                event.total_queries = (event.total_queries or 0) + payload.query_count
                db.add(event)

        # Sempre salvar detail durante ataque
        if sid in ACTIVE_ATTACKS:
            detail = AttackDetail(
                attack_event_id=ACTIVE_ATTACKS[sid],
                recorded_at=payload.timestamp,
                qps=payload.qps,
                nxdomain_rate=payload.nxdomain_rate,
                score_qps=result.score_qps,
                score_nxdomain=result.score_nxdomain,
                score_source_entropy=result.score_source_entropy,
                score_query_type=result.score_query_type,
                score_domain_entropy=result.score_domain_entropy,
                composite_score=result.composite_score,
                top_attacker_ips=payload.top_source_ips,
                top_queried_domains=[{"domain": d} for d in payload.top_queried_domains[:20]],
                query_types=payload.query_types,
            )
            db.add(detail)

    elif sid in ACTIVE_ATTACKS:
        # Fechar evento de ataque
        event_id = ACTIVE_ATTACKS.pop(sid)
        event = db.query(AttackEvent).filter(AttackEvent.id == event_id).first()
        if event:
            event.ended_at = payload.timestamp
            event.status = "resolved"
            db.add(event)
            logger.info("ATTACK_CLOSED event_id=%s server=%s", event_id, server.hostname)
