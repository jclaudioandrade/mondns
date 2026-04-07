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
from app.services.cache import get_redis_client

router = APIRouter(prefix="/collect", tags=["agent"])
logger = logging.getLogger(__name__)

# TTL da chave Redis: 1 hora — cobre ataques longos e limpa automaticamente
# caso o agente pare de enviar payloads sem fechar o evento.
_ATTACK_KEY_TTL = 3600


def _attack_key(server_id: int) -> str:
    return f"mondns:active_attack:{server_id}"


def _get_active_attack(server_id: int) -> int | None:
    val = get_redis_client().get(_attack_key(server_id))
    return int(val) if val else None


def _set_active_attack(server_id: int, event_id: int) -> None:
    get_redis_client().setex(_attack_key(server_id), _ATTACK_KEY_TTL, event_id)


def _close_active_attack(server_id: int) -> int | None:
    r = get_redis_client()
    key = _attack_key(server_id)
    val = r.get(key)
    if val:
        r.delete(key)
        return int(val)
    return None


# ── Confirmação de ataque (debounce) ──────────────────────────────────────────
# Evita falsos positivos de spikes curtos: só abre evento após N janelas
# consecutivas em estado de ataque. O started_at reflete o início real do spike.

import json as _json

_PENDING_KEY_TTL = 300   # 5 min — limpa automaticamente se o agente parar


def _pending_key(server_id: int) -> str:
    return f"mondns:attack_pending:{server_id}"


def _get_pending(server_id: int) -> dict | None:
    val = get_redis_client().get(_pending_key(server_id))
    return _json.loads(val) if val else None


def _inc_pending(server_id: int, started_at: str, score: float,
                 severity: str, triggered: list, qps: float, nxrate: float) -> int:
    r = get_redis_client()
    key = _pending_key(server_id)
    existing = r.get(key)
    if existing:
        data = _json.loads(existing)
        data["count"] += 1
        # Atualizar peak durante período pendente
        if score > data["score"]:
            data["score"] = score
            data["severity"] = severity
            data["triggered"] = triggered
        if qps > data["qps"]:
            data["qps"] = qps
        if nxrate > data["nxrate"]:
            data["nxrate"] = nxrate
    else:
        data = {"count": 1, "started_at": started_at, "score": score,
                "severity": severity, "triggered": triggered,
                "qps": qps, "nxrate": nxrate}
    r.setex(key, _PENDING_KEY_TTL, _json.dumps(data))
    return data["count"]


def _clear_pending(server_id: int) -> None:
    get_redis_client().delete(_pending_key(server_id))


CURRENT_AGENT_VERSION = "0.3.2"


class MetricPayload(BaseModel):
    agent_version: str = Field(default="0.1.0", max_length=20)
    timestamp: datetime
    qps: float = Field(ge=0)
    query_count: int = Field(ge=0)
    nxdomain_count: int = Field(ge=0)
    nxdomain_rate: float = Field(ge=0, le=100)
    rx_pps: float = Field(ge=0, default=0)
    tx_pps: float = Field(ge=0, default=0)
    query_types: dict[str, int] = Field(default_factory=dict)
    top_source_ips: list[dict] = Field(default_factory=list)   # [{"ip": "...", "count": N}]
    top_queried_domains:  list[dict] = Field(default_factory=list)  # [{"domain": "...", "count": N}]
    top_nxdomain_domains: list[dict] = Field(default_factory=list)  # [{"domain": "...", "count": N}]
    frames_discarded: int = Field(ge=0, default=0)


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def receive_metrics(
    payload: MetricPayload,
    server: DnsServer = Depends(require_api_key),
    db: Session = Depends(get_db),
):
    # Extrair nomes de domínio para o motor de detecção (espera lista de strings)
    domain_names = [d.get("domain", "") if isinstance(d, dict) else d
                    for d in payload.top_queried_domains]

    total_frames = payload.query_count + payload.frames_discarded
    discard_rate = (payload.frames_discarded / total_frames * 100.0) if total_frames > 0 else 0.0

    # 1. Rodar detecção
    inp = DetectionInput(
        server_id=server.id,
        qps=payload.qps,
        nxdomain_rate=payload.nxdomain_rate,
        query_types=payload.query_types,
        top_source_ips=payload.top_source_ips,
        top_queried_domains=domain_names,
        query_count=payload.query_count,
        discard_rate=discard_rate,
    )
    result = detect(inp, db)

    # 2. Persistir métrica — inclui todos os scores para análise retroativa
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
        top_queried_domains=payload.top_queried_domains[:20],
        top_nxdomain_domains=payload.top_nxdomain_domains[:20],
        frames_discarded=payload.frames_discarded,
        score_qps=result.score_qps,
        score_nxdomain=result.score_nxdomain,
        score_source_entropy=result.score_source_entropy,
        score_query_type=result.score_query_type,
        score_domain_entropy=result.score_domain_entropy,
        score_discard_rate=result.score_discard_rate,
        composite_score=result.composite_score,
        severity=result.severity,
        triggered_algorithms=result.triggered_algorithms,
    )
    db.add(metric)

    # 3. Atualizar last_seen e versão do agente
    server.last_seen = payload.timestamp
    server.agent_version = payload.agent_version
    db.add(server)

    # 4. Gerenciar eventos de ataque
    _handle_attack(server, payload, result, db)

    db.commit()

    # Verificar se há atualização forçada pendente para este servidor
    r = get_redis_client()
    force_update_key = f"mondns:force_update:{server.id}"
    force_update = bool(r.get(force_update_key))
    if force_update:
        r.delete(force_update_key)

    return {
        "status": "ok",
        "severity": result.severity,
        "score": result.composite_score,
        "current_version": CURRENT_AGENT_VERSION,
        "update_available": payload.agent_version != CURRENT_AGENT_VERSION,
        "force_update": force_update,
    }


def _handle_attack(server: DnsServer, payload: MetricPayload,
                   result, db: Session) -> None:
    from app.models.config import SystemConfig
    sid = server.id
    is_attack = result.severity in ("suspect", "attack")

    # Janelas mínimas consecutivas antes de abrir um evento (default 6 = ~60s)
    cfg = db.query(SystemConfig).filter(
        SystemConfig.config_key == "min_windows_for_attack"
    ).first()
    try:
        min_windows = int(float(cfg.config_value)) if cfg else 6
    except (ValueError, TypeError):
        min_windows = 6

    if is_attack:
        event_id = _get_active_attack(sid)
        if event_id is None:
            # Incrementar contador de confirmação
            count = _inc_pending(
                sid,
                started_at=payload.timestamp.isoformat(),
                score=result.composite_score,
                severity=result.severity,
                triggered=result.triggered_algorithms,
                qps=payload.qps,
                nxrate=payload.nxdomain_rate,
            )
            logger.debug("ATTACK_PENDING server=%s windows=%d/%d score=%.1f",
                         server.hostname, count, min_windows, result.composite_score)

            if count < min_windows:
                # Ainda não confirmado — não abrir evento, não salvar detail
                return

            # Confirmado: abrir evento com started_at do início do spike
            pending = _get_pending(sid)
            _clear_pending(sid)

            score = pending["score"] if pending else result.composite_score
            qps_peak = pending["qps"] if pending else payload.qps
            nxrate_peak = pending["nxrate"] if pending else payload.nxdomain_rate
            triggered = pending["triggered"] if pending else result.triggered_algorithms
            real_started_at = datetime.fromisoformat(pending["started_at"]) if pending else payload.timestamp

            if score >= 85:
                severity = "critical"
            elif score >= 70:
                severity = "high"
            elif score >= 50:
                severity = "medium"
            else:
                severity = "low"

            event = AttackEvent(
                server_id=sid,
                started_at=real_started_at,
                severity=severity,
                composite_score=score,
                peak_qps=qps_peak,
                peak_nxdomain_rate=nxrate_peak,
                total_queries=payload.query_count,
                triggered_algorithms=triggered,
                status="active",
            )
            db.add(event)
            db.flush()
            _set_active_attack(sid, event.id)
            event_id = event.id
            logger.warning("ATTACK_OPEN server=%s event_id=%s score=%.1f windows=%d",
                           server.hostname, event.id, score, count)
            try:
                send_attack_alert(db, server.hostname, severity,
                                  score, triggered, qps_peak)
            except Exception as exc:
                logger.error("Falha na notificação: %s", exc)
        else:
            # Evento já aberto — limpar pending e atualizar peaks
            _clear_pending(sid)
            _set_active_attack(sid, event_id)
            event = db.query(AttackEvent).filter(AttackEvent.id == event_id).first()
            if event:
                if payload.qps > (event.peak_qps or 0):
                    event.peak_qps = payload.qps
                if payload.nxdomain_rate > (event.peak_nxdomain_rate or 0):
                    event.peak_nxdomain_rate = payload.nxdomain_rate
                event.total_queries = (event.total_queries or 0) + payload.query_count
                db.add(event)

        # Salvar detail enquanto evento ativo
        detail = AttackDetail(
            attack_event_id=event_id,
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
            top_queried_domains=payload.top_queried_domains[:20],
            top_nxdomain_domains=payload.top_nxdomain_domains[:20],
            query_types=payload.query_types,
        )
        db.add(detail)

    else:
        # Score normal — zerar confirmação e fechar evento ativo
        _clear_pending(sid)
        event_id = _close_active_attack(sid)
        if event_id is not None:
            event = db.query(AttackEvent).filter(AttackEvent.id == event_id).first()
            if event:
                event.ended_at = payload.timestamp
                event.status = "resolved"
                db.add(event)
                logger.info("ATTACK_CLOSED event_id=%s server=%s", event_id, server.hostname)
