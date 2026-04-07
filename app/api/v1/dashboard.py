"""
Endpoints de dados para o dashboard (retornam JSON, consumidos via HTMX/JS).
"""
from datetime import datetime, timedelta, timezone

_BRT = timezone(timedelta(hours=-3))


def _to_brt_str(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc).astimezone(_BRT).strftime("%d/%m/%Y %H:%M:%S")
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_user
from app.api.v1.collect import CURRENT_AGENT_VERSION
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
            "agent_version": srv.agent_version,
            "update_available": bool(srv.agent_version and srv.agent_version != CURRENT_AGENT_VERSION),
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


@router.get("/metrics/all")
def get_all_metrics(
    minutes: int = Query(default=60, ge=5, le=4320),
    db: Session = Depends(get_db),
    _=Depends(require_api_user),
):
    """Série temporal de todos os servidores em uma única query — evita N requests paralelas."""
    if minutes <= 360:
        bucket_min = 1
    elif minutes <= 1440:
        bucket_min = 5
    else:
        bucket_min = 15

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(minutes=minutes)
    brt = timezone(timedelta(hours=-3))
    fmt = "%H:%M" if minutes <= 60 else "%d/%m %H:%M"

    rows = (
        db.query(DnsMetric)
        .filter(DnsMetric.recorded_at >= cutoff)
        .order_by(DnsMetric.recorded_at)
        .all()
    )

    from collections import defaultdict
    buckets: dict = defaultdict(lambda: defaultdict(list))
    for r in rows:
        ts = r.recorded_at
        bucket_ts = ts - timedelta(
            minutes=ts.minute % bucket_min,
            seconds=ts.second,
            microseconds=ts.microsecond,
        )
        buckets[r.server_id][bucket_ts].append(r)

    start = cutoff - timedelta(
        minutes=cutoff.minute % bucket_min,
        seconds=cutoff.second,
        microseconds=cutoff.microsecond,
    )
    labels = []
    cursor = start
    while cursor <= now:
        labels.append(cursor.replace(tzinfo=timezone.utc).astimezone(brt).strftime(fmt))
        cursor += timedelta(minutes=bucket_min)

    series_keys = ("qps", "nxdomain_rate", "score",
                   "score_qps", "score_nxdomain",
                   "score_source_entropy", "score_query_type",
                   "score_domain_entropy", "score_discard_rate")

    servers_data = {}
    for server_id, sbuckets in buckets.items():
        series = {k: [] for k in series_keys}
        cursor = start
        while cursor <= now:
            if cursor in sbuckets:
                pts = sbuckets[cursor]
                n = len(pts)
                series["qps"].append(round(sum(r.qps or 0 for r in pts) / n, 1))
                series["nxdomain_rate"].append(round(sum(r.nxdomain_rate or 0 for r in pts) / n, 1))
                series["score"].append(round(max(r.composite_score or 0 for r in pts), 1))
                series["score_qps"].append(round(max(r.score_qps or 0 for r in pts), 1))
                series["score_nxdomain"].append(round(max(r.score_nxdomain or 0 for r in pts), 1))
                series["score_source_entropy"].append(round(max(r.score_source_entropy or 0 for r in pts), 1))
                series["score_query_type"].append(round(max(r.score_query_type or 0 for r in pts), 1))
                series["score_domain_entropy"].append(round(max(r.score_domain_entropy or 0 for r in pts), 1))
                series["score_discard_rate"].append(round(max(r.score_discard_rate or 0 for r in pts), 1))
            else:
                for lst in series.values():
                    lst.append(None)
            cursor += timedelta(minutes=bucket_min)
        servers_data[server_id] = series

    from app.models.config import SystemConfig
    def _cfg(key, default):
        r = db.query(SystemConfig).filter(SystemConfig.config_key == key).first()
        try:
            return float(r.config_value) if r else default
        except (ValueError, TypeError):
            return default

    attack_events = (
        db.query(AttackEvent)
        .filter(
            AttackEvent.deleted_at == None,  # noqa
            AttackEvent.started_at >= cutoff - timedelta(hours=1),
        )
        .order_by(AttackEvent.started_at)
        .all()
    )
    attacks_by_server: dict = defaultdict(list)
    for ev in attack_events:
        start_brt = ev.started_at.replace(tzinfo=timezone.utc).astimezone(brt).strftime(fmt)
        end_brt   = ev.ended_at.replace(tzinfo=timezone.utc).astimezone(brt).strftime(fmt) if ev.ended_at else None
        attacks_by_server[ev.server_id].append({
            "id": ev.id, "severity": ev.severity, "status": ev.status,
            "started_label": start_brt, "ended_label": end_brt,
        })

    return {
        "labels": labels,
        "suspect_threshold": _cfg("score_suspect_threshold", 30.0),
        "attack_threshold": _cfg("score_attack_threshold", 70.0),
        "servers": {
            str(sid): {**series, "attacks": attacks_by_server.get(sid, [])}
            for sid, series in servers_data.items()
        },
    }


@router.get("/metrics/{server_id}")
def get_server_metrics(
    server_id: int,
    minutes: int = Query(default=60, ge=5, le=4320),
    db: Session = Depends(get_db),
    _=Depends(require_api_user),
):
    """Série temporal de QPS e score para gráficos do dashboard.
    Gera grade completa de timestamps com None nos buracos para que o
    gráfico mostre lacunas reais (ex: agente offline).
    """
    # Tamanho do bucket conforme período selecionado
    if minutes <= 360:
        bucket_min = 1
    elif minutes <= 1440:
        bucket_min = 5
    else:
        bucket_min = 15

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(minutes=minutes)

    rows = (
        db.query(DnsMetric)
        .filter(DnsMetric.server_id == server_id, DnsMetric.recorded_at >= cutoff)
        .order_by(DnsMetric.recorded_at)
        .all()
    )

    # Agrupa por bucket: bucket_ts -> lista de métricas
    from collections import defaultdict
    buckets: dict = defaultdict(list)
    for r in rows:
        ts = r.recorded_at
        bucket_ts = ts - timedelta(
            minutes=ts.minute % bucket_min,
            seconds=ts.second,
            microseconds=ts.microsecond,
        )
        buckets[bucket_ts].append(r)

    # Grade completa de buckets no período
    fmt = "%H:%M" if minutes <= 60 else "%d/%m %H:%M"
    brt = timezone(timedelta(hours=-3))

    # Ponto inicial alinhado ao bucket
    start = cutoff - timedelta(
        minutes=cutoff.minute % bucket_min,
        seconds=cutoff.second,
        microseconds=cutoff.microsecond,
    )

    series = {k: [] for k in ("qps", "nxdomain_rate", "score",
                               "score_qps", "score_nxdomain",
                               "score_source_entropy", "score_query_type",
                               "score_domain_entropy", "score_discard_rate")}
    labels = []
    cursor = start
    while cursor <= now:
        labels.append(cursor.replace(tzinfo=timezone.utc).astimezone(brt).strftime(fmt))
        if cursor in buckets:
            pts = buckets[cursor]
            n = len(pts)
            series["qps"].append(round(sum(r.qps or 0 for r in pts) / n, 1))
            series["nxdomain_rate"].append(round(sum(r.nxdomain_rate or 0 for r in pts) / n, 1))
            series["score"].append(round(max(r.composite_score or 0 for r in pts), 1))
            series["score_qps"].append(round(max(r.score_qps or 0 for r in pts), 1))
            series["score_nxdomain"].append(round(max(r.score_nxdomain or 0 for r in pts), 1))
            series["score_source_entropy"].append(round(max(r.score_source_entropy or 0 for r in pts), 1))
            series["score_query_type"].append(round(max(r.score_query_type or 0 for r in pts), 1))
            series["score_domain_entropy"].append(round(max(r.score_domain_entropy or 0 for r in pts), 1))
            series["score_discard_rate"].append(round(max(r.score_discard_rate or 0 for r in pts), 1))
        else:
            for lst in series.values():
                lst.append(None)
        cursor += timedelta(minutes=bucket_min)

    from app.models.config import SystemConfig
    def _cfg(key, default):
        r = db.query(SystemConfig).filter(SystemConfig.config_key == key).first()
        try:
            return float(r.config_value) if r else default
        except (ValueError, TypeError):
            return default

    # Eventos de ataque no período — para marcações no gráfico
    attack_events = (
        db.query(AttackEvent)
        .filter(
            AttackEvent.server_id == server_id,
            AttackEvent.deleted_at == None,  # noqa
            AttackEvent.started_at >= cutoff - timedelta(hours=1),  # margem
        )
        .order_by(AttackEvent.started_at)
        .all()
    )
    attacks_out = []
    for ev in attack_events:
        start_brt = ev.started_at.replace(tzinfo=timezone.utc).astimezone(brt).strftime(fmt)
        end_brt   = ev.ended_at.replace(tzinfo=timezone.utc).astimezone(brt).strftime(fmt) if ev.ended_at else None
        attacks_out.append({
            "id":       ev.id,
            "severity": ev.severity,
            "status":   ev.status,
            "started_label": start_brt,
            "ended_label":   end_brt,
        })

    return {
        "server_id": server_id,
        "labels": labels,
        "suspect_threshold": _cfg("score_suspect_threshold", 30.0),
        "attack_threshold": _cfg("score_attack_threshold", 70.0),
        "attacks": attacks_out,
        **series,
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
            "started_at": _to_brt_str(a.started_at),
            "ended_at": _to_brt_str(a.ended_at),
            "status": a.status,
        }
        for a, hostname in attacks
    ]
