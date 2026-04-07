"""
Motor de detecção de DDoS DNS.

Cinco algoritmos independentes com scores 0-100.
Score composto ponderado determina severidade.
"""
import math
import logging
from dataclasses import dataclass, field
from typing import Optional
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class DetectionInput:
    server_id: int
    qps: float
    nxdomain_rate: float               # % 0-100
    query_types: dict                   # {"A": N, "ANY": N, ...}
    top_source_ips: list[dict]          # [{"ip": "...", "count": N}]
    top_queried_domains: list[str]      # lista de domínios consultados
    query_count: int = 0               # total de queries na janela
    discard_rate: float = 0.0          # % de frames descartados (AUTH/RESOLVER) sobre total


@dataclass
class DetectionResult:
    score_qps: float = 0.0
    score_nxdomain: float = 0.0
    score_source_entropy: float = 0.0
    score_query_type: float = 0.0
    score_domain_entropy: float = 0.0
    score_discard_rate: float = 0.0
    composite_score: float = 0.0
    severity: str = "normal"            # normal | suspect | attack
    triggered_algorithms: list[str] = field(default_factory=list)


def _get_config(db: Session, key: str, default: float) -> float:
    from app.models.config import SystemConfig
    cfg = db.query(SystemConfig).filter(SystemConfig.config_key == key).first()
    try:
        return float(cfg.config_value) if cfg else default
    except (ValueError, TypeError):
        return default


def score_qps(qps: float, threshold: float) -> float:
    """Volume de queries/segundo vs threshold configurado."""
    if qps <= 0 or threshold <= 0:
        return 0.0
    ratio = qps / threshold
    if ratio < 0.5:
        return 0.0
    if ratio < 1.0:
        return ratio * 50.0
    return min(100.0, 50.0 + (ratio - 1.0) * 50.0)


def score_nxdomain(nxdomain_rate: float, threshold: float) -> float:
    """Taxa de NXDOMAIN — indica consulta a subdomínios inexistentes (random subdomain attack)."""
    if nxdomain_rate <= 0 or threshold <= 0:
        return 0.0
    return min(100.0, (nxdomain_rate / threshold) * 100.0)


def score_source_entropy(source_ips: list[dict]) -> float:
    """
    Entropia das fontes de tráfego.
    Concentração extrema (flood de 1 IP) OU dispersão extrema (botnet) → score alto.
    """
    if not source_ips:
        return 0.0
    total = sum(ip.get("count", 0) for ip in source_ips)
    if total == 0:
        return 0.0

    entropy = 0.0
    for ip in source_ips:
        p = ip.get("count", 0) / total
        if p > 0:
            entropy -= p * math.log2(p)

    max_entropy = math.log2(len(source_ips)) if len(source_ips) > 1 else 1.0
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0

    # Ambos os extremos são suspeitos
    if normalized < 0.15:       # concentrado — flood de único IP
        return min(100.0, (1.0 - normalized) * 100.0)
    elif normalized > 0.85:     # disperso — DDoS de múltiplas fontes
        return min(100.0, normalized * 100.0)
    return 0.0


def score_query_type(query_types: dict, any_threshold: float) -> float:
    """Queries ANY e TXT em excesso indicam ataque de amplificação."""
    total = sum(query_types.values())
    if total == 0 or any_threshold <= 0:
        return 0.0
    amplification = query_types.get("ANY", 0) + query_types.get("TXT", 0) + query_types.get("RRSIG", 0)
    rate = (amplification / total) * 100.0
    return min(100.0, (rate / any_threshold) * 100.0)


def score_discard_rate(discard_rate: float, threshold: float) -> float:
    """
    Taxa de frames descartados (AUTH/RESOLVER sobre total).
    Alta taxa indica que o BIND está gerando tráfego interno de resolução
    em resposta ao volume de ataque — amplificação interna.
    """
    if discard_rate <= 0 or threshold <= 0:
        return 0.0
    return min(100.0, (discard_rate / threshold) * 100.0)


def score_domain_entropy(domains: list[str], threshold: float) -> float:
    """
    Entropia de Shannon dos rótulos de subdomínio consultados.
    Alta entropia = subdomínios gerados aleatoriamente (DDoS via random labels).
    """
    if not domains or threshold <= 0:
        return 0.0
    labels = [d.split(".")[0] for d in domains if d]
    all_chars = "".join(labels)
    if not all_chars:
        return 0.0

    freq: dict[str, int] = {}
    for c in all_chars:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    total = len(all_chars)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)

    return min(100.0, (entropy / threshold) * 100.0)


def composite(scores: dict[str, float], weights: dict[str, float]) -> float:
    total_weight = sum(weights.values())
    if total_weight == 0:
        return 0.0
    return sum(scores[k] * weights[k] for k in scores if k in weights) / total_weight


def severity_label(score: float, suspect_threshold: float, attack_threshold: float) -> str:
    if score >= attack_threshold:
        return "attack"
    if score >= suspect_threshold:
        return "suspect"
    return "normal"


def detect(inp: DetectionInput, db: Session) -> DetectionResult:
    """Executa todos os algoritmos e retorna DetectionResult com score e severidade."""
    # Carregar thresholds do banco
    qps_thr = _get_config(db, "ddos_qps_threshold", 1000.0)
    nxd_thr = _get_config(db, "ddos_nxdomain_rate_threshold", 60.0)
    any_thr = _get_config(db, "ddos_any_query_rate_threshold", 30.0)
    dom_thr = _get_config(db, "ddos_domain_entropy_threshold", 3.5)
    suspect_thr = _get_config(db, "score_suspect_threshold", 30.0)
    attack_thr = _get_config(db, "score_attack_threshold", 70.0)
    min_queries_entropy = int(_get_config(db, "min_queries_for_entropy", 20.0))
    min_qps_entropy = _get_config(db, "min_qps_for_entropy", 100.0)

    discard_thr = _get_config(db, "ddos_discard_rate_threshold", 30.0)

    weights = {
        "qps": _get_config(db, "weight_qps", 25.0),
        "nxdomain": _get_config(db, "weight_nxdomain", 25.0),
        "source_entropy": _get_config(db, "weight_source_entropy", 20.0),
        "query_type": _get_config(db, "weight_query_type", 10.0),
        "domain_entropy": _get_config(db, "weight_domain_entropy", 10.0),
        "discard_rate": _get_config(db, "weight_discard_rate", 10.0),
    }

    s_qps = score_qps(inp.qps, qps_thr)
    s_nxd = score_nxdomain(inp.nxdomain_rate, nxd_thr)
    s_qtype = score_query_type(inp.query_types, any_thr)
    s_discard = score_discard_rate(inp.discard_rate, discard_thr)

    # Entropia só é significativa com amostra suficiente E QPS mínimo.
    # Sem volume, alta entropia é tráfego recursivo legítimo (muitos IPs/domínios diversos).
    if inp.query_count >= min_queries_entropy and inp.qps >= min_qps_entropy:
        s_src = score_source_entropy(inp.top_source_ips)
        s_dom = score_domain_entropy(inp.top_queried_domains, dom_thr)
    else:
        s_src = 0.0
        s_dom = 0.0
        if inp.query_count > 0:
            logger.debug(
                "ENTROPY_SKIP server_id=%s query_count=%d qps=%.1f min_queries=%d min_qps=%.0f",
                inp.server_id, inp.query_count, inp.qps, min_queries_entropy, min_qps_entropy,
            )

    scores_map = {
        "qps": s_qps,
        "nxdomain": s_nxd,
        "source_entropy": s_src,
        "query_type": s_qtype,
        "domain_entropy": s_dom,
        "discard_rate": s_discard,
    }
    comp = composite(scores_map, weights)
    sev = severity_label(comp, suspect_thr, attack_thr)

    triggered = [name for name, val in scores_map.items() if val >= 50.0]

    result = DetectionResult(
        score_qps=round(s_qps, 2),
        score_nxdomain=round(s_nxd, 2),
        score_source_entropy=round(s_src, 2),
        score_query_type=round(s_qtype, 2),
        score_domain_entropy=round(s_dom, 2),
        score_discard_rate=round(s_discard, 2),
        composite_score=round(comp, 2),
        severity=sev,
        triggered_algorithms=triggered,
    )

    if sev != "normal":
        logger.warning(
            "DETECTION server_id=%s severity=%s score=%.1f triggered=%s",
            inp.server_id, sev, comp, triggered,
        )

    return result
