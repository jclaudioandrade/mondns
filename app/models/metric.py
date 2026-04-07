from datetime import datetime
from sqlalchemy import Integer, Float, DateTime, ForeignKey, Index, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class DnsMetric(Base):
    """
    Métricas coletadas pelos agentes em cada servidor DNS.
    Retenção: configurável via metric_retention_days (padrão 7 dias).
    Inclui todos os inputs e outputs do motor de detecção para permitir
    análise retroativa de eventos não classificados como ataque.
    """
    __tablename__ = "dns_metrics"

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("dns_servers.id"), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    # Volume
    qps: Mapped[float | None] = mapped_column(Float, nullable=True)           # queries/segundo
    query_count: Mapped[int | None] = mapped_column(Integer, nullable=True)   # total no intervalo
    nxdomain_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    nxdomain_rate: Mapped[float | None] = mapped_column(Float, nullable=True) # % 0-100

    # Rede
    rx_pps: Mapped[float | None] = mapped_column(Float, nullable=True)
    tx_pps: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Distribuição de tipos de query ({"A": 50, "AAAA": 20, "ANY": 5, ...})
    query_types: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Top IPs fontes, domínios consultados e domínios NXDOMAIN (top 20)
    top_source_ips: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    top_queried_domains: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    top_nxdomain_domains: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Frames descartados pelo agente (tipos AUTH/RESOLVER não processados anteriormente)
    frames_discarded: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Scores individuais por algoritmo (0-100) — inputs completos da decisão
    score_qps: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_nxdomain: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_source_entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_query_type: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_domain_entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_discard_rate: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Score composto e resultado da detecção
    composite_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(nullable=True)              # normal|suspect|attack
    triggered_algorithms: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("ix_dns_metrics_server_recorded", "server_id", "recorded_at"),
    )
