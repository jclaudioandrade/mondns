from datetime import datetime
from sqlalchemy import Integer, Float, DateTime, ForeignKey, Index, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class DnsMetric(Base):
    """
    Métricas coletadas pelos agentes em cada servidor DNS.
    Retenção: 1 ano para dados normais (fora de ataque).
    Dados durante ataques são preservados indefinidamente via AttackDetail.
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
    rx_pps: Mapped[float | None] = mapped_column(Float, nullable=True)  # pacotes recv/s
    tx_pps: Mapped[float | None] = mapped_column(Float, nullable=True)  # pacotes sent/s

    # Distribuição de tipos de query ({"A": 50, "AAAA": 20, "ANY": 5, ...})
    query_types: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Top 10 IPs fontes (lista de {"ip": "x.x.x.x", "count": N})
    top_source_ips: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Score composto de detecção DDoS (0-100)
    composite_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("ix_dns_metrics_server_recorded", "server_id", "recorded_at"),
    )
