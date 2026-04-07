from datetime import datetime
from sqlalchemy import Integer, Float, BigInteger, String, Text, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class AttackEvent(Base):
    """
    Evento de ataque DDoS detectado.
    Retenção: INDEFINIDA — remoção manual somente por admin.
    """
    __tablename__ = "attack_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("dns_servers.id"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    severity: Mapped[str] = mapped_column(String(10), default="medium")  # low|medium|high|critical
    composite_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    peak_qps: Mapped[float | None] = mapped_column(Float, nullable=True)
    peak_nxdomain_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_queries: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Algoritmos que dispararam
    triggered_algorithms: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="active")  # active|resolved
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Soft delete — apenas admin pode remover
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deleted_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AttackDetail(Base):
    """
    Dados brutos por segundo durante um evento de ataque.
    Preservados indefinidamente junto com o AttackEvent.
    """
    __tablename__ = "attack_details"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    attack_event_id: Mapped[int] = mapped_column(Integer, ForeignKey("attack_events.id"), nullable=False, index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    qps: Mapped[float | None] = mapped_column(Float, nullable=True)
    nxdomain_rate: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Scores individuais por algoritmo (0-100)
    score_qps: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_nxdomain: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_source_entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_query_type: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_domain_entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    composite_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Top atacantes, domínios consultados, domínios NXDOMAIN e tipos de query
    top_attacker_ips: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    top_queried_domains: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    top_nxdomain_domains: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    query_types: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
