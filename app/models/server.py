from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class DnsServer(Base):
    __tablename__ = "dns_servers"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_internal: Mapped[str | None] = mapped_column(String(45), nullable=True)
    ip_external: Mapped[str | None] = mapped_column(String(45), nullable=True)
    role: Mapped[str] = mapped_column(String(10), default="slave")   # master | slave
    api_key: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    def __repr__(self) -> str:
        return f"<DnsServer {self.hostname} [{self.role}]>"
