from datetime import datetime
from sqlalchemy import String, Text, DateTime, Integer, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class SystemConfig(Base):
    """
    Configurações do sistema editáveis pelo admin via painel.
    Thresholds de detecção, notificações, retenção, etc.
    """
    __tablename__ = "system_config"

    id: Mapped[int] = mapped_column(primary_key=True)
    config_key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    config_value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    config_group: Mapped[str] = mapped_column(String(50), default="general")
    # groups: detection | notifications | retention | general
    updated_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return f"<SystemConfig {self.config_key}={self.config_value}>"


# Configurações padrão (inseridas na migration inicial)
DEFAULT_CONFIGS: list[dict] = [
    # --- Detecção ---
    {"key": "ddos_qps_threshold", "value": "1000", "desc": "Queries/segundo para iniciar análise", "group": "detection"},
    {"key": "ddos_qps_consecutive", "value": "10", "desc": "Janelas consecutivas acima do threshold para alarmar", "group": "detection"},
    {"key": "ddos_nxdomain_rate_threshold", "value": "60", "desc": "% de NXDOMAIN para considerar suspeito", "group": "detection"},
    {"key": "ddos_any_query_rate_threshold", "value": "30", "desc": "% de queries ANY/TXT para considerar amplificação", "group": "detection"},
    {"key": "ddos_domain_entropy_threshold", "value": "3.5", "desc": "Entropia de Shannon dos subdomínios (bits)", "group": "detection"},
    {"key": "score_suspect_threshold", "value": "30", "desc": "Score >= X = alerta amarelo (suspeito)", "group": "detection"},
    {"key": "score_attack_threshold", "value": "70", "desc": "Score >= X = alerta vermelho (ataque)", "group": "detection"},
    {"key": "weight_qps", "value": "25", "desc": "Peso do algoritmo QPS no score composto (%)", "group": "detection"},
    {"key": "weight_nxdomain", "value": "25", "desc": "Peso do algoritmo NXDOMAIN no score composto (%)", "group": "detection"},
    {"key": "weight_source_entropy", "value": "20", "desc": "Peso da entropia de fontes no score composto (%)", "group": "detection"},
    {"key": "weight_query_type", "value": "15", "desc": "Peso do tipo de query no score composto (%)", "group": "detection"},
    {"key": "weight_domain_entropy", "value": "15", "desc": "Peso da entropia de domínios no score composto (%)", "group": "detection"},
    {"key": "alarm_silence_minutes", "value": "60", "desc": "Minutos de silêncio após disparo de alarme", "group": "detection"},
    # --- Retenção ---
    {"key": "metric_retention_days", "value": "365", "desc": "Dias de retenção das métricas normais", "group": "retention"},
    # --- Notificações ---
    {"key": "smtp_host", "value": "", "desc": "Servidor SMTP para e-mail de alertas", "group": "notifications"},
    {"key": "smtp_port", "value": "587", "desc": "Porta SMTP", "group": "notifications"},
    {"key": "smtp_user", "value": "", "desc": "Usuário SMTP", "group": "notifications"},
    {"key": "smtp_password", "value": "", "desc": "Senha SMTP", "group": "notifications"},
    {"key": "smtp_from", "value": "mondns@sondaativas.com.br", "desc": "E-mail remetente", "group": "notifications"},
    {"key": "alert_email_to", "value": "joao.andrade@sonda.com", "desc": "Destinatários dos alertas (separados por vírgula)", "group": "notifications"},
    {"key": "webhook_url", "value": "", "desc": "URL de webhook para notificações (Slack/Teams/genérico)", "group": "notifications"},
    {"key": "notifications_enabled", "value": "true", "desc": "Habilitar envio de notificações", "group": "notifications"},
    # --- Geral ---
    {"key": "agent_poll_interval", "value": "5", "desc": "Intervalo de coleta do agente em segundos", "group": "general"},
    {"key": "dashboard_refresh_seconds", "value": "10", "desc": "Intervalo de atualização do dashboard", "group": "general"},
]
