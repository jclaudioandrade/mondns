import os
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- Aplicação ---
    app_env: str = "development"
    app_version: str = "0.2.0"
    app_name: str = "mondns"
    port: int = 8002
    secret_key: str = "changeme"
    log_level: str = "INFO"
    web_concurrency: int = 4

    # --- Banco de Dados ---
    database_url: str = "postgresql://mondns_user:changeme@localhost:5433/mondns_db"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30

    # --- Redis ---
    redis_url: str = "redis://:changeme@localhost:6380/0"

    # --- Sessão ---
    session_expire_seconds: int = 3600  # 1 hora

    # --- Rate Limiting ---
    rate_limit_per_minute: int = 100
    rate_limit_auth_per_minute: int = 10

    # --- BIND / DNS ---
    bind_log_dir: str = "/var/log/named"
    bind_query_log: str = "/var/log/named/query.log"
    bind_poll_interval_seconds: int = 5

    # --- Admin inicial (criado na primeira execução) ---
    initial_admin_username: str = "admin"
    initial_admin_email: str = "joao.andrade@sonda.com"
    initial_admin_password: str = "changeme_FORTE_12chars"

    # --- SMTP ---
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "mondns@sondaativas.com.br"
    alert_email_to: str = ""

    # --- Webhook ---
    webhook_url: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
