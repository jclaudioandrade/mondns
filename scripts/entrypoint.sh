#!/bin/bash
# ============================================================
# mondns — Container Entrypoint
# Executa migrations antes de iniciar a aplicação
# ============================================================
set -e

echo "==> [mondns] Iniciando entrypoint..."
echo "==> [mondns] Ambiente: ${APP_ENV:-production}"
echo "==> [mondns] Versão: ${APP_VERSION:-unknown}"

# Aguardar o PostgreSQL estar disponível
echo "==> [mondns] Aguardando PostgreSQL..."
until python -c "
import psycopg2, os, sys
try:
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    conn.close()
    sys.exit(0)
except Exception as e:
    print(f'PostgreSQL não disponível: {e}')
    sys.exit(1)
"; do
    echo "==> [mondns] PostgreSQL não disponível. Aguardando 2s..."
    sleep 2
done
echo "==> [mondns] PostgreSQL disponível."

# Criar tabelas e dados iniciais (antes do gunicorn subir múltiplos workers)
echo "==> [mondns] Inicializando banco de dados..."
python3 -c "
import logging
from app.db.base import Base
from app.db.session import engine, SessionLocal
import app.models.user, app.models.server, app.models.metric
import app.models.attack, app.models.config
from app.config import settings
from app.core.security import hash_password
from app.models.user import User
from app.models.config import SystemConfig, DEFAULT_CONFIGS

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('init_db')

Base.metadata.create_all(bind=engine)
log.info('Tabelas OK.')

# Migrações incrementais — ADD COLUMN IF NOT EXISTS é idempotente no PostgreSQL 9.6+
from sqlalchemy import text
with engine.connect() as conn:
    conn.execute(text('ALTER TABLE dns_metrics ADD COLUMN IF NOT EXISTS frames_discarded INTEGER'))
    conn.execute(text('ALTER TABLE dns_metrics ADD COLUMN IF NOT EXISTS score_discard_rate FLOAT'))
    conn.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS department VARCHAR(100)'))
    conn.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE'))
    conn.commit()
log.info('Colunas OK.')

db = SessionLocal()
try:
    for cfg in DEFAULT_CONFIGS:
        if not db.query(SystemConfig).filter(SystemConfig.config_key == cfg['key']).first():
            db.add(SystemConfig(config_key=cfg['key'], config_value=cfg['value'],
                                description=cfg['desc'], config_group=cfg['group']))
    if db.query(User).count() == 0:
        db.add(User(username=settings.initial_admin_username,
                    email=settings.initial_admin_email,
                    full_name='Administrador',
                    password_hash=hash_password(settings.initial_admin_password),
                    group_name='admin'))
        log.info('Admin criado: %s', settings.initial_admin_username)
    db.commit()
finally:
    db.close()
"
echo "==> [mondns] Banco inicializado."

# Iniciar aplicação
echo "==> [mondns] Iniciando aplicação na porta ${PORT:-8002}..."
exec "$@"
