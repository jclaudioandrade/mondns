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

# Executar migrations (12-Factor: migration separada do startup)
echo "==> [mondns] Executando migrations..."
alembic upgrade head
echo "==> [mondns] Migrations concluídas."

# Iniciar aplicação
echo "==> [mondns] Iniciando aplicação na porta ${PORT:-8002}..."
exec "$@"
