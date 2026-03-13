# ============================================================
# mondns — Dockerfile (Multi-stage build)
# Imagem base: python:3.12-slim (versão fixada)
# Usuário não-root: appuser (UID 1001)
# Sem secrets na imagem — injetados em runtime
# ============================================================

# ------------------------------------------------------------
# Stage 1: base — dependências compartilhadas
# ------------------------------------------------------------
FROM python:3.12.4-slim AS base

# Metadados
LABEL maintainer="João Claudio de Faria Andrade <joao.andrade@sonda.com>"
LABEL project="mondns"
LABEL description="Monitoramento de ataques DDoS em servidores DNS (BIND 9)"

# Variáveis de build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instalar dependências de sistema mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Criar usuário não-root
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home --shell /bin/bash appuser

# Diretório de trabalho
WORKDIR /app

# ------------------------------------------------------------
# Stage 2: builder — instalar dependências Python
# ------------------------------------------------------------
FROM base AS builder

# Instalar dependências de build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar e instalar dependências de produção
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# ------------------------------------------------------------
# Stage 3: development — ambiente de desenvolvimento
# ------------------------------------------------------------
FROM base AS development

# Copiar dependências instaladas
COPY --from=builder /install /usr/local

# Instalar dependências de dev (pytest, etc.)
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt

# Copiar código fonte
COPY --chown=appuser:appgroup . .

# Usar usuário não-root
USER appuser

# Porta via variável de ambiente
ENV PORT=8003
EXPOSE $PORT

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003", "--reload"]

# ------------------------------------------------------------
# Stage 4: production — imagem final mínima e segura
# ------------------------------------------------------------
FROM base AS production

# Instalar libpq para PostgreSQL (runtime only)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copiar dependências instaladas do builder
COPY --from=builder /install /usr/local

# Copiar scripts
COPY --chown=appuser:appgroup scripts/entrypoint.sh /entrypoint.sh
COPY --chown=appuser:appgroup scripts/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

# Copiar código fonte (sem .env, sem secrets)
COPY --chown=appuser:appgroup app/ ./app/
COPY --chown=appuser:appgroup migrations/ ./migrations/
COPY --chown=appuser:appgroup alembic.ini .

# Usar usuário não-root
USER appuser

# Porta via variável de ambiente
ENV PORT=8003
EXPOSE $PORT

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD /healthcheck.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "app.main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8003", \
     "--workers", "4", \
     "--timeout", "60", \
     "--graceful-timeout", "30", \
     "--log-file", "-", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
