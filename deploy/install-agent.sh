#!/bin/bash
# ============================================================
# mondns-agent — Script de Instalação nos Slaves DNS
# Executar em cada servidor slave (dc1slvns01..04)
#
# Uso: sudo bash install-agent.sh
#
# Ações com sudo (executadas por este script):
#   1. Criar usuário mondns-agent (sem shell, sem home)
#   2. Adicionar ao grupo 'named' (para ler query.log)
#   3. Instalar arquivos em /opt/mondns-agent/
#   4. Instalar serviço systemd
#   5. Habilitar e iniciar o serviço
#
# Autor: joao.andrade@sonda.com
# ============================================================
set -e

INSTALL_DIR="/opt/mondns-agent"
SERVICE_NAME="mondns-agent"
AGENT_USER="mondns-agent"
ENV_FILE="/etc/mondns-agent/.env"

# ── Verificar root ────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: Execute como root: sudo bash $0"
    exit 1
fi

echo "==> [mondns-agent] Instalando..."

# ── 1. Criar usuário dedicado ─────────────────────────────────
if ! id "$AGENT_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin "$AGENT_USER"
    echo "==> Usuário '$AGENT_USER' criado."
else
    echo "==> Usuário '$AGENT_USER' já existe."
fi

# ── 2. Adicionar ao grupo named ───────────────────────────────
if getent group named &>/dev/null; then
    usermod -aG named "$AGENT_USER"
    echo "==> '$AGENT_USER' adicionado ao grupo 'named'."
else
    echo "AVISO: Grupo 'named' não encontrado. Ajuste manualmente as permissões do query.log."
fi

# ── 3. Instalar arquivos ──────────────────────────────────────
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")/../mondns-agent" && pwd)"
cp "$SCRIPT_DIR/agent.py" "$INSTALL_DIR/agent.py"
chmod 755 "$INSTALL_DIR/agent.py"
chown -R "$AGENT_USER:$AGENT_USER" "$INSTALL_DIR"
echo "==> Arquivos instalados em $INSTALL_DIR"

# ── 4. Criar arquivo de configuração ─────────────────────────
mkdir -p /etc/mondns-agent
chmod 750 /etc/mondns-agent
chown "$AGENT_USER:$AGENT_USER" /etc/mondns-agent

if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<'ENVEOF'
# mondns-agent — Configuração
# Edite este arquivo com os valores corretos e reinicie o serviço.

# URL do servidor mondns central (obrigatório)
MONDNS_URL=https://mondns.sondaativas.com.br

# API Key deste servidor (obter no painel Admin > Servidores DNS)
API_KEY=COLE_AQUI_A_API_KEY_DO_SERVIDOR

# Caminho do query.log do BIND
QUERY_LOG=/var/log/named/query.log

# Interface de rede monitorada
NETWORK_IFACE=eth1

# Intervalo de coleta em segundos
POLL_INTERVAL=5

# Nível de log: DEBUG | INFO | WARNING | ERROR
LOG_LEVEL=INFO
ENVEOF
    chmod 640 "$ENV_FILE"
    chown "$AGENT_USER:$AGENT_USER" "$ENV_FILE"
    echo "==> Arquivo de configuração criado: $ENV_FILE"
    echo ""
    echo "!!! IMPORTANTE: Edite $ENV_FILE e configure:"
    echo "    - MONDNS_URL: URL do servidor mondns"
    echo "    - API_KEY: chave gerada no painel (Admin > Servidores DNS)"
    echo "    - NETWORK_IFACE: interface de rede (ip -br l)"
else
    echo "==> Configuração existente preservada: $ENV_FILE"
fi

# ── 5. Instalar serviço systemd ───────────────────────────────
cat > /etc/systemd/system/${SERVICE_NAME}.service <<UNITEOF
[Unit]
Description=mondns DNS DDoS Monitor Agent
Documentation=https://mondns.sondaativas.com.br/about
After=network-online.target named.service
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadOnlyPaths=/var/log/named
ReadWritePaths=
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNITEOF

chmod 644 /etc/systemd/system/${SERVICE_NAME}.service
echo "==> Serviço systemd instalado."

# ── 6. Verificar permissão do query.log ──────────────────────
QUERY_LOG_PATH=$(grep "^QUERY_LOG=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"')
QUERY_LOG_PATH="${QUERY_LOG_PATH:-/var/log/named/query.log}"
QUERY_LOG_DIR=$(dirname "$QUERY_LOG_PATH")

if [ -d "$QUERY_LOG_DIR" ]; then
    chmod g+rx "$QUERY_LOG_DIR" 2>/dev/null || true
    chown :named "$QUERY_LOG_DIR" 2>/dev/null || true
    if [ -f "$QUERY_LOG_PATH" ]; then
        chmod g+r "$QUERY_LOG_PATH" 2>/dev/null || true
    fi
    echo "==> Permissões do diretório de log ajustadas: $QUERY_LOG_DIR"
fi

# ── 7. Habilitar e recarregar ─────────────────────────────────
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}

echo ""
echo "==> Instalação concluída!"
echo ""
echo "Próximos passos:"
echo "  1. Edite $ENV_FILE e configure MONDNS_URL e API_KEY"
echo "  2. Inicie o serviço: systemctl start ${SERVICE_NAME}"
echo "  3. Verifique os logs: journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "Comandos úteis:"
echo "  systemctl status ${SERVICE_NAME}"
echo "  systemctl restart ${SERVICE_NAME}"
echo "  journalctl -u ${SERVICE_NAME} --since '1 hour ago'"
