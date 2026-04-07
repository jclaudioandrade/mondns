#!/bin/bash
# ============================================================
# mondns-agent — Instalador
# Uso (como root):
#
#   1. Adicione a entrada no /etc/hosts (necessário para resolver o painel):
#        grep -qF 'mondns.sondaativas.com.br' /etc/hosts || \
#          echo '192.0.2.241     mondns.sondaativas.com.br' >> /etc/hosts
#
#   2. Só então execute o instalador:
#        curl -fsSL https://mondns.sondaativas.com.br/api/v1/agent/install.sh \
#          | MONDNS_API_TOKEN=<sua_api_key> bash
#
# Em um único bloco (copie e cole tudo de uma vez):
#
#   grep -qF 'mondns.sondaativas.com.br' /etc/hosts || \
#     echo '192.0.2.241     mondns.sondaativas.com.br' >> /etc/hosts
#   curl -fsSL https://mondns.sondaativas.com.br/api/v1/agent/install.sh \
#     | MONDNS_API_TOKEN=<sua_api_key> bash
# ============================================================
set -euo pipefail

MONDNS_API_URL="${MONDNS_API_URL:-https://mondns.sondaativas.com.br}"
MONDNS_API_TOKEN="${MONDNS_API_TOKEN:-${1:-}}"
AGENT_DIR="/opt/mondns-agent"
CONFIG_DIR="/etc/mondns-agent"
SERVICE_FILE="/etc/systemd/system/mondns-agent.service"
AGENT_URL="${MONDNS_API_URL}/api/v1/agent/agent.py"
NAMED_CONF="/etc/named.conf"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[mondns]${NC} $*"; }
warn()  { echo -e "${YELLOW}[mondns]${NC} $*"; }
error() { echo -e "${RED}[mondns] ERRO:${NC} $*" >&2; exit 1; }

# ── Validações ─────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || error "Execute como root: sudo bash install.sh"
[ -n "$MONDNS_API_TOKEN" ] || error "API Token não informado. Uso: bash install.sh <api_key>"
command -v python3 &>/dev/null || error "python3 não encontrado. Instale: dnf install python3"
command -v curl   &>/dev/null || error "curl não encontrado. Instale: dnf install curl"

info "Iniciando instalação do mondns-agent..."
info "API URL: ${MONDNS_API_URL}"

# ── 1. Criar usuário (idempotente) ─────────────────────────────────────────
if ! id mondns-agent &>/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin mondns-agent
    usermod -aG named mondns-agent
    info "Usuário mondns-agent criado (membro do grupo named)."
else
    # Garantir que está no grupo named mesmo em reinstalação
    usermod -aG named mondns-agent 2>/dev/null || true
    info "Usuário mondns-agent já existe."
fi

# ── 2. Criar diretórios ────────────────────────────────────────────────────
install -d -m 755 "$AGENT_DIR"
install -d -m 750 -o mondns-agent -g mondns-agent "$CONFIG_DIR"

# ── 3. Garantir resolução do painel em /etc/hosts ──────────────────────────
MONDNS_HOST="mondns.sondaativas.com.br"
MONDNS_IP="192.0.2.241"
if grep -qF "$MONDNS_HOST" /etc/hosts 2>/dev/null; then
    info "/etc/hosts já contém entrada para ${MONDNS_HOST}."
else
    echo "${MONDNS_IP}     ${MONDNS_HOST}" >> /etc/hosts
    info "Adicionado ao /etc/hosts: ${MONDNS_IP}  ${MONDNS_HOST}"
fi

# ── 4. Baixar agente ────────────────────────────────────────────────────────
info "Baixando agente de ${AGENT_URL}..."
curl -fsSL "$AGENT_URL" -o "${AGENT_DIR}/agent.py" || error "Falha ao baixar o agente."
chmod 644 "${AGENT_DIR}/agent.py"
info "Agente instalado em ${AGENT_DIR}/agent.py"

# ── 5. Escrever config.env com token ───────────────────────────────────────
# Não sobrescreve se já existir (preserva config manual)
if [ ! -f "${CONFIG_DIR}/config.env" ]; then
    cat > "${CONFIG_DIR}/config.env" <<EOF
# mondns-agent — Configuração gerada automaticamente
MONDNS_API_URL=${MONDNS_API_URL}
MONDNS_API_TOKEN=${MONDNS_API_TOKEN}
DNSTAP_SOCK=/var/run/named/dnstap.sock
WINDOW_SECONDS=10
LOG_LEVEL=INFO
EOF
    chown mondns-agent:mondns-agent "${CONFIG_DIR}/config.env"
    chmod 600 "${CONFIG_DIR}/config.env"
    info "config.env configurado."
else
    # Em reinstalação: atualizar token e URL mas preservar demais configs
    sed -i "s|^MONDNS_API_TOKEN=.*|MONDNS_API_TOKEN=${MONDNS_API_TOKEN}|" "${CONFIG_DIR}/config.env"
    sed -i "s|^MONDNS_API_URL=.*|MONDNS_API_URL=${MONDNS_API_URL}|" "${CONFIG_DIR}/config.env"
    info "config.env atualizado (token renovado)."
fi

# ── 6. Instalar serviço systemd ────────────────────────────────────────────
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=mondns DNS DDoS Monitor Agent
After=network.target named.service
Requires=named.service

[Service]
Type=simple
User=mondns-agent
Group=mondns-agent
EnvironmentFile=/etc/mondns-agent/config.env
ExecStart=/usr/bin/python3 /opt/mondns-agent/agent.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mondns-agent
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/run/named /opt/mondns-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mondns-agent
info "Serviço systemd habilitado."

# ── 6b. Sudoers para auto-update (restart sem senha) ───────────────────────
echo "mondns-agent ALL=(ALL) NOPASSWD: /bin/systemctl restart mondns-agent" \
    > /etc/sudoers.d/mondns-agent-update
chmod 440 /etc/sudoers.d/mondns-agent-update
info "Sudoers configurado para auto-update."

# ── 7. Permissão no diretório do socket ────────────────────────────────────
# O agente cria o socket em /var/run/named/ — o grupo named precisa ter escrita
if [ -d /var/run/named ]; then
    chmod g+w /var/run/named/
fi
# Tornar persistente após reboot (tmpfiles.d)
echo 'd /run/named 0775 named named -' > /etc/tmpfiles.d/named-mondns.conf
info "Permissões de /var/run/named configuradas."

# ── 8. Configurar dnstap no named.conf ─────────────────────────────────────
echo ""
if grep -q "dnstap" "$NAMED_CONF" 2>/dev/null; then
    info "dnstap já configurado em ${NAMED_CONF}."
    DNSTAP_OK=true
else
    warn "═══════════════════════════════════════════════════════════════"
    warn "  AÇÃO NECESSÁRIA: adicione as linhas abaixo DENTRO do bloco"
    warn "  options { } em ${NAMED_CONF}:"
    warn ""
    warn "      dnstap { all; };"
    warn "      dnstap-output unix \"/var/run/named/dnstap.sock\";"
    warn ""
    warn "  Verifique a sintaxe: named-checkconf /etc/named.conf"
    warn "═══════════════════════════════════════════════════════════════"
    DNSTAP_OK=false
fi

# ── 9. Iniciar agente e instruções finais ───────────────────────────────────
echo ""

# Parar serviço anterior se estiver rodando
systemctl stop mondns-agent 2>/dev/null || true

# Iniciar agente (ele cria o socket e aguarda o named conectar)
systemctl start mondns-agent
info "Agente iniciado — aguardando conexão do named."

echo ""
if [ "$DNSTAP_OK" = true ]; then
    warn "═══════════════════════════════════════════════════════════════"
    warn "  Execute agora para o named conectar ao agente:"
    warn ""
    warn "      systemctl restart named"
    warn ""
    warn "  Acompanhe os logs:"
    warn "      journalctl -u mondns-agent -f"
    warn "═══════════════════════════════════════════════════════════════"
else
    warn "═══════════════════════════════════════════════════════════════"
    warn "  Após configurar o named.conf, execute:"
    warn ""
    warn "      named-checkconf /etc/named.conf && systemctl restart named"
    warn "      journalctl -u mondns-agent -f"
    warn "═══════════════════════════════════════════════════════════════"
fi

echo ""
info "══════════════════════════════════════════"
info "  Instalação concluída!"
info "  Painel: ${MONDNS_API_URL}"
info "══════════════════════════════════════════"
