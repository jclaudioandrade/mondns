#!/usr/bin/env python3
"""
mondns-agent v0.2.0 — Coletor de métricas BIND via dnstap
==========================================================
Roda nas VMs DNS como usuário mondns-agent (membro do grupo named).
Lê frames dnstap do socket Unix do BIND, agrega métricas por janela de
tempo e envia para a API central do mondns.

Dependências: apenas Python 3.6+ stdlib (sem pip necessário).

Variáveis de ambiente (carregadas de /etc/mondns-agent/config.env):
    MONDNS_API_URL      URL base da API (ex: https://mondns.sondaativas.com.br)
    MONDNS_API_TOKEN    API key do servidor (X-API-Key)
    DNSTAP_SOCK         Path do socket dnstap (padrão: /var/run/named/dnstap.sock)
    WINDOW_SECONDS      Janela de agregação em segundos (padrão: 10)
    LOG_LEVEL           DEBUG|INFO|WARNING (padrão: INFO)
"""

import os
import sys
import socket
import struct
import time
import json
import signal
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.request import urlopen, Request as URLRequest
from urllib.error import URLError, HTTPError

# ── Configuração ──────────────────────────────────────────────────────────────

API_URL     = os.environ.get("MONDNS_API_URL", "").rstrip("/")
API_TOKEN   = os.environ.get("MONDNS_API_TOKEN", "")
DNSTAP_SOCK = os.environ.get("DNSTAP_SOCK", "/var/run/named/dnstap.sock")
WINDOW_SEC  = int(os.environ.get("WINDOW_SECONDS", "10"))
LOG_LEVEL   = os.environ.get("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("mondns-agent")

AGENT_VERSION = "0.3.2"
RUNNING = True


def _stop(sig, _):
    global RUNNING
    RUNNING = False
    log.info("Recebido sinal %s — encerrando…", sig)


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)

# ── FSTRM (Frame Streams) ─────────────────────────────────────────────────────
# Protocolo usado pelo BIND para enviar frames dnstap via socket Unix.
# Ref: https://farsightsec.github.io/fstrm/

FSTRM_ACCEPT       = 1
FSTRM_START        = 2
FSTRM_STOP         = 3
FSTRM_READY        = 4
FSTRM_FINISH       = 5
FSTRM_FIELD_CTYPE  = 1
DNSTAP_CTYPE       = b"protobuf:dnstap.Dnstap"


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo named")
        buf += chunk
    return buf


def _read_frame(sock):
    """Lê um frame FSTRM. Retorna (is_control, data_bytes)."""
    length = struct.unpack("!I", _recv_exact(sock, 4))[0]
    if length == 0:
        # Frame de controle: próximos 4 bytes são o tamanho do conteúdo
        ctrl_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
        return True, _recv_exact(sock, ctrl_len)
    return False, _recv_exact(sock, length)


def _parse_ctrl(data):
    """Retorna (ctrl_type, content_type_bytes_or_None)."""
    if len(data) < 4:
        return 0, None
    ctrl_type = struct.unpack("!I", data[:4])[0]
    pos, ctype = 4, None
    while pos + 8 <= len(data):
        ft = struct.unpack("!I", data[pos:pos+4])[0]
        fl = struct.unpack("!I", data[pos+4:pos+8])[0]
        pos += 8
        if ft == FSTRM_FIELD_CTYPE:
            ctype = data[pos:pos+fl]
        pos += fl
    return ctrl_type, ctype


def _send_ctrl(sock, ctrl_type, content_type=None):
    """Envia um frame de controle FSTRM."""
    body = struct.pack("!I", ctrl_type)
    if content_type:
        body += struct.pack("!II", FSTRM_FIELD_CTYPE, len(content_type))
        body += content_type
    frame = struct.pack("!II", 0, len(body)) + body
    sock.sendall(frame)


def fstrm_handshake(sock):
    """
    Handshake bidirecional FSTRM:
      named → READY
      agent → ACCEPT
      named → START
      (dados fluem)
    """
    is_ctrl, data = _read_frame(sock)
    if not is_ctrl:
        raise RuntimeError("Esperava frame de controle READY")
    ctrl_type, ctype = _parse_ctrl(data)
    if ctrl_type != FSTRM_READY:
        raise RuntimeError(f"Esperava READY, recebeu tipo {ctrl_type}")
    if ctype != DNSTAP_CTYPE:
        raise RuntimeError(f"Content-type inesperado: {ctype}")

    _send_ctrl(sock, FSTRM_ACCEPT, DNSTAP_CTYPE)
    log.debug("ACCEPT enviado")

    is_ctrl, data = _read_frame(sock)
    if not is_ctrl:
        raise RuntimeError("Esperava frame de controle START")
    ctrl_type, _ = _parse_ctrl(data)
    if ctrl_type != FSTRM_START:
        raise RuntimeError(f"Esperava START, recebeu tipo {ctrl_type}")

    log.info("Handshake FSTRM concluído — recebendo frames dnstap")


# ── Protobuf mínimo ───────────────────────────────────────────────────────────
# Parser manual sem dependências externas.

def _varint(buf, pos):
    """Decodifica varint protobuf. Retorna (valor, novo_pos)."""
    result, shift = 0, 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Varint truncado")


def _pb_parse(buf):
    """
    Parser protobuf minimalista.
    Retorna dict: field_number → list[valor]
    Valores: int para varint/fixed, bytes para length-delimited.
    """
    fields = defaultdict(list)
    pos = 0
    while pos < len(buf):
        tag, pos = _varint(buf, pos)
        fn = tag >> 3
        wt = tag & 0x7
        if wt == 0:       # varint
            v, pos = _varint(buf, pos)
            fields[fn].append(v)
        elif wt == 1:     # 64-bit fixo
            fields[fn].append(struct.unpack_from("<Q", buf, pos)[0])
            pos += 8
        elif wt == 2:     # length-delimited (string/bytes/sub-message)
            ln, pos = _varint(buf, pos)
            fields[fn].append(buf[pos:pos+ln])
            pos += ln
        elif wt == 5:     # 32-bit fixo
            fields[fn].append(struct.unpack_from("<I", buf, pos)[0])
            pos += 4
        else:
            break  # wire type desconhecido
    return fields


# ── DNS wire format ───────────────────────────────────────────────────────────

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
    257: "CAA", 48: "DNSKEY", 43: "DS", 46: "RRSIG",
}


def _parse_qname(buf, pos):
    """
    Decodifica um QNAME do wire format DNS.
    Retorna (qname_str, pos_after_qname).
    Suporta ponteiros de compressão (sem seguir recursivamente).
    """
    labels = []
    while pos < len(buf):
        length = buf[pos]
        pos += 1
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            # Ponteiro de compressão — não seguir, só registrar
            pos += 1
            break
        end = pos + length
        labels.append(buf[pos:end].decode("ascii", errors="replace"))
        pos = end
    return ".".join(labels).lower() or ".", pos


def _dns_question(buf):
    """
    Extrai QNAME e QTYPE do wire format DNS.
    Retorna (qname, qtype_str) ou (None, None).
    """
    if len(buf) < 12:
        return None, None
    qdcount = struct.unpack_from("!H", buf, 4)[0]
    if qdcount == 0:
        return None, None
    try:
        qname, pos = _parse_qname(buf, 12)
        if pos + 2 > len(buf):
            return qname, None
        qtype_raw = struct.unpack_from("!H", buf, pos)[0]
        return qname, QTYPES.get(qtype_raw, str(qtype_raw))
    except Exception:
        return None, None


def _dns_rcode(buf):
    """Extrai RCODE do cabeçalho DNS (bits 0-3 do último nibble do byte 3)."""
    if len(buf) < 4:
        return -1
    return buf[3] & 0x0F


# ── Parser dnstap ─────────────────────────────────────────────────────────────
#
# Campos relevantes do proto dnstap.Dnstap (outer):
#   field 14 → DnstapMessage (submessage)
#
# Campos de DnstapMessage (dnstap.proto padrão):
#   field 1  → type (uint32)  AUTH_QUERY=1, AUTH_RESPONSE=2, CLIENT_QUERY=5, CLIENT_RESPONSE=6
#   field 2  → socket_family  (1=AF_INET, 2=AF_INET6)
#   field 3  → socket_protocol (1=UDP, 2=TCP)
#   field 4  → query_address   (bytes — IP do cliente)
#   field 5  → response_address (bytes — IP local do servidor DNS)
#   field 6  → query_port      (uint32)
#   field 7  → response_port   (uint32)
#   field 8  → query_time_sec  (uint64)
#   field 9  → query_time_nsec (fixed32)
#   field 10 → query_message   (bytes — DNS wire format da query)
#   field 12 → response_time_sec  (uint64)
#   field 13 → response_time_nsec (fixed32)
#   field 14 → response_message   (bytes — DNS wire format da resposta)

# Valores conforme dnstap.proto padrão (farsightsec) — estáveis em todas versões do BIND:
#   AUTH_QUERY=1, AUTH_RESPONSE=2, RESOLVER_QUERY=3, RESOLVER_RESPONSE=4
#   CLIENT_QUERY=5, CLIENT_RESPONSE=6
MSG_AUTH_QUERY      = 1   # Query recebida pelo servidor autoritativo
MSG_AUTH_RESPONSE   = 2   # Resposta enviada pelo servidor autoritativo
MSG_CLIENT_QUERY    = 5   # Query recebida de um cliente (resolver/stub)
MSG_CLIENT_RESPONSE = 6   # Resposta enviada ao cliente


_DEBUG_FIELDS = os.environ.get("MONDNS_DEBUG_FIELDS", "0").lower() in ("1", "true", "yes")
_debug_count = 0   # limita a quantidade de frames logados

_MSG_QUERY_TYPES    = (MSG_CLIENT_QUERY, MSG_AUTH_QUERY)
_MSG_RESPONSE_TYPES = (MSG_CLIENT_RESPONSE, MSG_AUTH_RESPONSE)
_MSG_ALL_TYPES      = _MSG_QUERY_TYPES + _MSG_RESPONSE_TYPES


def parse_dnstap(buf):
    """
    Parseia um frame dnstap completo.
    Retorna dict com os campos ou None se não for relevante.
    Aceita CLIENT_QUERY/RESPONSE (5/6) e AUTH_QUERY/RESPONSE (7/8).
    """
    global _debug_count
    top = _pb_parse(buf)
    if 14 not in top:
        return None

    msg = _pb_parse(top[14][0])
    msg_type = msg.get(1, [0])[0]

    if msg_type not in _MSG_ALL_TYPES:
        log.debug("FRAME_DESCARTADO tipo=%d", msg_type)
        return None

    # Debug: loga campos brutos do DnstapMessage (primeiros 20 frames)
    if _DEBUG_FIELDS and _debug_count < 20:
        _debug_count += 1
        field_dump = {
            fn: (
                [v.hex() if isinstance(v, bytes) else v for v in vals]
            )
            for fn, vals in sorted(msg.items())
        }
        log.info("DNSTAP_FIELDS type=%s fields=%s", msg_type, field_dump)

    def _extract_ip(raw):
        if not isinstance(raw, bytes) or not raw:
            return None
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
        if len(raw) == 16:
            return ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))
        return None

    # Campo 4 = query_address = IP do cliente (verificado no BIND 9.11)
    src_ip = _extract_ip(msg.get(4, [None])[0])

    # Timestamp: field 8 = query_time_sec, field 12 = response_time_sec
    ts = msg.get(8, msg.get(12, [int(time.time())]))[0]

    if msg_type in _MSG_QUERY_TYPES:
        dns_bytes = msg.get(10, [None])[0]   # field 10 = query_message
        if not isinstance(dns_bytes, bytes):
            dns_bytes = None
        qname, qtype = _dns_question(dns_bytes) if dns_bytes else (None, None)
        return {
            "type": "query",
            "src_ip": src_ip,
            "is_client": msg_type == MSG_CLIENT_QUERY,  # AUTH_QUERY tem IP do próprio BIND
            "qname": qname,
            "qtype": qtype,
            "ts": ts,
            "nxdomain": False,
        }

    if msg_type in _MSG_RESPONSE_TYPES:
        dns_bytes = msg.get(14, [None])[0]
        if not isinstance(dns_bytes, bytes):
            dns_bytes = None
        rcode = _dns_rcode(dns_bytes) if dns_bytes else -1
        qname, qtype = _dns_question(dns_bytes) if dns_bytes else (None, None)
        return {
            "type": "response",
            "src_ip": src_ip,
            "is_client": msg_type == MSG_CLIENT_RESPONSE,
            "qname": qname,
            "qtype": qtype,
            "ts": ts,
            "nxdomain": rcode == 3,
        }

    return None


# ── Agregador de métricas ─────────────────────────────────────────────────────

class Window:
    """
    Agrega eventos dnstap numa janela de tempo e produz o payload
    pronto para POST na API do mondns.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.start            = time.time()
        self.query_count      = 0
        self.response_count   = 0
        self.nxdomain_count   = 0
        self.frames_discarded = 0
        self.src_ips          = Counter()
        self.qtypes           = Counter()
        self.qnames           = Counter()
        self.nxdomain_domains = Counter()

    def add(self, event):
        if event["type"] == "query":
            self.query_count += 1
            # AUTH_QUERY contém o IP do resolver externo (o atacante) — rastrear todos
            if event["src_ip"]:
                self.src_ips[event["src_ip"]] += 1
            if event["qtype"]:
                self.qtypes[event["qtype"]] += 1
            if event["qname"]:
                self.qnames[event["qname"]] += 1
        else:  # response
            self.response_count += 1
            if event["nxdomain"]:
                self.nxdomain_count += 1
                if event["qname"]:
                    self.nxdomain_domains[event["qname"]] += 1

    def flush(self):
        elapsed = max(time.time() - self.start, 1.0)
        # QPS baseado em queries (CLIENT_QUERY), não responses
        qps     = self.query_count / elapsed
        # NXDOMAIN rate: denominador = responses (não o total de frames)
        nxrate  = min((self.nxdomain_count / max(self.response_count, 1)) * 100, 100.0)

        payload = {
            "agent_version":     AGENT_VERSION,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "qps":               round(qps, 2),
            "query_count":       self.query_count,
            "nxdomain_count":    self.nxdomain_count,
            "nxdomain_rate":     round(nxrate, 2),
            "rx_pps":            0.0,
            "tx_pps":            0.0,
            "query_types":       dict(self.qtypes.most_common(20)),
            "top_source_ips":    [{"ip": ip, "count": c}
                                  for ip, c in self.src_ips.most_common(20)],
            "top_queried_domains":  [{"domain": d, "count": c} for d, c in self.qnames.most_common(20)],
            "top_nxdomain_domains": [{"domain": d, "count": c} for d, c in self.nxdomain_domains.most_common(20)],
            "frames_discarded":    self.frames_discarded,
        }
        self.reset()
        return payload


# ── HTTP POST ─────────────────────────────────────────────────────────────────

def post_metrics(payload):
    """Envia métricas para o servidor. Retorna o body da resposta ou None em caso de erro."""
    data = json.dumps(payload).encode()
    req = URLRequest(
        f"{API_URL}/api/v1/collect",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key":    API_TOKEN,
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            log.info(
                "metrics enviadas — qps=%.1f nxdomain_rate=%.1f%% score=%s severity=%s update=%s frames_ok=%d frames_descartados=%d",
                payload["qps"], payload["nxdomain_rate"],
                body.get("score"), body.get("severity"),
                body.get("update_available", False),
                payload["query_count"], payload.get("frames_discarded", 0),
            )
            return body
    except HTTPError as exc:
        log.error("POST HTTP %s: %s", exc.code, exc.read()[:300])
    except URLError as exc:
        log.error("POST URLError: %s", exc.reason)
    except Exception as exc:
        log.error("POST erro inesperado: %s", exc)
    return None


def self_update():
    """
    Baixa nova versão do agente, substitui o arquivo atual e reinicia via systemd.
    Requer: ReadWritePaths=/opt/mondns-agent no service e sudoers para systemctl restart.
    """
    import subprocess
    agent_path = os.path.abspath(__file__)
    tmp_path = agent_path + ".new"
    download_url = f"{API_URL}/api/v1/agent/agent.py"

    log.info("AUTO-UPDATE: iniciando download de %s", download_url)
    try:
        req = URLRequest(download_url)
        with urlopen(req, timeout=30) as resp:
            data = resp.read()

        if len(data) < 1000 or b"mondns" not in data:
            log.error("AUTO-UPDATE: arquivo baixado parece inválido (%d bytes) — abortando.", len(data))
            return

        with open(tmp_path, "wb") as f:
            f.write(data)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, agent_path)
        log.info("AUTO-UPDATE: arquivo substituído em %s. Reiniciando serviço...", agent_path)

        subprocess.Popen(["sudo", "/usr/bin/systemctl", "restart", "mondns-agent"])

    except PermissionError:
        log.error(
            "AUTO-UPDATE: sem permissão para escrever em %s. "
            "Adicione ReadWritePaths=/opt/mondns-agent ao service e execute: "
            "sudo systemctl daemon-reload && sudo systemctl restart mondns-agent",
            agent_path,
        )
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    except Exception as exc:
        log.error("AUTO-UPDATE: falha — %s", exc)
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


# ── Loop principal ────────────────────────────────────────────────────────────
#
# No BIND 9.11, o named é o CLIENTE do socket dnstap:
#   - O agente cria o socket Unix e escuta (servidor)
#   - O named conecta ao socket (cliente/writer)
#   - O named envia READY → agente responde ACCEPT → named envia START → dados fluem

def _create_server_socket():
    """Cria o socket Unix no caminho configurado e retorna o socket servidor."""
    import grp
    # Remover socket anterior se existir
    if os.path.exists(DNSTAP_SOCK):
        os.unlink(DNSTAP_SOCK)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(DNSTAP_SOCK)
    # Mudar grupo para 'named' para que o named possa conectar
    try:
        named_gid = grp.getgrnam("named").gr_gid
        os.chown(DNSTAP_SOCK, -1, named_gid)
    except KeyError:
        log.warning("Grupo 'named' não encontrado — socket pode não ser acessível pelo named")
    # Permissão 0660: owner (mondns-agent) + group (named) podem ler/escrever
    os.chmod(DNSTAP_SOCK, 0o660)
    srv.listen(1)
    return srv


def run():
    window     = Window()
    next_flush = time.time() + WINDOW_SEC
    conn       = None
    server     = None

    log.info(
        "mondns-agent v%s | socket=%s window=%ds api=%s",
        AGENT_VERSION,
        DNSTAP_SOCK, WINDOW_SEC, API_URL,
    )

    while RUNNING:
        try:
            # Criar socket e aguardar named conectar
            server = _create_server_socket()
            log.info("Socket criado, aguardando conexão do named: %s", DNSTAP_SOCK)
            server.settimeout(5.0)

            while RUNNING:
                try:
                    conn, _ = server.accept()
                    break
                except socket.timeout:
                    continue

            if not RUNNING:
                break

            log.info("named conectado — iniciando handshake FSTRM")
            conn.settimeout(2.0)
            fstrm_handshake(conn)

            while RUNNING:
                # Flush da janela de tempo
                if time.time() >= next_flush:
                    payload    = window.flush()
                    next_flush = time.time() + WINDOW_SEC
                    resp = post_metrics(payload)
                    if resp and (resp.get("force_update") or resp.get("update_available")):
                        log.warning("AUTO-UPDATE: nova versão disponível (%s → %s).",
                                    AGENT_VERSION, resp.get("current_version", "?"))
                        self_update()

                # Leitura com timeout para não bloquear o flush
                try:
                    is_ctrl, data = _read_frame(conn)
                except socket.timeout:
                    continue
                except ConnectionError:
                    log.warning("Conexão encerrada pelo named.")
                    break

                if is_ctrl:
                    ctrl_type, _ = _parse_ctrl(data)
                    if ctrl_type in (FSTRM_STOP, FSTRM_FINISH):
                        log.info("STOP/FINISH recebido — encerrando sessão.")
                        try:
                            _send_ctrl(conn, FSTRM_FINISH)
                        except Exception:
                            pass
                        break
                    continue

                # Frame de dados — parsear dnstap
                event = parse_dnstap(data)
                if event:
                    window.add(event)
                else:
                    window.frames_discarded += 1

        except Exception as exc:
            log.error("Erro: %s — reiniciando em 5s…", exc)
        finally:
            for s in (conn, server):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
            conn = server = None
            # Remover socket do disco ao encerrar sessão
            try:
                if os.path.exists(DNSTAP_SOCK):
                    os.unlink(DNSTAP_SOCK)
            except Exception:
                pass

        if RUNNING:
            time.sleep(5)

    log.info("mondns-agent encerrado.")


# ── Entrada ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    missing = [v for v in ("MONDNS_API_URL", "MONDNS_API_TOKEN") if not os.environ.get(v)]
    if missing:
        log.critical("Variáveis obrigatórias ausentes: %s", ", ".join(missing))
        sys.exit(1)
    run()
