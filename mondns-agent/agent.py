#!/usr/bin/env python3
"""
mondns-agent — Agente de coleta DNS DDoS
Instalar nos servidores DNS slave (dc1slvns01..04)

Lê o query.log do BIND em tempo real + stats de interface de rede.
Envia métricas para o servidor central mondns a cada POLL_INTERVAL segundos.

Permissões necessárias:
- Usuário mondns-agent no grupo 'named' (para ler query.log)
- Sem necessidade de root em operação normal

Autor: João Claudio de Faria Andrade <joao.andrade@sonda.com>
"""
import os
import re
import sys
import json
import time
import signal
import logging
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Configuração via variáveis de ambiente ────────────────────
MONDNS_URL       = os.environ.get("MONDNS_URL", "https://mondns.sondaativas.com.br")
API_KEY          = os.environ.get("API_KEY", "")
POLL_INTERVAL    = int(os.environ.get("POLL_INTERVAL", "5"))
QUERY_LOG        = os.environ.get("QUERY_LOG", "/var/log/named/query.log")
NETWORK_IFACE    = os.environ.get("NETWORK_IFACE", "eth1")
LOG_LEVEL        = os.environ.get("LOG_LEVEL", "INFO")
MAX_TOP_IPS      = int(os.environ.get("MAX_TOP_IPS", "20"))
MAX_TOP_DOMAINS  = int(os.environ.get("MAX_TOP_DOMAINS", "20"))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("mondns-agent")

# ── Regex para query.log do BIND 9 ───────────────────────────
# Formato: DD-Mon-YYYY HH:MM:SS.mmm client IP#port (domain): query: domain IN TYPE ...
# Também: client @ptr IP#port (domain): query: ...
QUERY_RE = re.compile(
    r"client\s+(?:@\S+\s+)?(\d+\.\d+\.\d+\.\d+)#\d+.*?query:\s+(\S+)\s+IN\s+(\S+)",
    re.IGNORECASE,
)
NXDOMAIN_RE = re.compile(r"NXDOMAIN", re.IGNORECASE)

# ── Leitura de estatísticas de rede ──────────────────────────

def read_net_stats(iface: str) -> tuple[int, int]:
    """Retorna (rx_packets, tx_packets) da interface."""
    try:
        rx = int(Path(f"/sys/class/net/{iface}/statistics/rx_packets").read_text())
        tx = int(Path(f"/sys/class/net/{iface}/statistics/tx_packets").read_text())
        return rx, tx
    except Exception as exc:
        logger.debug("Falha ao ler stats de rede: %s", exc)
        return 0, 0


# ── Seguidor de arquivo (tail -F equivalente) ─────────────────

class LogFollower:
    def __init__(self, path: str):
        self.path = path
        self._file = None
        self._inode = None
        self._open()

    def _open(self):
        try:
            self._file = open(self.path, "r")
            self._file.seek(0, 2)  # ir para o final
            self._inode = os.stat(self.path).st_ino
            logger.info("Monitorando: %s", self.path)
        except FileNotFoundError:
            logger.warning("Arquivo não encontrado: %s — aguardando...", self.path)
            self._file = None
            self._inode = None

    def readlines(self) -> list[str]:
        """Retorna novas linhas desde a última leitura."""
        if self._file is None:
            self._open()
            return []
        try:
            # Verificar rotação de log
            try:
                current_inode = os.stat(self.path).st_ino
                if current_inode != self._inode:
                    logger.info("Rotação de log detectada, reabrindo.")
                    self._file.close()
                    self._open()
                    if self._file is None:
                        return []
            except FileNotFoundError:
                return []

            lines = self._file.readlines()
            return [l.rstrip("\n") for l in lines if l]
        except Exception as exc:
            logger.error("Erro ao ler log: %s", exc)
            return []


# ── Agregador de métricas ─────────────────────────────────────

class MetricAggregator:
    def __init__(self):
        self.reset()

    def reset(self):
        self.query_count = 0
        self.nxdomain_count = 0
        self.query_types: dict[str, int] = defaultdict(int)
        self.source_ips: dict[str, int] = defaultdict(int)
        self.domains: list[str] = []

    def add_line(self, line: str):
        m = QUERY_RE.search(line)
        if m:
            ip, domain, qtype = m.group(1), m.group(2), m.group(3).upper()
            self.query_count += 1
            self.query_types[qtype] += 1
            self.source_ips[ip] += 1
            if len(self.domains) < 500:
                self.domains.append(domain)
        if NXDOMAIN_RE.search(line):
            self.nxdomain_count += 1

    def build_payload(self, qps: float, rx_pps: float, tx_pps: float) -> dict:
        nxdomain_rate = (
            (self.nxdomain_count / max(self.query_count, 1)) * 100.0
            if self.query_count > 0 else 0.0
        )
        top_ips = sorted(
            [{"ip": ip, "count": cnt} for ip, cnt in self.source_ips.items()],
            key=lambda x: x["count"], reverse=True
        )[:MAX_TOP_IPS]

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "qps": round(qps, 2),
            "query_count": self.query_count,
            "nxdomain_count": self.nxdomain_count,
            "nxdomain_rate": round(nxdomain_rate, 2),
            "rx_pps": round(rx_pps, 2),
            "tx_pps": round(tx_pps, 2),
            "query_types": dict(self.query_types),
            "top_source_ips": top_ips,
            "top_queried_domains": list(set(self.domains))[:MAX_TOP_DOMAINS],
        }


# ── Envio de métricas ─────────────────────────────────────────

def send_metrics(payload: dict) -> bool:
    url = f"{MONDNS_URL.rstrip('/')}/api/v1/collect"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "User-Agent": "mondns-agent/0.2.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            severity = result.get("severity", "unknown")
            score = result.get("score", 0)
            if severity != "normal":
                logger.warning("ALERTA servidor=%s severity=%s score=%.1f",
                               payload.get("timestamp", ""), severity, score)
            else:
                logger.debug("Métricas enviadas: qps=%.1f score=%.1f", payload["qps"], score)
            return True
    except urllib.error.HTTPError as exc:
        logger.error("HTTP %s ao enviar métricas: %s", exc.code, exc.read()[:200])
    except urllib.error.URLError as exc:
        logger.warning("Falha de conexão com %s: %s", MONDNS_URL, exc.reason)
    except Exception as exc:
        logger.error("Erro inesperado: %s", exc)
    return False


# ── Loop principal ────────────────────────────────────────────

_running = True


def handle_signal(sig, frame):
    global _running
    logger.info("Sinal %s recebido. Encerrando gracefully...", sig)
    _running = False


def main():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if not API_KEY:
        logger.error("API_KEY não configurada. Defina a variável de ambiente API_KEY.")
        sys.exit(1)

    logger.info("mondns-agent iniciando")
    logger.info("  Servidor mondns: %s", MONDNS_URL)
    logger.info("  Query log: %s", QUERY_LOG)
    logger.info("  Interface: %s", NETWORK_IFACE)
    logger.info("  Intervalo: %ss", POLL_INTERVAL)

    follower = LogFollower(QUERY_LOG)
    aggregator = MetricAggregator()
    rx_old, tx_old = read_net_stats(NETWORK_IFACE)

    while _running:
        start = time.monotonic()

        # Ler novas linhas do log
        lines = follower.readlines()
        for line in lines:
            aggregator.add_line(line)

        # Calcular métricas de rede
        rx_new, tx_new = read_net_stats(NETWORK_IFACE)
        elapsed = max(time.monotonic() - start, 0.001)
        rx_pps = (rx_new - rx_old) / elapsed
        tx_pps = (tx_new - tx_old) / elapsed
        qps = aggregator.query_count / elapsed
        rx_old, tx_old = rx_new, tx_new

        # Enviar
        if aggregator.query_count > 0 or rx_pps > 0:
            payload = aggregator.build_payload(qps, rx_pps, tx_pps)
            send_metrics(payload)
        else:
            # Enviar heartbeat mesmo sem queries
            payload = aggregator.build_payload(0, rx_pps, tx_pps)
            send_metrics(payload)

        aggregator.reset()

        # Dormir o restante do intervalo
        sleep_time = POLL_INTERVAL - (time.monotonic() - start)
        if sleep_time > 0 and _running:
            time.sleep(sleep_time)

    logger.info("mondns-agent encerrado.")


if __name__ == "__main__":
    main()
