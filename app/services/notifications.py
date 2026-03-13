"""
Serviço de notificações: e-mail SMTP e webhook HTTP.
Configurações lidas do banco (SystemConfig), nunca hardcoded.
"""
import json
import logging
import smtplib
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def _cfg(db: Session, key: str, default: str = "") -> str:
    from app.models.config import SystemConfig
    row = db.query(SystemConfig).filter(SystemConfig.config_key == key).first()
    return row.config_value if row else default


def send_attack_alert(db: Session, server_hostname: str, severity: str, score: float,
                      triggered: list[str], peak_qps: float) -> None:
    if _cfg(db, "notifications_enabled", "true").lower() != "true":
        return
    subject = f"[mondns] Ataque DDoS DNS detectado — {server_hostname} [{severity.upper()}]"
    body = (
        f"<h2>Alerta de Ataque DDoS DNS</h2>"
        f"<p><b>Servidor:</b> {server_hostname}</p>"
        f"<p><b>Severidade:</b> {severity.upper()}</p>"
        f"<p><b>Score:</b> {score:.1f}/100</p>"
        f"<p><b>Pico QPS:</b> {peak_qps:.0f}</p>"
        f"<p><b>Algoritmos disparados:</b> {', '.join(triggered)}</p>"
        f"<p>Acesse o painel mondns para detalhes.</p>"
    )
    _send_email(db, subject, body)
    _send_webhook(db, {"event": "attack_detected", "server": server_hostname,
                       "severity": severity, "score": score, "peak_qps": peak_qps})


def _send_email(db: Session, subject: str, html_body: str) -> None:
    host = _cfg(db, "smtp_host")
    if not host:
        logger.debug("SMTP não configurado, e-mail não enviado.")
        return
    try:
        port = int(_cfg(db, "smtp_port", "587"))
        user = _cfg(db, "smtp_user")
        password = _cfg(db, "smtp_password")
        from_addr = _cfg(db, "smtp_from", "mondns@sondaativas.com.br")
        to_raw = _cfg(db, "alert_email_to")
        recipients = [r.strip() for r in to_raw.split(",") if r.strip()]
        if not recipients:
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.sendmail(from_addr, recipients, msg.as_string())
        logger.info("E-mail de alerta enviado para %s", recipients)
    except Exception as exc:
        logger.error("Falha ao enviar e-mail: %s", exc)


def _send_webhook(db: Session, payload: dict) -> None:
    url = _cfg(db, "webhook_url")
    if not url:
        return
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5):
            pass
        logger.info("Webhook enviado para %s", url)
    except Exception as exc:
        logger.error("Falha ao enviar webhook: %s", exc)
