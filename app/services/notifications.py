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


def _smtp_connect(host: str, port: int, user: str, password: str):
    """
    Cria e retorna uma conexão SMTP já autenticada (se necessário).
    Adapta-se automaticamente ao servidor:
      - Porta 465 → SSL direto
      - Outras portas → tenta STARTTLS apenas se o servidor anunciar
      - Login apenas se servidor anunciar AUTH e user estiver configurado
    """
    if port == 465:
        smtp = smtplib.SMTP_SSL(host, port, timeout=10)
    else:
        smtp = smtplib.SMTP(host, port, timeout=10)
        smtp.ehlo()
        # STARTTLS apenas se o servidor suportar
        if smtp.has_extn("STARTTLS"):
            smtp.starttls()
            smtp.ehlo()

    # Login apenas se o servidor anunciar AUTH e credenciais estiverem definidas
    if user and smtp.has_extn("AUTH"):
        smtp.login(user, password)

    return smtp


def send_attack_alert(db: Session, server_hostname: str, severity: str, score: float,
                      triggered: list[str], peak_qps: float) -> None:
    if _cfg(db, "notifications_enabled", "true").lower() != "true":
        return
    subject = f"[mondns] Ataque DDoS DNS detectado — {server_hostname} [{severity.upper()}]"
    dashboard_url = "https://mondns.sondaativas.com.br"
    body = (
        f"<h2>Alerta de Ataque DDoS DNS</h2>"
        f"<p><b>Servidor:</b> {server_hostname}</p>"
        f"<p><b>Severidade:</b> {severity.upper()}</p>"
        f"<p><b>Score:</b> {score:.1f}/100</p>"
        f"<p><b>Pico QPS:</b> {peak_qps:.0f}</p>"
        f"<p><b>Algoritmos disparados:</b> {', '.join(triggered)}</p>"
        f"<p><a href=\"{dashboard_url}/attacks\">Acesse o painel mondns para detalhes</a></p>"
        f"<p style=\"color:#888;font-size:.9em\">{dashboard_url}</p>"
    )
    _send_email(db, subject, body)
    _send_webhook(db, {"event": "attack_detected", "server": server_hostname,
                       "severity": severity, "score": score, "peak_qps": peak_qps})


def send_welcome_email(db: Session, to_email: str, username: str,
                       full_name: str, temp_password: str) -> bool:
    """Envia e-mail de boas-vindas com senha temporária. Retorna True se enviado."""
    subject = "[mondns] Seu acesso ao mondns foi criado"
    body = (
        f"<p>Olá, <b>{full_name}</b>!</p>"
        "<p>Seu acesso ao <b>mondns — DNS DDoS Monitor</b> foi criado.</p>"
        "<table style='border-collapse:collapse;margin:16px 0'>"
        f"<tr><td style='padding:4px 12px 4px 0;color:#888'>Usuário:</td>"
        f"<td><code style='background:#f1f5f9;padding:2px 6px;border-radius:4px'>{username}</code></td></tr>"
        f"<tr><td style='padding:4px 12px 4px 0;color:#888'>Senha temporária:</td>"
        f"<td><code style='background:#f1f5f9;padding:2px 6px;border-radius:4px'>{temp_password}</code></td></tr>"
        "</table>"
        "<p><b>Importante:</b> no primeiro acesso você será obrigado a definir uma nova senha.</p>"
        '<p><a href="https://mondns.sondaativas.com.br/login" '
        'style="background:#2563eb;color:#fff;padding:10px 20px;border-radius:6px;'
        'text-decoration:none;display:inline-block">Acessar mondns</a></p>'
        "<p style='color:#888;font-size:.85em'>mondns — DNS DDoS Monitor | "
        "mondns.sondaativas.com.br</p>"
    )
    host = _cfg(db, "smtp_host")
    if not host:
        logger.warning("SMTP não configurado — e-mail de boas-vindas não enviado para %s", to_email)
        return False
    try:
        port = int(_cfg(db, "smtp_port", "587"))
        user = _cfg(db, "smtp_user")
        password = _cfg(db, "smtp_password")
        from_addr = _cfg(db, "smtp_from", "mondns@sondaativas.com.br")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_email
        msg.attach(MIMEText(body, "html"))

        smtp = _smtp_connect(host, port, user, password)
        try:
            smtp.sendmail(from_addr, [to_email], msg.as_string())
        finally:
            smtp.quit()
        logger.info("E-mail de boas-vindas enviado para %s", to_email)
        return True
    except Exception as exc:
        logger.error("Falha ao enviar e-mail de boas-vindas: %s", exc)
        return False


def send_password_reset_email(db: Session, to_email: str, reset_url: str) -> bool:
    """Envia e-mail com link de redefinição de senha. Retorna True se enviado."""
    subject = "[mondns] Redefinição de senha"
    body = (
        "<p>Você (ou alguém em seu nome) solicitou a redefinição de senha no <b>mondns</b>.</p>"
        f'<p><a href="{reset_url}" style="background:#2563eb;color:#fff;padding:10px 20px;'
        'border-radius:6px;text-decoration:none;display:inline-block">Redefinir minha senha</a></p>'
        "<p>Este link expira em <b>30 minutos</b>.</p>"
        "<p>Se você não solicitou, ignore este e-mail. Sua senha permanece inalterada.</p>"
        f'<p style="color:#888;font-size:.85em">Link direto: {reset_url}</p>'
        '<p style="color:#888;font-size:.85em">mondns — DNS DDoS Monitor | '
        'mondns.sondaativas.com.br</p>'
    )
    host = _cfg(db, "smtp_host")
    if not host:
        logger.warning("SMTP não configurado — e-mail de reset não enviado para %s", to_email)
        return False
    try:
        port = int(_cfg(db, "smtp_port", "587"))
        user = _cfg(db, "smtp_user")
        password = _cfg(db, "smtp_password")
        from_addr = _cfg(db, "smtp_from", "mondns@sondaativas.com.br")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_email
        msg.attach(MIMEText(body, "html"))

        smtp = _smtp_connect(host, port, user, password)
        try:
            smtp.sendmail(from_addr, [to_email], msg.as_string())
        finally:
            smtp.quit()
        logger.info("E-mail de reset de senha enviado para %s", to_email)
        return True
    except Exception as exc:
        logger.error("Falha ao enviar e-mail de reset: %s", exc)
        return False


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

        smtp = _smtp_connect(host, port, user, password)
        try:
            smtp.sendmail(from_addr, recipients, msg.as_string())
        finally:
            smtp.quit()
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
