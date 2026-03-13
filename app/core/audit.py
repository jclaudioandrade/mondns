import json
import logging
from typing import Optional
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    action: str,
    username: str = "system",
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """
    Registra uma ação de auditoria:
    - Persiste no banco de dados
    - Emite para stdout com prefixo AUDIT: (12-Factor: logs para stdout)
    """
    from app.models.audit import AuditLog

    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(entry)
    db.commit()

    # stdout (12-Factor)
    audit_record = {
        "event": "AUDIT",
        "action": action,
        "username": username,
        "user_id": user_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "ip": ip_address,
        "details": details,
    }
    logger.info("AUDIT: %s", json.dumps(audit_record, default=str))


def get_client_ip(request) -> str:
    """Extrai o IP real do cliente (considera X-Forwarded-For do Nginx)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
