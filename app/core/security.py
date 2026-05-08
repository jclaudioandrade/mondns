import uuid
import json
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

import bcrypt as _bcrypt
from sqlalchemy.orm import Session

from app.config import settings

SESSION_COOKIE = "mondns_session"
SESSION_PREFIX = "session:"
SESSION_EXPIRE_SECONDS = settings.session_expire_seconds


# ── Senhas ───────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


# ── Senha temporária ──────────────────────────────────────────────────────────

def generate_temp_password() -> str:
    """Gera senha temporária segura de 14 chars com complexidade garantida."""
    import string
    lc = string.ascii_lowercase
    uc = string.ascii_uppercase
    dg = string.digits
    sp = "!@#$%-_"
    # Garante ao menos 1 de cada categoria
    pwd = [
        secrets.choice(lc), secrets.choice(uc),
        secrets.choice(dg), secrets.choice(sp),
    ]
    alphabet = lc + uc + dg + sp
    pwd += [secrets.choice(alphabet) for _ in range(10)]
    # Embaralha de forma criptograficamente segura
    for i in range(len(pwd) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd[i], pwd[j] = pwd[j], pwd[i]
    return "".join(pwd)


# ── API Keys ──────────────────────────────────────────────────────────────────

def generate_api_key() -> str:
    """Gera uma API key segura de 40 hex chars."""
    return secrets.token_hex(32)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# ── Sessões (Redis) ───────────────────────────────────────────────────────────

def get_redis():
    """Lazy import para evitar dependência circular."""
    from app.services.cache import get_redis_client
    return get_redis_client()


def create_session(user_data: dict) -> str:
    session_id = str(uuid.uuid4())
    r = get_redis()
    r.setex(
        f"{SESSION_PREFIX}{session_id}",
        settings.session_expire_seconds,
        json.dumps(user_data),
    )
    return session_id


def get_session(session_id: str) -> Optional[dict]:
    r = get_redis()
    raw = r.get(f"{SESSION_PREFIX}{session_id}")
    if not raw:
        return None
    r.expire(f"{SESSION_PREFIX}{session_id}", settings.session_expire_seconds)
    return json.loads(raw)


def delete_session(session_id: str) -> None:
    r = get_redis()
    r.delete(f"{SESSION_PREFIX}{session_id}")


def get_active_sessions() -> list[dict]:
    """Retorna lista de usuários com sessão ativa (deduplicado por user id)."""
    r = get_redis()
    seen: set = set()
    result = []
    for key in r.scan_iter(f"{SESSION_PREFIX}*"):
        raw = r.get(key)
        if not raw:
            continue
        try:
            data = json.loads(raw)
            uid = data.get("id")
            if uid not in seen:
                seen.add(uid)
                result.append({
                    "username": data.get("username", ""),
                    "full_name": data.get("full_name") or data.get("username", ""),
                })
        except Exception:
            pass
    return result


# ── Password Reset Tokens (Redis) ────────────────────────────────────────────

RESET_TOKEN_PREFIX = "pwd_reset:"
RESET_TOKEN_TTL = 1800  # 30 minutos


def create_password_reset_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    r = get_redis()
    r.setex(f"{RESET_TOKEN_PREFIX}{token}", RESET_TOKEN_TTL, str(user_id))
    return token


def verify_password_reset_token(token: str) -> Optional[int]:
    """Retorna user_id se token válido, None caso contrário. Não consome o token."""
    r = get_redis()
    val = r.get(f"{RESET_TOKEN_PREFIX}{token}")
    if not val:
        return None
    return int(val)


def consume_password_reset_token(token: str) -> Optional[int]:
    """Valida e remove o token. Retorna user_id ou None."""
    user_id = verify_password_reset_token(token)
    if user_id is not None:
        get_redis().delete(f"{RESET_TOKEN_PREFIX}{token}")
    return user_id


# ── Autenticação Web ──────────────────────────────────────────────────────────

def authenticate_user(db: Session, username: str, password: str):
    from app.models.user import User
    user = db.query(User).filter(
        User.username == username,
        User.is_active == True,  # noqa: E712
    ).first()
    if not user or not verify_password(password, user.password_hash):
        return None
    return user


def get_current_user_from_request(request) -> Optional[dict]:
    """Extrai usuário da sessão a partir do cookie."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    return get_session(session_id)
