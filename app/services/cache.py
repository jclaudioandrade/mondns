import redis
from functools import lru_cache
from app.config import settings

_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(settings.redis_url, decode_responses=True)
    return _client


# ── Contadores em tempo real ──────────────────────────────────────────────────

def incr_counter(key: str, amount: int = 1, expire: int = 120) -> int:
    r = get_redis_client()
    val = r.incrby(key, amount)
    r.expire(key, expire)
    return val


def get_counter(key: str) -> int:
    r = get_redis_client()
    val = r.get(key)
    return int(val) if val else 0


def set_value(key: str, value: str, expire: int = 300) -> None:
    r = get_redis_client()
    r.setex(key, expire, value)


def get_value(key: str) -> str | None:
    return get_redis_client().get(key)


def delete_key(key: str) -> None:
    get_redis_client().delete(key)
