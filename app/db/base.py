from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# Importar todos os models aqui para que o Alembic os detecte
from app.models.user import User          # noqa: F401, E402
from app.models.server import DnsServer   # noqa: F401, E402
from app.models.metric import DnsMetric   # noqa: F401, E402
from app.models.attack import AttackEvent, AttackDetail  # noqa: F401, E402
from app.models.config import SystemConfig  # noqa: F401, E402
from app.models.audit import AuditLog     # noqa: F401, E402
