"""
Instância centralizada de Jinja2Templates com filtros customizados.
Todos os módulos web devem importar `templates` daqui.
"""
from datetime import datetime, timezone, timedelta
from fastapi.templating import Jinja2Templates

# Brasília = UTC-3 fixo (Brasil aboliu horário de verão em 2019)
_BRT = timezone(timedelta(hours=-3))


def _as_brt(dt: datetime | None) -> datetime | None:
    """Converte datetime UTC → America/Sao_Paulo (UTC-3)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_BRT)


templates = Jinja2Templates(directory="app/templates")
templates.env.filters["as_brt"] = _as_brt
