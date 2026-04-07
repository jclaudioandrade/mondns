"""
Endpoints para download e gerenciamento do mondns-agent.
Serve install.sh e agent.py diretamente da aplicação.
"""
import os
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_admin
from app.services.cache import get_redis_client
from app.api.v1.collect import CURRENT_AGENT_VERSION

router = APIRouter(prefix="/agent", tags=["agent-download"])

# Arquivos ficam em /app/agent/ dentro do container
AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "agent")

_FORCE_UPDATE_TTL = 300  # 5 minutos para o agente buscar a atualização


def _serve(filename: str, media_type: str):
    path = os.path.normpath(os.path.join(AGENT_DIR, filename))
    if not os.path.isfile(path):
        return PlainTextResponse("Arquivo não encontrado.", status_code=404)
    return FileResponse(path, media_type=media_type, filename=filename)


@router.get("/install.sh")
def download_install_script():
    return _serve("install.sh", "text/x-shellscript")


@router.get("/agent.py")
def download_agent():
    return _serve("agent.py", "text/x-python")


@router.get("/version")
def get_current_version():
    """Retorna a versão oficial atual do agente."""
    return {"version": CURRENT_AGENT_VERSION}


@router.post("/trigger-update/{server_id}")
def trigger_agent_update(
    server_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_api_admin),
):
    """
    Solicita atualização do agente no próximo ciclo de coleta.
    O agente verifica o flag na resposta do /collect e faz download+restart.
    """
    from app.models.server import DnsServer
    server = db.query(DnsServer).filter(DnsServer.id == server_id, DnsServer.is_active == True).first()  # noqa
    if not server:
        raise HTTPException(status_code=404, detail="Servidor não encontrado.")

    r = get_redis_client()
    r.setex(f"mondns:force_update:{server_id}", _FORCE_UPDATE_TTL, "1")

    return {"ok": True, "server_id": server_id, "message": "Atualização solicitada. O agente atualizará na próxima janela de coleta."}
