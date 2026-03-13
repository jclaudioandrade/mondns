from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.security import get_current_user_from_request
from app.config import settings

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

TECHNOLOGIES = [
    {"name": "Python 3.12", "desc": "Linguagem principal do backend"},
    {"name": "FastAPI 0.111", "desc": "Framework web assíncrono"},
    {"name": "SQLAlchemy 2.0", "desc": "ORM para acesso ao banco de dados"},
    {"name": "Alembic 1.13", "desc": "Migrations de banco de dados"},
    {"name": "PostgreSQL 15", "desc": "Banco de dados relacional (porta 5433)"},
    {"name": "Redis 7", "desc": "Cache e gerenciamento de sessões (porta 6380)"},
    {"name": "Pydantic v2", "desc": "Validação de dados e schemas"},
    {"name": "Passlib (bcrypt 12)", "desc": "Hash seguro de senhas"},
    {"name": "Podman + podman-compose", "desc": "Orquestração de containers"},
    {"name": "Nginx", "desc": "Proxy reverso (wildcard *.sondaativas.com.br)"},
    {"name": "BIND 9.11.36-RedHat", "desc": "Servidor DNS monitorado"},
    {"name": "Bootstrap 5.3", "desc": "Framework CSS responsivo"},
    {"name": "Chart.js 4", "desc": "Gráficos interativos"},
    {"name": "HTMX 1.9", "desc": "Atualizações parciais sem JavaScript complexo"},
]

CHANGELOG = [
    {
        "version": "0.2.0",
        "date": "2026-03-13",
        "items": [
            "Backend completo: modelos, migrations, autenticação por sessão",
            "Motor de detecção DDoS com 5 algoritmos independentes (QPS, NXDOMAIN, entropia de fontes, tipo de query, entropia de domínio)",
            "Score composto ponderado com thresholds configuráveis",
            "Endpoint de coleta para agentes (autenticação por API Key por servidor)",
            "Gerenciamento automático de eventos de ataque (abertura, atualização, fechamento)",
            "Dashboard web em tempo real (HTMX + Chart.js)",
            "Histórico de ataques com detalhamento por segundo",
            "Painel admin: usuários, configurações, thresholds, servidores, auditoria, retenção",
            "Log de auditoria de todas as ações relevantes",
            "Sistema de notificações: e-mail SMTP e webhook HTTP",
            "Agente mondns-agent para instalação nos slaves (Python + systemd)",
            "Script de instalação do agente (deploy/install-agent.sh)",
            "Retenção: métricas normais 1 ano, dados de ataque indefinidos (remoção manual admin)",
        ],
    },
    {
        "version": "0.1.0",
        "date": "2026-03-13",
        "items": [
            "Scaffold inicial: CLAUDE.md, .gitignore, .env.example",
            "podman-compose.yml com PostgreSQL 15 (5433), Redis 7 (6380), app (8002)",
            "Dockerfile multi-stage com usuário não-root (appuser UID 1001)",
            "Configuração Nginx para mondns.sondaativas.com.br",
            "Diretrizes de desenvolvimento: 12-Factor App, Security by Design",
        ],
    },
]


@router.get("/about", response_class=HTMLResponse)
def about_page(request: Request):
    user = get_current_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("about/index.html", {
        "request": request,
        "user": user,
        "app_version": settings.app_version,
        "technologies": TECHNOLOGIES,
        "changelog": CHANGELOG,
        "page_title": "Sobre",
    })
