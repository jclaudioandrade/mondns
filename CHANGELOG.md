# Changelog — mondns

Todas as mudanças relevantes do projeto são documentadas neste arquivo.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/).
Versionamento segue [Semantic Versioning](https://semver.org/lang/pt-BR/).

---

## [0.1.0] — 2026-03-13

### Adicionado
- Scaffold inicial do projeto (CLAUDE.md, .gitignore, .env.example)
- Configuração de orquestração com `podman-compose.yml`
  - PostgreSQL 15 (porta dedicada 5433)
  - Redis 7 (porta dedicada 6380)
  - Aplicação mondns (porta dedicada 8002)
- `Dockerfile` multi-stage (development / production) com usuário não-root
- Configuração Nginx (`deploy/nginx.conf`) para `mondns.sondaativas.com.br`
  - Redirect HTTP → HTTPS
  - Certificado wildcard Sectigo
  - Headers de segurança HTTP (HSTS, CSP, X-Frame-Options, etc.)
- Scripts de entrypoint e healthcheck do container
- Estrutura base de diretórios da aplicação
- Diretrizes de desenvolvimento (CLAUDE.md) com:
  - 12-Factor App aplicado à stack
  - Security by Design
  - Isolamento de serviços (OpenShift-ready)
  - Página Sobre e política de versionamento

### Tecnologias
- Python 3.12 / FastAPI
- PostgreSQL 15
- Redis 7
- Podman + podman-compose
- Nginx (wildcard *.sondaativas.com.br)
- BIND 9.11.36-RedHat (integração)
- Alembic (migrations)
- Gunicorn + Uvicorn workers

---

## Versões Futuras (Roadmap)

- **0.2.0** — Backend: modelos, migrations, endpoints base, autenticação JWT
- **0.3.0** — Parser de logs BIND 9, detecção de anomalias DDoS
- **0.4.0** — Dashboard frontend (métricas em tempo real)
- **0.5.0** — Sistema de alertas (e-mail, webhook)
- **1.0.0** — Release estável com cobertura de testes completa
