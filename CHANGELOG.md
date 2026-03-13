# Changelog — mondns

Todas as mudanças relevantes do projeto são documentadas neste arquivo.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/).
Versionamento segue [Semantic Versioning](https://semver.org/lang/pt-BR/).

---

## [0.2.0] — 2026-03-13

### Adicionado
- Backend completo FastAPI com modelos SQLAlchemy 2.0 (User, DnsServer, DnsMetric, AttackEvent, AttackDetail, SystemConfig, AuditLog)
- Motor de detecção DDoS com 5 algoritmos independentes:
  - **QPS Threshold**: volume de queries/segundo vs threshold configurado
  - **NXDOMAIN Rate**: % de respostas NXDOMAIN (random subdomain attack)
  - **Source Entropy**: concentração/dispersão das fontes (flood vs botnet)
  - **Query Type Anomaly**: pico de ANY/TXT/RRSIG (amplificação)
  - **Domain Entropy**: entropia Shannon dos subdomínios (geração aleatória)
- Score composto ponderado (0–100) com classificação Normal/Suspeito/Ataque
- Endpoint `/api/v1/collect` para recebimento de métricas dos agentes (autenticação X-API-Key)
- Gerenciamento automático de AttackEvent (abertura, atualização, fechamento)
- Dashboard web em tempo real (HTMX polling + Chart.js)
- Autenticação por sessão Redis com HTTP-only cookie
- Grupos de usuários: `admin` e `analyst` com permissões distintas
- Painel Admin completo:
  - Gerenciamento de Usuários (CRUD)
  - Servidores DNS (registro + API Keys + rotação)
  - Thresholds de Detecção (editáveis em tempo real)
  - Configurações do Sistema (por grupo)
  - Notificações (SMTP + Webhook)
  - Log de Auditoria
  - Retenção de Dados (remoção manual admin)
- Histórico de ataques com timeline detalhada (QPS, score, NXDOMAIN, top IPs)
- Sistema de notificações: e-mail SMTP e webhook HTTP genérico
- Log de auditoria completo (banco + stdout prefixo `AUDIT:`)
- Página Sobre com versão, autor, tecnologias e changelog
- **mondns-agent**: agente Python puro (sem deps externas) para os slaves
  - Lê query.log do BIND em tempo real (tail -F)
  - Coleta stats de rede via /sys/class/net/
  - Sem necessidade de root em operação normal
- Script `deploy/install-agent.sh` para instalação nos slaves
- `migrations/env.py` configurado para DATABASE_URL via variável de ambiente

### Retenção de dados
- Métricas normais: 1 ano (DnsMetric)
- Dados de ataque: indefinidos (AttackEvent + AttackDetail) — remoção manual admin

---

## [0.1.0] — 2026-03-13

### Adicionado
- Scaffold inicial do projeto (CLAUDE.md, .gitignore, .env.example)
- Configuração de orquestração com `podman-compose.yml`
  - PostgreSQL 15 (porta dedicada 5433)
  - Redis 7 (porta dedicada 6380)
  - Aplicação mondns (porta dedicada 8003)
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
