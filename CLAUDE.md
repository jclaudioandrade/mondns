# CLAUDE.md — Diretrizes Obrigatórias do Projeto mondns

> Este arquivo governa TODAS as respostas e decisões técnicas neste projeto.
> Leia-o integralmente antes de qualquer ação de código.

---

## 1. Objetivo do Projeto

Monitorar ataques DDoS aos servidores DNS, integrado ao BIND 9.11.36-RedHat.
Ambiente atual: VM VMware Linux compartilhado. Migração futura planejada para Red Hat OpenShift.

---

## 2. Arquitetura e Stack

| Camada         | Tecnologia                                      |
|----------------|-------------------------------------------------|
| Backend        | Python 3.12 (FastAPI ou Flask)                  |
| Banco de dados | PostgreSQL 15 — porta dedicada 5433             |
| Cache          | Redis 7 — porta dedicada 6380                   |
| Container      | Podman + podman-compose (NÃO Docker)            |
| Web server     | Nginx compartilhado (wildcard *.sondaativas.com.br, Sectigo, válido até 2027) |
| DNS Integration| BIND 9.11.36-RedHat-9.11.36-5.el8_7.2          |
| Porta da app   | 8002 (localhost only, atrás do Nginx)           |
| Subdomínio     | mondns.sondaativas.com.br                       |

---

## 3. Os 12 Princípios do 12-Factor App

### I. Codebase
- Um repositório Git por aplicação. Branch principal: `main`.

### II. Dependências
- Todas as dependências declaradas em `requirements.txt` com versões fixadas (pin exato).
- Executar `pip-audit` antes de qualquer release.

### III. Config — **100% via variáveis de ambiente**
- NUNCA hardcodar configuração, secrets, URLs, ports ou credenciais no código ou imagem.
- Todas as variáveis documentadas em `.env.example`.
- Em desenvolvimento, usar arquivo `.env` (nunca commitado).

### IV. Backing Services
- PostgreSQL e Redis tratados como recursos anexados via `DATABASE_URL` e `REDIS_URL`.
- Troca de instância sem alteração de código — apenas variável de ambiente.

### V. Build, Release, Run
- Imagem de container construída SEM secrets.
- Secrets injetados apenas em runtime via variáveis de ambiente.
- Build, release e execução são etapas distintas e separadas.

### VI. Processos
- Aplicação stateless: zero estado em memória entre requisições.
- Estado persistido APENAS em PostgreSQL ou Redis.
- Múltiplos workers (Gunicorn) sem compartilhamento de estado local.

### VII. Port Binding
- Porta definida via variável `PORT`.
- Bind sempre em `0.0.0.0`.
- Porta dedicada: **8002** (não conflita com outras apps do servidor).

### VIII. Concorrência
- Escalado via processos (Gunicorn workers), não threads.
- Configuração de workers via variável `WEB_CONCURRENCY`.

### IX. Descartabilidade
- Startup rápido (< 5s).
- Shutdown graceful: capturar SIGTERM, finalizar requisições em andamento, fechar conexões.
- Usar `--timeout` e `--graceful-timeout` no Gunicorn.

### X. Dev/Prod Parity
- Mesmas imagens e versões de serviços em todos os ambientes.
- Usar podman-compose tanto em dev quanto em produção.

### XI. Logs
- Logs SEMPRE para stdout/stderr — NUNCA para arquivo.
- Formato estruturado JSON em produção.
- Coletor externo (Fluentd, journald, OpenShift logging) é responsável por capturar/rotacionar.

### XII. Admin Processes
- Migrations executadas como processo separado antes do startup da aplicação.
- Nunca executar migrations dentro do entrypoint principal.
- Comando dedicado: `python -m app.db.migrate` ou `alembic upgrade head`.

---

## 4. Security by Design

### Validação de Input
- Toda entrada validada com schema (Pydantic v2 ou Marshmallow).
- Rejeitar e logar tentativas com input inválido.

### Menor Privilégio
- Container roda com usuário não-root dedicado (`appuser`, UID 1001).
- Roles de banco de dados com permissões mínimas (apenas SELECT/INSERT/UPDATE nas tabelas necessárias).
- APIs externas com roles read-only quando possível.

### Secrets
- Secrets NUNCA hardcoded, NUNCA na imagem, NUNCA commitados.
- Usar `.env` apenas em desenvolvimento local (listado no `.gitignore`).
- Em produção: variáveis de ambiente injetadas pelo orquestrador (OpenShift Secrets).

### Senhas
- Hash com bcrypt, fator de custo mínimo 12.
- Nunca logar passwords ou tokens.

### Audit Log
- Registrar todas as ações relevantes: login, logout, alteração de configuração, alertas gerados.
- Incluir: timestamp, usuário, IP, ação, resultado.
- Logs de audit para stdout (prefixo `AUDIT:`).

### Tratamento de Erros
- Erros genéricos para o usuário final (nunca stack traces).
- Detalhes completos apenas nos logs internos (stderr).
- Códigos HTTP corretos: 400, 401, 403, 404, 422, 500.

### Headers de Segurança HTTP
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'` (ajustar conforme frontend)
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

### Dependências
- Versões fixadas (pin exato em `requirements.txt`).
- Executar `pip-audit` no pipeline CI.
- Atualizar dependências com vulnerabilidades antes de qualquer release.

### Rate Limiting
- Rate limiting por IP na camada Nginx e/ou na aplicação.
- Padrão: 100 req/min por IP para endpoints de API.
- Endpoints de autenticação: 10 req/min por IP.

### Autenticação JWT
- Access token: expiração curta (15 minutos).
- Refresh token: expiração longa (7 dias) com rotação a cada uso.
- Algoritmo: RS256 (chaves assimétricas).
- Refresh tokens revogados armazenados no Redis.

---

## 5. Isolamento de Serviços (OpenShift-Ready)

- **Banco de dados dedicado**: role `mondns_user` + database `mondns_db` — NUNCA compartilhado.
- **Redis dedicado**: container isolado na porta **6380** — NUNCA compartilhado.
- **Container/processo dedicado**: porta **8002** no localhost — NUNCA compartilhado.
- **Rede isolada**: rede Podman `mondns_net` — sem comunicação com outras aplicações.
- **Volumes nomeados**: `mondns_postgres_data`, `mondns_redis_data`.

**Justificativa:** Isolamento de falhas, migrations independentes, escalonamento independente por serviço,
segurança por namespace no OpenShift (cada app em seu próprio projeto/namespace).

---

## 6. Estrutura de Diretórios

```
mondns/
├── CLAUDE.md                  # Este arquivo — diretrizes do projeto
├── Dockerfile                 # Multi-stage build (dev/prod)
├── podman-compose.yml         # Orquestração local (Podman)
├── .env.example               # Template de variáveis de ambiente
├── .gitignore                 # Arquivos ignorados pelo Git
├── requirements.txt           # Dependências Python com versões fixadas
├── requirements-dev.txt       # Dependências de desenvolvimento
├── alembic.ini                # Configuração do Alembic (migrations)
│
├── app/                       # Código principal da aplicação
│   ├── __init__.py
│   ├── main.py                # Entrypoint FastAPI/Flask
│   ├── config.py              # Leitura de variáveis de ambiente (Pydantic Settings)
│   ├── api/                   # Rotas e endpoints
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py        # Endpoints de autenticação
│   │   │   ├── alerts.py      # Endpoints de alertas DDoS
│   │   │   ├── metrics.py     # Endpoints de métricas DNS
│   │   │   └── about.py       # Endpoint da página Sobre
│   ├── core/                  # Lógica de negócio central
│   │   ├── __init__.py
│   │   ├── security.py        # JWT, bcrypt, rate limiting
│   │   ├── audit.py           # Audit log
│   │   └── exceptions.py      # Exceções customizadas
│   ├── db/                    # Banco de dados
│   │   ├── __init__.py
│   │   ├── base.py            # SQLAlchemy base
│   │   ├── session.py         # Gerenciamento de sessão
│   │   └── migrate.py         # Entrypoint de migrations
│   ├── models/                # Modelos SQLAlchemy
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── alert.py
│   │   └── metric.py
│   ├── schemas/               # Schemas Pydantic (validação)
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── alert.py
│   │   └── metric.py
│   ├── services/              # Camada de serviços
│   │   ├── __init__.py
│   │   ├── bind_parser.py     # Parser de logs do BIND 9
│   │   ├── ddos_detector.py   # Lógica de detecção DDoS
│   │   ├── alert_service.py   # Gerenciamento de alertas
│   │   └── cache.py           # Serviço Redis
│   └── tasks/                 # Tasks assíncronas/background
│       ├── __init__.py
│       └── monitor.py         # Worker de monitoramento DNS
│
├── migrations/                # Alembic migrations
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│
├── tests/                     # Testes automatizados
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_alerts.py
│   └── test_ddos_detector.py
│
├── deploy/                    # Configurações de deploy
│   ├── nginx.conf             # Virtual host Nginx
│   └── openshift/             # Manifestos OpenShift (futuro)
│       ├── deployment.yaml
│       ├── service.yaml
│       └── route.yaml
│
├── scripts/                   # Scripts utilitários
│   ├── entrypoint.sh          # Entrypoint do container
│   └── healthcheck.sh         # Script de health check
│
└── nginx/                     # Certificados SSL (não commitados)
    └── ssl/                   # *.sondaativas.com.br wildcard cert
        ├── .gitkeep
        └── (certificados .pem/.key — não commitados)
```

---

## 7. Arquivos que NUNCA devem ser commitados

- `.env` e qualquer variação (`.env.local`, `.env.prod`, `.env.staging`)
- `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx` (certificados e chaves privadas)
- `nginx/ssl/*` exceto `.gitkeep`
- `*.db`, `*.sqlite`, `*.sqlite3`
- `storage/`, `uploads/`, `media/`
- `logs/`, `*.log`
- `__pycache__/`, `*.pyc`, `*.pyo`, `.pytest_cache/`
- `.venv/`, `venv/`, `env/`
- Qualquer arquivo com credenciais, tokens ou secrets

---

## 8. Página "Sobre" (About)

A aplicação DEVE manter uma página/endpoint **Sobre** sempre atualizada, contendo:

- **Objetivo**: Monitorar ataques DDoS aos servidores DNS
- **Autor**: João Claudio de Faria Andrade — joao.andrade@sonda.com
- **Tecnologias**: Lista completa das tecnologias utilizadas
- **Versionamento**: Histórico completo do que foi implementado em cada versão

**Regras:**
- A página Sobre DEVE ser atualizada a cada alteração de versão.
- O versionamento segue Semantic Versioning (MAJOR.MINOR.PATCH).
- O histórico de versões deve ser mantido em `CHANGELOG.md` e exibido na página Sobre.
- Endpoint: `GET /about` (API) e rota `/about` (frontend, se houver).
- Esta instrução deve ser seguida automaticamente — não aguardar solicitação explícita.

---

## 9. Regras de Desenvolvimento

1. **Nunca** usar `docker` — sempre `podman` e `podman-compose`.
2. **Nunca** hardcodar valores — sempre variáveis de ambiente.
3. **Nunca** logar para arquivo — sempre stdout/stderr.
4. **Nunca** compartilhar banco ou Redis entre aplicações.
5. **Sempre** validar inputs com Pydantic.
6. **Sempre** executar migrations antes do startup.
7. **Sempre** atualizar a página Sobre ao versionar.
8. **Sempre** usar versões fixadas nas dependências.
9. **Sempre** rodar `pip-audit` antes de releases.
10. **Sempre** seguir os princípios do 12-Factor App.
