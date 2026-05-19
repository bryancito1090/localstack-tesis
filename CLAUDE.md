# localstack-tesis

Sistema de detección y respuesta ante incidentes de seguridad en entornos cloud (AWS), desarrollado 100% en local con Docker + LocalStack.

## Proyecto y contexto

- **Tesis:** Diseño e implementación de un sistema de detección y respuesta ante incidentes en AWS
- **Componente:** C — Respuesta Automatizada (Bryan)
- **Entorno:** LocalStack en `localhost:4566`, credenciales ficticias `test/test`, perfil AWS `local`
- **Restricciones:** Sin AWS real, sin SIEMs comerciales. Athena → DuckDB local; GuardDuty → scripts Python

**Arquitectura objetivo:**
```
CloudTrail / VPC Flow Logs / GuardDuty
  → CloudWatch Logs → S3 → DuckDB (Athena local)
  → CloudWatch Alarms + SNS → SQS
  → Lambda Playbooks + IAM
```

**Componentes del equipo:**
| Componente | Responsable | Scope |
|------------|-------------|-------|
| A — Arquitectura y Logs | Melany | CloudTrail, VPC Flow Logs, GuardDuty, S3, Glue |
| B — Detección | Aarón | Reglas SQL/DuckDB, CloudWatch Alarms, patrones |
| C — Respuesta Automatizada | **Bryan** | Lambda Playbooks, IAM, SNS, SQS, dispatcher |

## Comandos importantes

Siempre usar `awslocal` en lugar de `aws`. Verificar que LocalStack esté corriendo antes de ejecutar.

```bash
# Levantar el stack
docker compose up -d

# Verificar salud
curl -s http://localhost:4566/_localstack/health | python3 -m json.tool

# AWS local
.venv/bin/awslocal <servicio> <comando>
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test .venv/bin/awslocal <servicio> <comando>
```

## Skills disponibles

| Skill | Descripción |
|-------|-------------|
| `/localstack-up` | Verifica/levanta el stack LocalStack |
| `/simulate-incident` | Simula un evento de incidente de seguridad completo |
| `/bootstrap-resources` | Crea todos los recursos AWS locales necesarios |
| `/deploy-lambda` | Despliega o actualiza un Lambda playbook |
| `/query-logs` | Consulta SQL sobre logs con DuckDB |
| `/new-playbook` | Crea un nuevo Lambda playbook de respuesta |

## Lambda Playbooks (Componente C)

Ubicados en `lambdas/`:
- `block-ip/` — Bloquea una IP en Security Groups
- `isolate-instance/` — Aísla una instancia EC2
- `revoke-credentials/` — Revoca credenciales IAM comprometidas
- `notify-alert/` — Envía notificaciones SNS
- `dispatcher/` — Orquestador central de respuesta automática

## Estructura del proyecto

```
localstack-tesis/
├── .claude/
│   ├── commands/          # Skills personalizados
│   └── settings.local.json
├── infra/                 # IaC y setup de recursos
├── lambdas/               # Playbooks de respuesta
├── simulators/            # Generadores de logs (cloudtrail_gen.py, etc.)
├── queries/               # Queries DuckDB/SQL
├── logs/                  # Logs locales
├── docker-compose.yml
└── .env                   # Credenciales locales (no commitear)
```

## NotebookLM (integración MCP)

Conectado vía `notebooklm-mcp-cli` para análisis de fuentes de la tesis.

- **CLI:** `/home/bryan/.local/bin/nlm`
- **MCP server:** configurado en `~/.claude.json` (scope global)
- **Skill:** `/nlm-skill`
- **Cuenta:** banobryan1090@gmail.com
- **Auth data:** `~/.notebooklm-mcp-cli/`

```bash
nlm login            # Re-autenticar (abre Chromium)
nlm login --check    # Verificar sesión activa
nlm notebook list    # Listar notebooks
nlm doctor           # Diagnóstico
```

**Notebooks disponibles:**
| Título | ID |
|--------|----|
| Automatización de Detección y Respuesta Ante Incidentes en AWS | 6abc796b-0f31-42e6-afa9-05390c999ab8 |
| Cloud Computing | 2f9d5485-b9f7-4165-87ca-76c574395257 |
| Modelos y simulacion | 7dded2ec-f52b-4649-beaf-3b651fe2be62 |
| Formulacion de proyectos | 1bfeb22b-e453-494b-8b63-3a635200bbc6 |
| Formatos de Gestión ISTPET | fc8a101d-4280-4eea-834f-91f9163c1a57 |
| diseño | 8cb2a4b6-9f18-412c-aef4-b0f076bcba40 |

Si las cookies expiran (~2-4 semanas):
```bash
nlm login
# Si falla por singleton:
rm -f ~/.notebooklm-mcp/chrome-profile/Singleton* && nlm login
```
