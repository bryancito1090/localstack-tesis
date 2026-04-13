# Entorno de Desarrollo Local — Tesis: Sistema de Detección y Respuesta ante Incidentes en AWS

## Contexto del Proyecto

Este documento describe el entorno local emulado para desarrollar el **Componente C: Automatización de Respuesta**, parte del Trabajo de Integración Curricular sobre diseño e implementación de un sistema de detección y respuesta ante incidentes de seguridad en entornos cloud (AWS).

| Componente | Responsable | Descripción |
|------------|-------------|-------------|
| A — Arquitectura y Logs | Melany | CloudTrail, VPC Flow Logs, GuardDuty, S3, Glue |
| B — Detección de Incidentes | Aarón | Reglas SQL/Athena, CloudWatch Alarms, DuckDB local |
| **C — Automatización de Respuesta** | **Bryan** | **Lambda Playbooks, IAM, SNS, respuesta automatizada** |

---

## ¿Por qué un entorno local?

Probar directamente en AWS real durante el desarrollo tiene dos problemas críticos:

1. **Costos descontrolados**: errores en bucles Lambda o mala configuración de triggers pueden generar cargos exponenciales.
2. **Lentitud de iteración**: cada prueba requiere despliegue real, latencia de red y permisos de cuenta.

El entorno local permite iterar en segundos, sin internet y sin tarjeta de crédito.

---

## Arquitectura de Emulación Local

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose Stack                      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              LocalStack 3.8 (community)               │   │
│  │  ┌──────┐  ┌──────┐  ┌────────┐  ┌───┐  ┌───────┐  │   │
│  │  │  S3  │  │ SNS  │  │ Lambda │  │IAM│  │  SQS  │  │   │
│  │  └──────┘  └──────┘  └────────┘  └───┘  └───────┘  │   │
│  │  ┌──────────────────────────────────────────────┐    │   │
│  │  │          CloudWatch Logs / Events             │    │   │
│  │  └──────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────┘   │
│                     localhost:4566                           │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           DuckDB (reemplaza Amazon Athena)            │   │
│  │      Consulta directa de archivos JSON de logs        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
  awslocal → .venv/bin/awslocal → apunta a localhost:4566
  aws CLI  → perfil "local" con credenciales ficticias
```

### Mapeo: AWS Real → Emulación Local

| Servicio AWS Real | Emulación Local | Propósito en el Proyecto |
|---|---|---|
| Amazon S3 | LocalStack S3 | Almacenamiento de logs JSON |
| AWS Lambda | LocalStack Lambda | Playbooks de respuesta automatizada |
| Amazon SNS | LocalStack SNS | Notificaciones de alertas al equipo |
| Amazon SQS | LocalStack SQS | Cola de eventos para triggear Lambdas |
| AWS IAM | LocalStack IAM | Roles y políticas de mínimo privilegio |
| CloudWatch Logs | LocalStack CloudWatch | Centralización de logs |
| Amazon Athena | **DuckDB local** | Consultas SQL sobre logs JSON |
| AWS GuardDuty | **Scripts Python** | Simulación de hallazgos de seguridad |
| AWS CloudTrail | **cloudtrail_gen.py** | Generación de eventos de API simulados |

---

## Stack Tecnológico Instalado

| Herramienta | Versión | Rol |
|---|---|---|
| Docker Engine | 29.3.0 | Motor de contenedores |
| Docker Compose | 5.1.0 | Orquestación del stack |
| LocalStack | 3.8.1 community | Emulador de servicios AWS |
| Python | 3.14.3 | Scripts de simulación y Lambdas |
| aws-cli-v2 | 2.34.24 | Interfaz de comandos (perfil `local`) |
| awscli-local | 0.22.2 | Wrapper `awslocal` para LocalStack |
| boto3 | 1.42.88 | SDK Python para AWS / LocalStack |
| DuckDB | 1.5.1 | Motor SQL local (reemplaza Athena) |

> Las dependencias Python están aisladas en `.venv/` dentro del proyecto.
> `awslocal` se encuentra en `.venv/bin/awslocal`.

---

## Estructura de Archivos

```
localstack-tesis/
├── ENTORNO_LOCAL.md              ← Este documento
├── docker-compose.yml            ← Stack de LocalStack (imagen 3.8)
├── .env                          ← Variables de entorno del proyecto
├── activate.sh                   ← Activa el venv y exporta variables
├── requirements.txt              ← Dependencias Python del proyecto
│
├── .venv/                        ← Entorno virtual Python (no commitear)
│
├── .claude/
│   └── commands/                 ← Skills de Claude Code (ver sección Skills)
│
├── infra/
│   ├── setup.sh                  ← Bootstrap de recursos AWS locales
│   └── lambda-policies/
│       └── base-policy.json      ← Política IAM base para Lambdas
│
├── lambdas/                      ← Playbooks de respuesta automatizada
│   ├── notify-alert/             ← Publica alerta a SNS
│   │   ├── handler.py
│   │   ├── policy.json
│   │   └── test_event.json
│   └── revoke-credentials/       ← Desactiva keys IAM comprometidas
│       ├── handler.py
│       ├── policy.json
│       └── test_event.json
│
├── simulators/
│   ├── cloudtrail_gen.py         ← Genera eventos CloudTrail por tipo de incidente
│   └── inject_logs.py            ← Sube eventos a S3 y envía mensaje a SQS
│
├── queries/                      ← SQL para DuckDB (equivalente a Athena)
│   ├── detect_brute_force.sql
│   ├── detect_privilege_esc.sql
│   └── detect_exfiltration.sql
│
└── logs/
    └── sample_cloudtrail.json    ← Log de referencia para pruebas sin LocalStack
```

---

## Recursos AWS Locales Creados

Estos recursos ya existen en LocalStack y se recrean con `bash infra/setup.sh` si se pierde el estado (LocalStack no persiste entre reinicios por defecto).

| Tipo | Nombre | ARN / URL |
|---|---|---|
| S3 | `tesis-security-logs` | prefijos: `cloudtrail/`, `vpc-flow/`, `guardduty/`, `responses/` |
| SNS | `tesis-security-alerts` | `arn:aws:sns:us-east-1:000000000000:tesis-security-alerts` |
| SNS | `tesis-lambda-triggers` | `arn:aws:sns:us-east-1:000000000000:tesis-lambda-triggers` |
| SQS | `tesis-incident-queue` | cola principal de eventos de incidentes |
| SQS | `tesis-incident-queue-dlq` | dead letter queue para mensajes fallidos |
| CloudWatch | `/tesis/security-events` | log group de eventos de seguridad |
| CloudWatch | `/tesis/lambda-responses` | log group de respuestas de Lambdas |
| IAM | `tesis-lambda-response-role` | `arn:aws:iam::000000000000:role/tesis-lambda-response-role` |

---

## Cómo iniciar el entorno

Estos son los pasos para tener el entorno operativo al comenzar cada sesión de trabajo.

### Paso 1 — Activar el entorno Python

Desde el directorio del proyecto:

```bash
source activate.sh
```

Esto activa el venv y exporta las variables de entorno necesarias (`AWS_ENDPOINT_URL`, `AWS_DEFAULT_REGION`, etc.). Solo dura la sesión de terminal actual.

### Paso 2 — Levantar LocalStack

```bash
docker compose up -d
```

Espera unos segundos y verifica que esté healthy:

```bash
curl -s http://localhost:4566/_localstack/health | python3 -m json.tool
```

Los servicios relevantes deben aparecer como `"available"`: `s3`, `sns`, `sqs`, `lambda`, `iam`, `logs`.

### Paso 3 — Recrear los recursos AWS locales

LocalStack **no persiste** su estado entre reinicios. Cada vez que se levanta de cero hay que recrear los recursos:

```bash
bash infra/setup.sh
```

> Si el venv no está activo, usa la ruta completa: `.venv/bin/awslocal` en lugar de `awslocal`.

### Resumen de comandos por sesión

```bash
cd ~/localstack-tesis
source activate.sh
docker compose up -d
bash infra/setup.sh
```

---

## Skills de Claude Code

Los skills están en `.claude/commands/` y solo están disponibles cuando Claude Code está abierto en este directorio. Se invocan escribiendo el nombre en el chat.

| Skill | Descripción |
|---|---|
| `/localstack-up` | Verifica si LocalStack está corriendo y lo levanta si no. Muestra el estado de cada servicio relevante para el Componente C. |
| `/bootstrap-resources` | Crea todos los recursos AWS locales del proyecto (S3, SNS, SQS, IAM, CloudWatch). Equivale a correr `bash infra/setup.sh`. |
| `/simulate-incident [tipo]` | Genera un evento de incidente de seguridad sintético, lo sube a S3 y envía el mensaje a SQS para activar el flujo completo. Tipos: `brute-force`, `privilege-escalation`, `credential-leak`, `exfiltration`, `port-scan`. |
| `/deploy-lambda [playbook]` | Empaqueta y despliega un Lambda Playbook en LocalStack. Lo invoca con su `test_event.json` y muestra el resultado. Playbooks: `notify-alert`, `revoke-credentials`, `block-ip`, `isolate-instance`. |
| `/query-logs [tipo]` | Descarga logs de S3 y ejecuta una consulta DuckDB sobre ellos (equivalente a Athena). Tipos: `brute-force`, `privilege-escalation`, `exfiltration`, `summary`, `recent`. |
| `/new-playbook [descripción]` | Crea la estructura completa de un nuevo Lambda Playbook: `handler.py`, `policy.json` (mínimo privilegio) y `test_event.json`. |

### Flujo de trabajo típico

```
/localstack-up
    → /bootstrap-resources          (si es primera vez o LocalStack fue reiniciado)
        → /simulate-incident brute-force
            → /query-logs brute-force
                → /deploy-lambda notify-alert
```

---

## Restricciones del Entorno

1. **No usar la consola web de AWS real** ni credenciales reales en ningún archivo.
2. **No usar SIEMs comerciales** (Splunk, Datadog, Elastic). Solo servicios AWS nativos emulados.
3. **Athena → DuckDB**: todas las consultas SQL sobre logs se hacen con DuckDB.
4. **GuardDuty → Scripts Python**: los hallazgos se simulan con `simulators/cloudtrail_gen.py`.
5. Cada Lambda debe tener su `policy.json` con permisos de mínimo privilegio.
6. Los archivos en `logs/` son datos sintéticos, nunca logs reales de producción.
7. LocalStack Community **no persiste** estado entre reinicios: siempre correr `setup.sh` al levantar.
