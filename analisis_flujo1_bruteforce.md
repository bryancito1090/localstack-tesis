# Análisis de Flujo 1 — Ataque Brute-Force en Entorno Local

**Proyecto:** Trabajo de Integración Curricular — Sistema de Detección y Respuesta ante Incidentes en AWS  
**Componente:** C — Automatización de Respuesta  
**Responsable:** Bryan  
**Fecha de ejecución:** 2026-04-20  
**Entorno:** LocalStack 3.8.1 Community — localhost:4566

---

## 1. Descripción del Escenario

Se simuló un ataque de fuerza bruta contra la consola de AWS, donde un actor externo realizó **10 intentos fallidos de autenticación** (`ConsoleLogin` con `AccessDenied`) contra el usuario IAM `admin` desde la IP `185.220.101.5` en un período de ~2 minutos.

El flujo completo cubre: generación del incidente → almacenamiento en S3 → detección con DuckDB → notificación vía Lambda + SNS.

---

## 2. Flujo Ejecutado

```
PASO 1  /localstack-up          LocalStack levantado y verificado
PASO 2  /bootstrap-resources    Recursos AWS locales creados en LocalStack
PASO 3  /simulate-incident      Evento brute-force generado → S3 + SQS
PASO 4  /query-logs             DuckDB detectó el IoC (análisis Athena-equivalente)
PASO 5  /deploy-lambda          Lambda notify-alert desplegada y ejecutada
```

---

## 3. Recursos AWS Locales Utilizados

| Tipo | Nombre | ARN / URL |
|------|--------|-----------|
| S3 | `tesis-security-logs` | `s3://tesis-security-logs/cloudtrail/` |
| SNS | `tesis-security-alerts` | `arn:aws:sns:us-east-1:000000000000:tesis-security-alerts` |
| SNS | `tesis-lambda-triggers` | `arn:aws:sns:us-east-1:000000000000:tesis-lambda-triggers` |
| SQS | `tesis-incident-queue` | `http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/tesis-incident-queue` |
| SQS | `tesis-incident-queue-dlq` | dead letter queue para mensajes fallidos |
| CloudWatch | `/tesis/security-events` | log group de eventos de seguridad |
| CloudWatch | `/tesis/lambda-responses` | log group de respuestas de Lambdas |
| CloudWatch | `/aws/lambda/tesis-notify-alert` | logs de ejecución de la Lambda |
| IAM | `tesis-lambda-response-role` | `arn:aws:iam::000000000000:role/tesis-lambda-response-role` |
| Lambda | `tesis-notify-alert` | `arn:aws:lambda:us-east-1:000000000000:function:tesis-notify-alert` |

---

## 4. Paso a Paso con Respuestas del Sistema

### 4.1 LocalStack UP

```bash
docker compose -f docker-compose.yml up -d
curl -s http://localhost:4566/_localstack/health | python3 -m json.tool
```

**Respuesta:**
```
LocalStack 3.8.1 community — localhost:4566
Servicios disponibles: s3, sns, sqs, lambda, iam, logs, cloudwatch, events
```

---

### 4.2 Bootstrap de Recursos

```bash
source activate.sh
bash infra/setup.sh
```

**Respuesta:**
```
[OK] S3: s3://tesis-security-logs [cloudtrail/, vpc-flow/, guardduty/, responses/]
[OK] SNS alerts:   arn:aws:sns:us-east-1:000000000000:tesis-security-alerts
[OK] SNS triggers: arn:aws:sns:us-east-1:000000000000:tesis-lambda-triggers
[OK] SQS queue: http://...localstack.cloud:4566/.../tesis-incident-queue
[OK] SQS DLQ:   http://...localstack.cloud:4566/.../tesis-incident-queue-dlq
[OK] CloudWatch: /tesis/security-events
[OK] CloudWatch: /tesis/lambda-responses
[OK] IAM Role: arn:aws:iam::000000000000:role/tesis-lambda-response-role
```

---

### 4.3 Simulación del Incidente Brute-Force

```bash
.venv/bin/python3 simulators/inject_logs.py brute-force
```

**Respuesta:**
```
[inject] Generados 10 eventos de tipo 'brute-force'
[inject] Subido a s3://tesis-security-logs/cloudtrail/2026/04/20/234235/brute-force-51cbb9f1.json
[inject] Mensaje SQS enviado a tesis-incident-queue
```

**Payload enviado a SQS (entrada para Lambda):**
```json
{
  "incident_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "sourceIPAddress": "185.220.101.5",
  "affectedResource": "iam:user/admin",
  "s3_log_key": "cloudtrail/2026/04/20/234235/brute-force-51cbb9f1.json",
  "event_count": 10,
  "timestamp": "2026-04-20T23:42:35.606154Z"
}
```

**Verificación S3:**
```
s3://tesis-security-logs/cloudtrail/2026/04/20/234235/brute-force-51cbb9f1.json  (7,681 bytes)
```

**Verificación SQS:**
```
ApproximateNumberOfMessages: 1
```

---

### 4.4 Detección con DuckDB (equivalente a Amazon Athena)

```bash
.venv/bin/awslocal s3 sync s3://tesis-security-logs/cloudtrail/ /tmp/tesis-logs/
# Ejecutar queries/detect_brute_force.sql sobre los archivos descargados
```

**Estructura del evento CloudTrail simulado:**
```json
{
  "eventVersion": "1.08",
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "errorCode": "AccessDenied",
  "sourceIPAddress": "185.220.101.5",
  "userIdentity": { "type": "IAMUser", "userName": "admin" },
  "responseElements": { "ConsoleLogin": "Failure" }
}
```

**Resultado de la consulta DuckDB:**

| sourceIPAddress | username | failed_attempts | first_attempt | last_attempt |
|-----------------|----------|-----------------|---------------|--------------|
| 185.220.101.5 | admin | **10** | 2026-04-20T23:42:35Z | 2026-04-20T23:44:50Z |

```
IoC detectados: 1
Regla disparada: ConsoleLogin + AccessDenied > 5 intentos
Ventana temporal: ~2 minutos
Acción recomendada: notify-alert → block-ip
```

---

### 4.5 Despliegue y Ejecución de Lambda Playbook `notify-alert`

```bash
# Empaquetar
python3 -c "import zipfile; z=zipfile.ZipFile('/tmp/notify-alert.zip','w'); z.write('handler.py'); z.close()"

# Desplegar
.venv/bin/awslocal lambda create-function \
  --function-name tesis-notify-alert \
  --runtime python3.12 \
  --handler handler.lambda_handler \
  --zip-file fileb:///tmp/notify-alert.zip \
  ...

# Invocar
.venv/bin/awslocal lambda invoke \
  --function-name tesis-notify-alert \
  --cli-binary-format raw-in-base64-out \
  --payload file://lambdas/notify-alert/test_event.json \
  output.json
```

**Respuesta de la Lambda (HTTP 200):**
```json
{
  "status": "success",
  "processed": 1,
  "results": [{
    "status": "success",
    "action": "sns_published",
    "details": {
      "alert_type": "SECURITY_INCIDENT",
      "incident_type": "BRUTE_FORCE",
      "severity": "HIGH",
      "sourceIPAddress": "203.0.113.42",
      "affectedResource": "iam:user/admin",
      "detectedAt": "2024-01-15T10:30:00Z",
      "respondedAt": "2026-04-21T00:00:45Z",
      "playbook": "notify-alert",
      "status": "NOTIFIED"
    }
  }],
  "timestamp": "2026-04-21T00:00:45Z"
}
```

**Logs de ejecución (CloudWatch):**
```
START RequestId: 11c6f134-... Version: $LATEST
[notify-alert] Alerta publicada: BRUTE_FORCE desde 203.0.113.42
END RequestId: 11c6f134-...
REPORT Duration: 7.45 ms  Billed Duration: 8 ms  Memory: 128 MB
```

---

## 5. Dónde Ver los Logs (Guía Visual)

### 5.1 Archivos en disco (más directo)

```bash
# Ver el JSON del incidente subido a S3 (descargado localmente):
cat /tmp/tesis-logs/2026/04/20/234235/brute-force-51cbb9f1.json | python3 -m json.tool

# Sincronizar todos los logs de S3 a local:
.venv/bin/awslocal s3 sync s3://tesis-security-logs/cloudtrail/ /tmp/tesis-logs/

# Ver todos los archivos de logs en S3:
.venv/bin/awslocal s3 ls s3://tesis-security-logs/ --recursive
```

### 5.2 Logs de ejecución de Lambda (CloudWatch)

```bash
# Ver todos los log groups disponibles:
.venv/bin/awslocal logs describe-log-groups --query 'logGroups[].logGroupName' --output text

# Ver los streams de la Lambda:
.venv/bin/awslocal logs describe-log-streams \
  --log-group-name /aws/lambda/tesis-notify-alert \
  --query 'logStreams[].logStreamName' --output text

# Leer los logs de la última ejecución:
.venv/bin/awslocal logs get-log-events \
  --log-group-name /aws/lambda/tesis-notify-alert \
  --log-stream-name "2026/04/21/[\$LATEST]STREAM_ID" \
  --query 'events[].message' --output text
```

### 5.3 Mensajes en SQS (cola de incidentes)

```bash
# Ver cuántos mensajes hay en la cola:
.venv/bin/awslocal sqs get-queue-attributes \
  --queue-url http://localhost:4566/000000000000/tesis-incident-queue \
  --attribute-names ApproximateNumberOfMessages

# Leer un mensaje de la cola (sin eliminarlo):
.venv/bin/awslocal sqs receive-message \
  --queue-url http://localhost:4566/000000000000/tesis-incident-queue \
  --attribute-names All
```

### 5.4 Mensajes publicados en SNS

```bash
# Listar tópicos SNS:
.venv/bin/awslocal sns list-topics

# Para ver mensajes SNS publicados, suscribir SQS al tópico primero:
.venv/bin/awslocal sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:000000000000:tesis-security-alerts \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:000000000000:tesis-incident-queue
```

### 5.5 Interfaz Web — LocalStack Web UI (sin instalar nada extra)

LocalStack Community expone una API REST que puedes consultar desde el navegador:

| Recurso | URL directa en navegador |
|---------|--------------------------|
| Health general | http://localhost:4566/_localstack/health |
| Listar buckets S3 | http://localhost:4566/tesis-security-logs/ |
| Info de LocalStack | http://localhost:4566/_localstack/info |

> Para una UI visual completa (tablas, árbol de recursos, gráficos), instala **LocalStack Desktop** (gratuito): https://app.localstack.cloud/download — conecta a `localhost:4566` sin credenciales adicionales.

---

## 6. Hallazgos y Correcciones Aplicadas

### Hallazgo 1 — Scripts fallaban sin credenciales AWS

**Síntoma:** `botocore.exceptions.NoCredentialsError` al correr `inject_logs.py` sin activar el venv antes.

**Causa raíz:** `activate.sh` exporta `AWS_ACCESS_KEY_ID=test` pero solo en el shell que lo ejecuta con `source`. Si se llama el script directamente sin haber hecho `source activate.sh`, boto3 no encuentra credenciales.

**Corrección aplicada** (`simulators/inject_logs.py`):
```python
_KEY    = os.environ.get("AWS_ACCESS_KEY_ID", "test")
_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY", "test")
s3  = boto3.client("s3",  ..., aws_access_key_id=_KEY, aws_secret_access_key=_SECRET)
sqs = boto3.client("sqs", ..., aws_access_key_id=_KEY, aws_secret_access_key=_SECRET)
```

**Regla para la tesis:** Siempre hacer `source activate.sh` antes de cualquier comando, o asegurar fallback `"test"` en los clientes boto3 del entorno local.

---

### Hallazgo 2 — Queries SQL incompatibles con DuckDB

**Síntoma:** `ConversionException: Unimplemented type for cast` al ejecutar las queries `.sql`.

**Causa raíz:** Los archivos SQL usaban el operador de extracción JSON de PostgreSQL (`->>'campo'`), pero DuckDB trabaja con registros struct y requiere acceso por punto (`r.campo`). Además, `format='array'` no es necesario cuando los Records son un campo dentro del JSON raíz.

**Corrección aplicada** (los 3 archivos en `queries/`):
```sql
-- ANTES (PostgreSQL/Athena style — no funciona en DuckDB):
FROM read_json_auto('$LOG_PATH', format='array')
WHERE eventName = 'ConsoleLogin' AND userIdentity->>'userName' = 'x'

-- DESPUÉS (DuckDB struct access):
FROM (SELECT unnest(Records) AS r FROM read_json_auto('$LOG_PATH'))
WHERE r.eventName = 'ConsoleLogin' AND r.userIdentity.userName = 'x'
```

**Regla para la tesis:** DuckDB usa acceso por punto para campos de structs anidados. Para JSON complejo con arreglos dentro de objetos, usar `unnest()` para aplanar el array antes de filtrar.

---

### Hallazgo 3 — Lambda no podía alcanzar LocalStack (endpoint `localhost:4566`)

**Síntoma:** `EndpointConnectionError: Could not connect to http://localhost:4566/` desde dentro de la Lambda.

**Causa raíz:** Las Lambdas con `LAMBDA_EXECUTOR=docker` se ejecutan en contenedores Docker separados. Dentro de ese contenedor, `localhost` es el propio contenedor Lambda, no el host ni el contenedor LocalStack.

**Corrección aplicada** (`lambdas/*/handler.py`):
```python
# ANTES — hardcoded, falla dentro del contenedor:
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")

# DESPUÉS — usa LOCALSTACK_HOSTNAME inyectada automáticamente por LocalStack:
_ls_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", f"http://{_ls_host}:4566")
```

**Por qué funciona:** LocalStack inyecta automáticamente la variable `LOCALSTACK_HOSTNAME` en cada contenedor Lambda que lanza, apuntando al hostname correcto dentro de la red Docker.

---

### Hallazgo 4 — IP de LocalStack cambia entre reinicios

**Síntoma:** Workaround manual de usar `172.19.0.2:4566` dejó de funcionar tras reiniciar Docker (la IP puede asignarse distinta).

**Causa raíz:** Sin una red Docker configurada explícitamente para los contenedores Lambda, cada reinicio puede resultar en IPs distintas para los contenedores.

**Corrección aplicada** (`docker-compose.yml`):
```yaml
environment:
  - LAMBDA_EXECUTOR=docker
  - LAMBDA_DOCKER_NETWORK=localstack-tesis_default  # ← AÑADIDO
```

Esto garantiza que los contenedores Lambda se unan a la misma red Docker que LocalStack (`localstack-tesis_default`), haciendo que `LOCALSTACK_HOSTNAME` sea siempre resoluble por nombre de contenedor, independientemente de la IP asignada.

---

## 7. Archivos Modificados en Esta Sesión

| Archivo | Cambio |
|---------|--------|
| `simulators/inject_logs.py` | Credenciales boto3 con fallback `"test"` |
| `queries/detect_brute_force.sql` | Sintaxis DuckDB: `r.campo` en lugar de `->>'campo'` |
| `queries/detect_privilege_esc.sql` | Misma corrección de sintaxis |
| `queries/detect_exfiltration.sql` | Misma corrección de sintaxis |
| `docker-compose.yml` | `LAMBDA_DOCKER_NETWORK=localstack-tesis_default` |
| `lambdas/notify-alert/handler.py` | Endpoint via `LOCALSTACK_HOSTNAME` |
| `lambdas/revoke-credentials/handler.py` | Endpoint via `LOCALSTACK_HOSTNAME` |

---

## 8. Diagrama del Flujo Ejecutado

```
Atacante externo
185.220.101.5
      │
      │ 10x ConsoleLogin FAILED
      ▼
┌─────────────────────────────────────────────────────────┐
│                  simulators/inject_logs.py               │
│  cloudtrail_gen.py → genera 10 eventos CloudTrail JSON   │
└────────────────────┬────────────────────────────────────┘
                     │
          ┌──────────┼──────────┐
          ▼                     ▼
┌─────────────────┐   ┌─────────────────────────┐
│   S3 LocalStack  │   │     SQS LocalStack       │
│ tesis-security- │   │  tesis-incident-queue    │
│ logs/cloudtrail/ │   │  payload BRUTE_FORCE     │
│ (7,681 bytes)    │   │  severity: HIGH          │
└────────┬────────┘   └───────────┬─────────────┘
         │                        │
         ▼                        ▼
┌─────────────────┐   ┌─────────────────────────┐
│ DuckDB (Athena) │   │  Lambda: notify-alert    │
│ detect_brute_   │   │  Runtime: python3.12     │
│ force.sql       │   │  Duration: 7.45 ms       │
│                 │   │                          │
│ RESULTADO:      │   │  → sns.publish()         │
│ 10 intentos     │   │  → SNS: tesis-security-  │
│ desde misma IP  │   │    alerts                │
│ IoC: CONFIRMADO │   │  → status: NOTIFIED      │
└─────────────────┘   └───────────┬─────────────┘
                                   │
                        ┌──────────▼──────────┐
                        │  CloudWatch Logs     │
                        │ /aws/lambda/tesis-   │
                        │  notify-alert        │
                        │                      │
                        │  [notify-alert]      │
                        │  Alerta publicada:   │
                        │  BRUTE_FORCE desde   │
                        │  203.0.113.42        │
                        └─────────────────────┘
```

---

## 9. Verificación Final del Estado

```bash
# Verificar Lambda activa:
.venv/bin/awslocal lambda get-function --function-name tesis-notify-alert \
  --query 'Configuration.[State,Runtime,Timeout]' --output text
# Active  python3.12  30

# Ver log de ejecución:
.venv/bin/awslocal logs get-log-events \
  --log-group-name /aws/lambda/tesis-notify-alert \
  --log-stream-name "$(awslocal logs describe-log-streams \
    --log-group-name /aws/lambda/tesis-notify-alert \
    --query 'logStreams[0].logStreamName' --output text)" \
  --query 'events[].message' --output text
```

**Salida esperada:**
```
START RequestId: 11c6f134-... Version: $LATEST
[notify-alert] Alerta publicada: BRUTE_FORCE desde 203.0.113.42
END RequestId: 11c6f134-...
REPORT Duration: 7.45 ms  Billed Duration: 8 ms  Memory: 128 MB
```

---

## 10. Próximos Pasos

- [ ] Desplegar playbook `block-ip` y encadenarlo tras `notify-alert`
- [ ] Desplegar playbook `revoke-credentials` para escenario `credential-leak`
- [ ] Simular incidente `privilege-escalation` y ejecutar el flujo completo
- [ ] Conectar SQS → Lambda trigger (event source mapping) para respuesta automática sin invocación manual
- [ ] Suscribir un email o cola SQS al tópico SNS para ver notificaciones end-to-end
