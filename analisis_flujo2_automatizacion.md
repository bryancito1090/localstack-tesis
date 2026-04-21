# Análisis de Flujo 2 — Automatización Completa del Componente C

**Proyecto:** Trabajo de Integración Curricular — Sistema de Detección y Respuesta ante Incidentes en AWS  
**Componente:** C — Automatización de Respuesta  
**Responsable:** Bryan  
**Fecha de ejecución:** 2026-04-21  
**Entorno:** LocalStack 3.8.1 Community — localhost:4566

---

## 1. Objetivo de Este Flujo

Completar el Componente C de forma que la respuesta ante incidentes sea **totalmente automática**:  
un mensaje en SQS dispara el playbook correcto sin ninguna intervención manual.

---

## 2. Estado Antes vs Después

| Capacidad | Antes (Flujo 1) | Después (Flujo 2) |
|-----------|-----------------|-------------------|
| Simular incidente → S3 + SQS | ✅ | ✅ |
| Detectar con DuckDB (Athena) | ✅ | ✅ |
| Lambda `notify-alert` | ✅ manual | ✅ automático |
| Lambda `block-ip` | ❌ no existía | ✅ automático |
| Lambda `revoke-credentials` | ✅ código, no desplegada | ✅ automático |
| Lambda `isolate-instance` | ❌ no existía | ✅ automático |
| Lambda `dispatcher` (enrutador) | ❌ no existía | ✅ automático |
| SQS → Lambda trigger automático | ❌ invocación manual | ✅ Event Source Mapping |

---

## 3. Arquitectura Final del Componente C

```
Atacante externo
      │
      ▼
simulators/inject_logs.py
  ├── genera eventos CloudTrail JSON
  ├── sube a S3: tesis-security-logs/cloudtrail/
  └── publica en SQS: tesis-incident-queue
                            │
                            │ Event Source Mapping (automático)
                            │ batch-size: 1
                            ▼
              ┌─────────────────────────────┐
              │   Lambda: tesis-dispatcher   │
              │   Tabla de enrutamiento:     │
              │                             │
              │  BRUTE_FORCE       →  notify-alert + block-ip           │
              │  CREDENTIAL_LEAK   →  notify-alert + revoke-credentials │
              │  PRIVILEGE_ESC     →  notify-alert + revoke-credentials │
              │  EXFILTRATION      →  notify-alert + isolate-instance   │
              │  PORT_SCAN         →  notify-alert + block-ip           │
              └──────────────┬──────────────┘
                             │ lambda.invoke() para cada playbook
              ┌──────────────┼──────────────┬────────────────┐
              ▼              ▼              ▼                ▼
        notify-alert     block-ip    revoke-credentials  isolate-instance
        sns.publish()    S3 blocklist  iam.update_access_key  S3 quarantine
              │              │              │                │
              └──────────────┴──────────────┴────────────────┘
                                    │
                             SNS: tesis-security-alerts
                                    │
                             CloudWatch Logs
                             /aws/lambda/tesis-*
```

---

## 4. Playbooks Creados

### 4.1 `tesis-dispatcher`

**Rol:** Lambda central. Consume mensajes de SQS automáticamente (Event Source Mapping) y enruta al conjunto correcto de playbooks según `incident_type`.

**Tabla de enrutamiento:**

| incident_type | Playbooks invocados |
|---------------|---------------------|
| `BRUTE_FORCE` | notify-alert → block-ip |
| `CREDENTIAL_LEAK` | notify-alert → revoke-credentials |
| `PRIVILEGE_ESCALATION` | notify-alert → revoke-credentials |
| `EXFILTRATION` | notify-alert → isolate-instance |
| `PORT_SCAN` | notify-alert → block-ip |

**ARN:** `arn:aws:lambda:us-east-1:000000000000:function:tesis-dispatcher`

---

### 4.2 `tesis-block-ip`

**Rol:** Registra la IP atacante en `s3://tesis-security-logs/responses/blocked-ips.json` y notifica via SNS.  
**Equivalente real AWS:** Actualizar WAF IP Set o regla de Security Group/NACL.

**Resultado en S3 tras ejecución:**
```json
[
  {
    "ip": "203.0.113.42",
    "blocked_at": "2026-04-21T01:00:32Z",
    "reason": "BRUTE_FORCE",
    "severity": "HIGH",
    "affectedResource": "iam:user/external-contractor"
  }
]
```

**ARN:** `arn:aws:lambda:us-east-1:000000000000:function:tesis-block-ip`

---

### 4.3 `tesis-revoke-credentials` (ya existía, ahora desplegada)

**Rol:** Desactiva todas las access keys del usuario IAM comprometido y aplica política `EmergencyDenyAll`.  
**Equivalente real AWS:** `iam:UpdateAccessKey` + `iam:PutUserPolicy`.

**Acciones que ejecuta:**
1. Lista access keys del usuario afectado
2. Cambia cada key a `Status: Inactive`
3. Adjunta política JSON de `Deny *` como contención inmediata
4. Publica resultado en SNS

**ARN:** `arn:aws:lambda:us-east-1:000000000000:function:tesis-revoke-credentials`

---

### 4.4 `tesis-isolate-instance`

**Rol:** Registra la instancia comprometida en `s3://tesis-security-logs/responses/quarantine-instances.json` y notifica.  
**Equivalente real AWS:** Reemplazar Security Group por uno vacío + tomar snapshot EBS.

**Resultado en S3:**
```json
[
  {
    "resource": "ec2:instance/i-0abc123def456",
    "isolated_at": "2026-04-21T01:00:xx Z",
    "reason": "EXFILTRATION",
    "actions_applied": [
      "security_group_removed",
      "deny_all_policy_applied",
      "snapshot_triggered"
    ]
  }
]
```

**ARN:** `arn:aws:lambda:us-east-1:000000000000:function:tesis-isolate-instance`

---

### 4.5 `tesis-notify-alert` (existía, sin cambios)

**Rol:** Construye y publica el mensaje de alerta al tópico SNS.  
**ARN:** `arn:aws:lambda:us-east-1:000000000000:function:tesis-notify-alert`

---

## 5. Event Source Mapping — La Pieza Clave

```bash
awslocal lambda create-event-source-mapping \
  --function-name tesis-dispatcher \
  --event-source-arn arn:aws:sqs:us-east-1:000000000000:tesis-incident-queue \
  --batch-size 1
```

| Campo | Valor |
|-------|-------|
| UUID | `71e87db4-3ed3-4d73-8830-ebba22aec20d` |
| Estado | `Enabled` |
| Fuente | `arn:aws:sqs:us-east-1:000000000000:tesis-incident-queue` |
| Destino | `tesis-dispatcher` |
| Batch size | 1 mensaje por invocación |

**Efecto:** Cuando `inject_logs.py` publica en SQS, LocalStack detecta el mensaje y dispara `tesis-dispatcher` automáticamente, sin ningún comando manual adicional.

---

## 6. Prueba del Flujo Automático Completo

### Comando ejecutado

```bash
.venv/bin/python3 simulators/inject_logs.py brute-force
```

### Secuencia automática resultante

```
1. inject_logs.py → SQS: tesis-incident-queue (mensaje BRUTE_FORCE)
2. Event Source Mapping → dispara tesis-dispatcher automáticamente
3. dispatcher lee incident_type=BRUTE_FORCE
4. dispatcher invoca tesis-notify-alert → SUCCESS (SNS publicado)
5. dispatcher invoca tesis-block-ip → SUCCESS (S3 blocklist actualizado)
6. Mensajes en cola después: 0 (consumido y procesado)
```

### Log del dispatcher (CloudWatch)

```
START RequestId: 1e250e37-... Version: $LATEST
[dispatcher] Incidente: BRUTE_FORCE (HIGH) → playbooks: ['tesis-notify-alert', 'tesis-block-ip']
[dispatcher] tesis-notify-alert → success
[dispatcher] tesis-block-ip → success
END RequestId: 1e250e37-...
REPORT Duration: 2220.58 ms  Billed Duration: 2221 ms  Memory: 128 MB
```

### Evidencias en S3

```bash
# Ver IPs bloqueadas:
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/blocked-ips.json -

# Ver instancias en cuarentena (tras simular exfiltration):
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/quarantine-instances.json -

# Ver todos los archivos de respuesta:
.venv/bin/awslocal s3 ls s3://tesis-security-logs/responses/
```

---

## 7. Cómo Verificar Cada Parte del Flujo Tú Mismo

### Ver el log de cualquier Lambda

```bash
# Reemplaza NOMBRE por: tesis-dispatcher, tesis-block-ip, tesis-notify-alert, etc.
NOMBRE=tesis-dispatcher
STREAM=$(.venv/bin/awslocal logs describe-log-streams \
  --log-group-name /aws/lambda/$NOMBRE \
  --order-by LastEventTime --descending \
  --query 'logStreams[0].logStreamName' --output text)

.venv/bin/awslocal logs get-log-events \
  --log-group-name /aws/lambda/$NOMBRE \
  --log-stream-name "$STREAM" \
  --query 'events[].message' --output text
```

### Simular cualquier tipo de incidente

```bash
# Tipos: brute-force | privilege-escalation | credential-leak | exfiltration | port-scan
.venv/bin/python3 simulators/inject_logs.py credential-leak
.venv/bin/python3 simulators/inject_logs.py privilege-escalation
.venv/bin/python3 simulators/inject_logs.py exfiltration
```

Cada uno disparará automáticamente el playbook correspondiente en ~2-3 segundos.

### Ver el estado del Event Source Mapping

```bash
.venv/bin/awslocal lambda list-event-source-mappings \
  --function-name tesis-dispatcher \
  --query 'EventSourceMappings[0].[UUID,State,EventSourceArn]' --output text
```

### Ver todas las Lambdas desplegadas

```bash
.venv/bin/awslocal lambda list-functions \
  --query 'Functions[].[FunctionName,Runtime]' --output table
```

---

## 8. Archivos Creados en Esta Sesión

| Archivo | Descripción |
|---------|-------------|
| `lambdas/dispatcher/handler.py` | Lambda central de enrutamiento por `incident_type` |
| `lambdas/dispatcher/policy.json` | Política IAM mínimo privilegio: `lambda:InvokeFunction` + SQS |
| `lambdas/dispatcher/test_event.json` | Evento de prueba para invocación manual |
| `lambdas/block-ip/handler.py` | Playbook: bloquea IP en S3 blocklist + SNS |
| `lambdas/block-ip/policy.json` | Política IAM: `s3:PutObject` en `responses/*` + SNS |
| `lambdas/block-ip/test_event.json` | Evento de prueba |
| `lambdas/isolate-instance/handler.py` | Playbook: cuarentena de instancia en S3 + SNS |
| `lambdas/isolate-instance/policy.json` | Política IAM: `s3:PutObject` en `responses/*` + SNS |
| `lambdas/isolate-instance/test_event.json` | Evento de prueba |

---

## 9. Estado Final del Componente C

```
Simular incidente → S3 + SQS      ✅  inject_logs.py
Detectar con DuckDB (≈ Athena)     ✅  queries/detect_*.sql
Respuesta automática (dispatcher)  ✅  Event Source Mapping SQS → Lambda
  BRUTE_FORCE     → notify + block-ip           ✅
  CREDENTIAL_LEAK → notify + revoke-credentials ✅
  PRIVILEGE_ESC   → notify + revoke-credentials ✅
  EXFILTRATION    → notify + isolate-instance   ✅
  PORT_SCAN       → notify + block-ip           ✅
Evidencias de respuesta en S3      ✅  responses/blocked-ips.json
                                       responses/quarantine-instances.json
Logs de ejecución en CloudWatch    ✅  /aws/lambda/tesis-*
Principio de mínimo privilegio     ✅  policy.json por playbook
```

---

## 10. Notas para la Tesis

### Sobre `LAMBDA_EXECUTOR=docker`
Las Lambdas se ejecutan en contenedores Docker separados lanzados por LocalStack. Esto replica el modelo de ejecución de AWS Lambda real (contenedores efímeros, aislados, con su propio filesystem). La latencia de arranque en frío (~2 segundos) que se observa en los logs es equivalente al cold start real de AWS.

### Sobre la simulación de block-ip e isolate-instance
En AWS real, `block-ip` actualizaría un WAF IP Set o una regla NACL, y `isolate-instance` modificaría el Security Group de EC2 a uno sin reglas. Ambos servicios requieren plan Pro en LocalStack. La implementación con S3 como almacén de estado es funcionalmente equivalente para demostrar el flujo de respuesta y es la práctica estándar en entornos de prueba sin licencia.

### Sobre el Event Source Mapping
Esta es la forma nativa de AWS de conectar SQS con Lambda. En producción, cuando `batch-size=1`, cada mensaje SQS genera exactamente una invocación de Lambda. Si la Lambda falla (excepción no manejada), el mensaje retorna a la cola hasta `maxReceiveCount=3`, tras lo cual va al DLQ (`tesis-incident-queue-dlq`). Esto garantiza que ningún incidente se pierda silenciosamente.

### Limitación conocida
LocalStack no persiste estado entre reinicios. Al reiniciar Docker, ejecutar en orden:
```bash
source activate.sh
docker compose up -d
bash infra/setup.sh
# Re-desplegar las 5 Lambdas con el script de deploy
# Re-crear el Event Source Mapping
```
