# Guía Técnica de Pruebas del Prototipo — Perspectiva del Atacante y Respuesta del Sistema

**Proyecto:** Trabajo de Integración Curricular — Sistema de Detección y Respuesta ante Incidentes en AWS  
**Componente:** C — Automatización de Respuesta  
**Responsable:** Bryan  
**Fecha:** 2026-05-05  
**Entorno:** LocalStack Community — `localhost:4566`

> **Propósito:** Describir los comandos exactos para reproducir cada escenario de ataque liviano,
> verificar que el sistema lo detecta, y confirmar que la respuesta automatizada se ejecuta
> correctamente. Cada sección se lee desde la perspectiva del atacante y del sistema en paralelo.

---

## Tabla de contenido

1. [Prerequisitos — entorno en estado válido](#1-prerequisitos)
2. [Escenario 1 — Fuerza Bruta (BRUTE_FORCE)](#2-escenario-1--fuerza-bruta)
3. [Escenario 2 — Credencial Filtrada (CREDENTIAL_LEAK)](#3-escenario-2--credencial-filtrada)
4. [Escenario 3 — Escalada de Privilegios (PRIVILEGE_ESCALATION)](#4-escenario-3--escalada-de-privilegios)
5. [Escenario 4 — Exfiltración de Datos (EXFILTRATION)](#5-escenario-4--exfiltración-de-datos)
6. [Escenario 5 — Escaneo de Puertos (PORT_SCAN)](#6-escenario-5--escaneo-de-puertos)
7. [Verificación cruzada del flujo completo (Dispatcher)](#7-verificación-cruzada-del-flujo-completo)
8. [Preguntas clave para la defensa del prototipo](#8-preguntas-clave-para-la-defensa-del-prototipo)

---

## 1. Prerequisitos

Antes de cualquier prueba verificar que el entorno esté en estado limpio y funcional.

```bash
# 1a. Activar credenciales ficticias del entorno local
source activate.sh

# 1b. Levantar LocalStack (si no está corriendo)
docker compose -f docker-compose.yml up -d

# 1c. Verificar servicios disponibles
curl -s http://localhost:4566/_localstack/health | python3 -m json.tool
# Esperado: s3, sqs, sns, lambda, iam, logs — todos en "available"

# 1d. Crear recursos base (solo si es la primera vez o se reinició)
bash infra/setup.sh

# 1e. Verificar que las 5 Lambdas están desplegadas
.venv/bin/awslocal lambda list-functions \
  --query 'Functions[].FunctionName' --output text
# Esperado: tesis-dispatcher tesis-notify-alert tesis-block-ip tesis-revoke-credentials tesis-isolate-instance

# 1f. Verificar que la cola SQS existe
.venv/bin/awslocal sqs list-queues
# Esperado: tesis-incident-queue y tesis-incident-queue-dlq

# 1g. Verificar el bucket S3
.venv/bin/awslocal s3 ls s3://tesis-security-logs/
# Esperado: cloudtrail/ vpc-flow/ guardduty/ responses/
```

---

## 2. Escenario 1 — Fuerza Bruta

### Perspectiva del atacante

El atacante intenta adivinar la contraseña de `iam:user/admin` probando combinaciones comunes
desde la IP `185.220.101.5`. Cada intento devuelve `AccessDenied`. No sabe que cada fallo
genera un evento `ConsoleLogin` en CloudTrail.

**Umbral de detección:** 5 o más intentos fallidos desde la misma IP en una ventana de 5 minutos.

---

### A. Simular el ataque (generar logs)

```bash
# Genera 10 eventos ConsoleLogin + AccessDenied y los sube a S3 + SQS
.venv/bin/python3 simulators/inject_logs.py brute-force

# Verificar que el log llegó a S3
.venv/bin/awslocal s3 ls s3://tesis-security-logs/cloudtrail/ --recursive

# Verificar que el mensaje llegó a SQS
.venv/bin/awslocal sqs get-queue-attributes \
  --queue-url http://localhost:4566/000000000000/tesis-incident-queue \
  --attribute-names ApproximateNumberOfMessages
# Esperado: "ApproximateNumberOfMessages": "1"
```

---

### B. Detección — consulta DuckDB (equivalente a Athena)

```bash
# Sincronizar los logs de S3 al sistema de archivos local
.venv/bin/awslocal s3 sync s3://tesis-security-logs/cloudtrail/ /tmp/tesis-logs/

# Ejecutar la query de detección
LOG_PATH=/tmp/tesis-logs/**/*.json \
  duckdb -c "
    SELECT
      r.sourceIPAddress,
      r.userIdentity.userName   AS username,
      COUNT(*)                  AS failed_attempts,
      MIN(r.eventTime)          AS first_attempt,
      MAX(r.eventTime)          AS last_attempt
    FROM (
      SELECT unnest(Records) AS r
      FROM read_json_auto('/tmp/tesis-logs/**/*.json', union_by_name=true)
    )
    WHERE r.eventName = 'ConsoleLogin'
      AND r.errorCode = 'AccessDenied'
    GROUP BY r.sourceIPAddress, r.userIdentity.userName
    HAVING COUNT(*) >= 5
    ORDER BY failed_attempts DESC;
  "
# Esperado: 1 fila — IP 185.220.101.5, 10 intentos, usuario admin
```

---

### C. Respuesta automatizada — invocar el Dispatcher

```bash
# Opción 1: invocar el dispatcher directamente con el payload del incidente
.venv/bin/awslocal lambda invoke \
  --function-name tesis-dispatcher \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "Records": [{
      "body": "{\"incident_type\":\"BRUTE_FORCE\",\"severity\":\"HIGH\",\"sourceIPAddress\":\"185.220.101.5\",\"affectedResource\":\"iam:user/admin\",\"event_count\":10}"
    }]
  }' \
  /tmp/dispatcher-out.json && cat /tmp/dispatcher-out.json | python3 -m json.tool
```

```bash
# Opción 2: leer el mensaje directamente de SQS (como haría el Event Source Mapping)
MSG=$(.venv/bin/awslocal sqs receive-message \
  --queue-url http://localhost:4566/000000000000/tesis-incident-queue \
  --query 'Messages[0].Body' --output text)

.venv/bin/awslocal lambda invoke \
  --function-name tesis-dispatcher \
  --cli-binary-format raw-in-base64-out \
  --payload "{\"Records\":[{\"body\":$MSG}]}" \
  /tmp/dispatcher-out.json && cat /tmp/dispatcher-out.json | python3 -m json.tool
```

**Respuesta esperada del Dispatcher:**
```json
{
  "status": "success",
  "processed": 1,
  "results": [{
    "incident_type": "BRUTE_FORCE",
    "severity": "HIGH",
    "playbooks_run": ["tesis-notify-alert", "tesis-block-ip"],
    "invocations": [
      {"function": "tesis-notify-alert", "status": "success"},
      {"function": "tesis-block-ip",     "status": "success"}
    ]
  }]
}
```

---

### D. Verificar evidencia de la respuesta

```bash
# Confirmar que la IP quedó en el blocklist de S3
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/blocked-ips.json - | python3 -m json.tool
# Esperado: entrada con "ip": "185.220.101.5"

# Ver logs de ejecución de block-ip en CloudWatch
.venv/bin/awslocal logs describe-log-streams \
  --log-group-name /aws/lambda/tesis-block-ip \
  --query 'logStreams[-1].logStreamName' --output text

# (reemplazar STREAM_NAME con el resultado anterior)
.venv/bin/awslocal logs get-log-events \
  --log-group-name /aws/lambda/tesis-block-ip \
  --log-stream-name "STREAM_NAME" \
  --query 'events[].message' --output text
# Esperado: [block-ip] IP 185.220.101.5 añadida al blocklist
```

---

## 3. Escenario 2 — Credencial Filtrada

### Perspectiva del atacante

El atacante encontró `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` en un repositorio GitHub público.
Empieza a llamar la API de AWS directamente: lista buckets, describe instancias. Cree que nadie
sabe de su acceso porque no intentó hacer login.

**Umbral de detección:** key usada desde IP no registrada en el historial del usuario o en
horario fuera de patrón. En el prototipo: evento `AssumeRole` o `GetCallerIdentity` con
`errorCode != null` o flag de credencial comprometida.

---

### A. Simular el ataque

```bash
.venv/bin/python3 simulators/inject_logs.py credential-leak

# Verificar log en S3
.venv/bin/awslocal s3 ls s3://tesis-security-logs/cloudtrail/ --recursive

# Verificar mensaje en SQS
.venv/bin/awslocal sqs get-queue-attributes \
  --queue-url http://localhost:4566/000000000000/tesis-incident-queue \
  --attribute-names ApproximateNumberOfMessages
```

---

### B. Detección — query de credencial comprometida

```bash
.venv/bin/awslocal s3 sync s3://tesis-security-logs/cloudtrail/ /tmp/tesis-logs/

duckdb -c "
  SELECT
    r.userIdentity.accessKeyId   AS access_key,
    r.sourceIPAddress,
    r.eventName,
    r.eventTime
  FROM (
    SELECT unnest(Records) AS r
    FROM read_json_auto('/tmp/tesis-logs/**/*.json', union_by_name=true)
  )
  WHERE r.userIdentity.accessKeyId IS NOT NULL
    AND r.errorCode IS NOT NULL
  ORDER BY r.eventTime;
"
```

---

### C. Respuesta — revocar la credencial

```bash
# Invocar el dispatcher con tipo CREDENTIAL_LEAK
.venv/bin/awslocal lambda invoke \
  --function-name tesis-dispatcher \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "Records": [{
      "body": "{\"incident_type\":\"CREDENTIAL_LEAK\",\"severity\":\"CRITICAL\",\"sourceIPAddress\":\"203.0.113.99\",\"affectedResource\":\"iam:user/dev-user\",\"compromisedKey\":\"AKIAIOSFODNN7EXAMPLE\"}"
    }]
  }' \
  /tmp/dispatcher-out.json && cat /tmp/dispatcher-out.json | python3 -m json.tool
```

**Playbooks activados:** `tesis-notify-alert` → `tesis-revoke-credentials`

---

### D. Verificar que la key fue desactivada

```bash
# Ver el registro de credenciales revocadas en S3
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/revoked-credentials.json - \
  | python3 -m json.tool
# Esperado: entrada con "key": "AKIAIOSFODNN7EXAMPLE", "status": "REVOKED"

# Ver logs de la Lambda revoke-credentials
.venv/bin/awslocal logs get-log-events \
  --log-group-name /aws/lambda/tesis-revoke-credentials \
  --log-stream-name "$(.venv/bin/awslocal logs describe-log-streams \
      --log-group-name /aws/lambda/tesis-revoke-credentials \
      --query 'logStreams[-1].logStreamName' --output text)" \
  --query 'events[].message' --output text
```

---

## 4. Escenario 3 — Escalada de Privilegios

### Perspectiva del atacante

El atacante tiene acceso a una cuenta de bajos privilegios (`dev-user`, solo lectura).
Intenta ejecutar `iam:AttachUserPolicy` para darse permisos de administrador.
El comando sería rechazado por IAM, pero el intento queda registrado en CloudTrail.

**Umbral de detección:** llamada a `iam:AttachUserPolicy`, `iam:CreateRole`, o `iam:PutUserPolicy`
desde un usuario cuyo historial no incluye ese tipo de acciones.

---

### A. Simular el ataque

```bash
.venv/bin/python3 simulators/inject_logs.py privilege-escalation

.venv/bin/awslocal s3 ls s3://tesis-security-logs/cloudtrail/ --recursive
```

---

### B. Detección — query de escalada de privilegios

```bash
.venv/bin/awslocal s3 sync s3://tesis-security-logs/cloudtrail/ /tmp/tesis-logs/

duckdb -c "
  SELECT
    r.userIdentity.userName  AS username,
    r.eventName,
    r.sourceIPAddress,
    r.errorCode,
    r.eventTime
  FROM (
    SELECT unnest(Records) AS r
    FROM read_json_auto('/tmp/tesis-logs/**/*.json', union_by_name=true)
  )
  WHERE r.eventSource = 'iam.amazonaws.com'
    AND r.eventName IN (
      'AttachUserPolicy', 'CreateRole', 'PutUserPolicy',
      'AddUserToGroup', 'AttachRolePolicy'
    )
  ORDER BY r.eventTime;
"
# Esperado: evento IAM sospechoso desde dev-user
```

---

### C. Respuesta

```bash
.venv/bin/awslocal lambda invoke \
  --function-name tesis-dispatcher \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "Records": [{
      "body": "{\"incident_type\":\"PRIVILEGE_ESCALATION\",\"severity\":\"CRITICAL\",\"sourceIPAddress\":\"10.0.1.45\",\"affectedResource\":\"iam:user/dev-user\",\"suspiciousAction\":\"AttachUserPolicy\"}"
    }]
  }' \
  /tmp/dispatcher-out.json && cat /tmp/dispatcher-out.json | python3 -m json.tool
```

**Playbooks activados:** `tesis-notify-alert` → `tesis-revoke-credentials`

---

## 5. Escenario 4 — Exfiltración de Datos

### Perspectiva del atacante

Ya dentro del entorno, el atacante ejecuta `GetObject` de forma masiva sobre el bucket
`tesis-security-logs`. Descarga decenas de archivos en segundos. Desde su perspectiva,
los datos fluyen sin interrupción.

**Umbral de detección:** más de 20 operaciones `GetObject` desde la misma IP o usuario
en menos de 60 segundos, sobre el mismo bucket.

---

### A. Simular el ataque

```bash
.venv/bin/python3 simulators/inject_logs.py exfiltration

.venv/bin/awslocal s3 ls s3://tesis-security-logs/cloudtrail/ --recursive
```

---

### B. Detección — query de exfiltración

```bash
.venv/bin/awslocal s3 sync s3://tesis-security-logs/cloudtrail/ /tmp/tesis-logs/

duckdb -c "
  SELECT
    r.sourceIPAddress,
    r.userIdentity.userName     AS username,
    r.requestParameters.bucketName AS bucket,
    COUNT(*)                    AS object_downloads,
    MIN(r.eventTime)            AS window_start,
    MAX(r.eventTime)            AS window_end
  FROM (
    SELECT unnest(Records) AS r
    FROM read_json_auto('/tmp/tesis-logs/**/*.json', union_by_name=true)
  )
  WHERE r.eventName = 'GetObject'
  GROUP BY r.sourceIPAddress, r.userIdentity.userName, r.requestParameters.bucketName
  HAVING COUNT(*) > 20
  ORDER BY object_downloads DESC;
"
```

---

### C. Respuesta — aislar el recurso

```bash
.venv/bin/awslocal lambda invoke \
  --function-name tesis-dispatcher \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "Records": [{
      "body": "{\"incident_type\":\"EXFILTRATION\",\"severity\":\"CRITICAL\",\"sourceIPAddress\":\"198.51.100.77\",\"affectedResource\":\"s3://tesis-security-logs\",\"event_count\":35}"
    }]
  }' \
  /tmp/dispatcher-out.json && cat /tmp/dispatcher-out.json | python3 -m json.tool
```

**Playbooks activados:** `tesis-notify-alert` → `tesis-isolate-instance`

---

### D. Verificar el aislamiento

```bash
# Ver registro de recursos aislados
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/isolated-resources.json - \
  | python3 -m json.tool
# Esperado: "resource": "s3://tesis-security-logs", "status": "ISOLATED"
```

---

## 6. Escenario 5 — Escaneo de Puertos

### Perspectiva del atacante

Fase de reconocimiento: el atacante envía paquetes SYN a 50 puertos distintos del mismo host
en menos de 10 segundos, buscando servicios abiertos. Es el primer paso antes del ataque real.

**Umbral de detección:** más de 15 conexiones rechazadas (`REJECT`) desde la misma IP hacia
distintos puertos en los VPC Flow Logs, en una ventana de 60 segundos.

---

### A. Simular el ataque

```bash
.venv/bin/python3 simulators/inject_logs.py port-scan

# Los eventos van a vpc-flow/ en lugar de cloudtrail/
.venv/bin/awslocal s3 ls s3://tesis-security-logs/vpc-flow/ --recursive
```

---

### B. Detección — query sobre VPC Flow Logs

```bash
.venv/bin/awslocal s3 sync s3://tesis-security-logs/vpc-flow/ /tmp/tesis-vpc/

duckdb -c "
  SELECT
    srcaddr      AS attacker_ip,
    dstaddr      AS target_host,
    COUNT(DISTINCT dstport) AS ports_scanned,
    MIN(start)              AS window_start,
    MAX(start)              AS window_end
  FROM read_csv_auto('/tmp/tesis-vpc/**/*.log', header=true)
  WHERE action = 'REJECT'
  GROUP BY srcaddr, dstaddr
  HAVING COUNT(DISTINCT dstport) > 15
  ORDER BY ports_scanned DESC;
"
```

---

### C. Respuesta

```bash
.venv/bin/awslocal lambda invoke \
  --function-name tesis-dispatcher \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "Records": [{
      "body": "{\"incident_type\":\"PORT_SCAN\",\"severity\":\"MEDIUM\",\"sourceIPAddress\":\"45.33.32.156\",\"affectedResource\":\"vpc/tesis-vpc\",\"ports_scanned\":48}"
    }]
  }' \
  /tmp/dispatcher-out.json && cat /tmp/dispatcher-out.json | python3 -m json.tool
```

**Playbooks activados:** `tesis-notify-alert` → `tesis-block-ip`

---

## 7. Verificación cruzada del flujo completo

Comandos para confirmar el estado del sistema después de ejecutar uno o más escenarios.

```bash
# Estado de la cola SQS (mensajes procesados vs pendientes)
.venv/bin/awslocal sqs get-queue-attributes \
  --queue-url http://localhost:4566/000000000000/tesis-incident-queue \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible \
  --output table

# Dead letter queue — mensajes fallidos (debe estar en 0 si todo funcionó)
.venv/bin/awslocal sqs get-queue-attributes \
  --queue-url http://localhost:4566/000000000000/tesis-incident-queue-dlq \
  --attribute-names ApproximateNumberOfMessages

# Resumen de IPs bloqueadas (blocklist acumulada)
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/blocked-ips.json - \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(e['ip'], e['reason']) for e in d]"

# Resumen de credenciales revocadas
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/revoked-credentials.json - \
  | python3 -m json.tool

# Resumen de recursos aislados
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/isolated-resources.json - \
  | python3 -m json.tool

# Logs de todos los playbooks en CloudWatch
for fn in dispatcher notify-alert block-ip revoke-credentials isolate-instance; do
  echo "=== tesis-$fn ==="
  STREAM=$(.venv/bin/awslocal logs describe-log-streams \
    --log-group-name /aws/lambda/tesis-$fn \
    --query 'logStreams[-1].logStreamName' --output text 2>/dev/null)
  [ -n "$STREAM" ] && .venv/bin/awslocal logs get-log-events \
    --log-group-name /aws/lambda/tesis-$fn \
    --log-stream-name "$STREAM" \
    --query 'events[].message' --output text | head -10
done

# Listar todos los objetos de respuesta generados
.venv/bin/awslocal s3 ls s3://tesis-security-logs/responses/ --recursive
```

---

## 8. Preguntas clave para la defensa del prototipo

Estas preguntas se dividen en tres categorías: **diseño de detección**, **diseño de respuesta**,
y **validez del prototipo**. Sirven tanto para preparar la defensa oral como para identificar
posibles brechas técnicas antes de presentar.

---

### 8.1 Sobre la detección

**P1. ¿Cuál es el umbral exacto para detectar fuerza bruta y por qué ese número?**
> El sistema usa 5 intentos fallidos en 5 minutos. ¿Por qué no 3 o 10? ¿Cómo afecta ese
> umbral a los falsos positivos (un usuario legítimo olvidando su contraseña)?

**P2. ¿Qué pasa si el atacante distribuye la fuerza bruta entre múltiples IPs?**
> Ataque distribuido (botnet) donde cada IP hace solo 2 intentos. La regla actual agrupa por
> `sourceIPAddress` — ¿cómo se puede extender para detectar patrones por `username` independientemente de la IP?

**P3. ¿Cómo distingues un escaneo de puertos legítimo (auditoría interna) de uno malicioso?**
> La query actual detecta volumen, no intención. ¿Hay atributos adicionales en los VPC Flow Logs
> (como `vpc-id`, `subnet-id`, o `account-id`) que permitan contextualizar la fuente?

**P4. ¿Por qué usas DuckDB en lugar de ejecutar las queries directamente en Athena de LocalStack?**
> LocalStack Community no implementa Athena. DuckDB es funcionalmente equivalente para las
> queries SQL sobre archivos JSON/CSV locales, pero ¿hay diferencias de comportamiento que
> puedan afectar la traducción a producción real?

**P5. ¿Qué tan cerca están los logs simulados de los logs reales de CloudTrail?**
> ¿Qué campos del schema de CloudTrail 1.08 están presentes en los eventos generados por
> `inject_logs.py`? ¿Cuáles se omitieron por simplificación y cuáles son críticos para detección?

---

### 8.2 Sobre la respuesta automatizada

**P6. ¿Qué pasa si el Dispatcher falla a mitad de la ejecución de los playbooks?**
> Ejemplo: `notify-alert` se ejecuta exitosamente, pero `block-ip` falla. ¿El incidente
> queda registrado como bloqueado aunque no lo esté? ¿Cómo se detecta ese estado inconsistente?

**P7. ¿Por qué el blocklist de IPs se persiste en S3 en lugar de actualizar un Security Group o WAF?**
> LocalStack Community no implementa WAF ni EC2 Security Groups completos. ¿Cómo sería
> la implementación en AWS real? ¿Qué servicio específico recibiría la regla de bloqueo?

**P8. ¿La respuesta del sistema es idempotente?**
> Si el mismo incidente llega dos veces a la cola (duplicado), ¿qué pasa? `block-ip` verifica
> si la IP ya está en el blocklist antes de agregarla. ¿Los demás playbooks tienen esa misma
> protección contra duplicados?

**P9. ¿Cuál es el tiempo de respuesta medido (detección → acción)?**
> Los logs de CloudWatch muestran `Duration: 7.45 ms` para `notify-alert`. ¿Cuánto tarda el
> flujo completo (Dispatcher + todos los playbooks) en un escenario real? ¿Hay un SLA implícito
> de tiempo de respuesta para este sistema?

**P10. ¿Qué pasa con el atacante mientras el sistema responde?**
> El bloqueo de IP es reactivo — ocurre después de la detección. ¿Cuántos eventos puede generar
> el atacante entre el primer intento y el momento en que la IP queda registrada en el blocklist?
> ¿Eso es aceptable para el alcance del prototipo?

---

### 8.3 Sobre la validez y limitaciones del prototipo

**P11. ¿Qué diferencias funcionales existen entre este prototipo y un sistema real en AWS?**
> Las principales limitaciones son: sin WAF real, sin Security Groups activos, sin GuardDuty
> nativo, sin Athena. ¿Cómo se documentan estas diferencias en la tesis para no sobre-vender
> el alcance del prototipo?

**P12. ¿Por qué se eligió el patrón SQS + Dispatcher en lugar de SNS directo?**
> SNS puede perder mensajes si la Lambda falla. SQS retiene el mensaje y reintenta hasta 3 veces.
> En un contexto de seguridad donde perder un incidente tiene consecuencias graves, ¿cuál es
> el costo real de no tener DLQ en producción?

**P13. ¿Cómo se prueba que el Event Source Mapping funciona sin intervención manual?**
> Actualmente los escenarios invocan el Dispatcher directamente. ¿Está el Event Source Mapping
> configurado en LocalStack para que la cola SQS active el Dispatcher automáticamente?
> ¿Cómo se verifica eso sin hacer la invocación manual?

```bash
# Verificar si el Event Source Mapping está configurado
.venv/bin/awslocal lambda list-event-source-mappings \
  --function-name tesis-dispatcher \
  --query 'EventSourceMappings[*].{State:State,Source:EventSourceArn}' --output table
```

**P14. ¿Los escenarios de prueba son suficientemente representativos de ataques reales?**
> Los 5 escenarios (brute force, credential leak, privilege escalation, exfiltration, port scan)
> cubren los vectores más comunes en AWS según el MITRE ATT&CK Cloud matrix. ¿Se justifica
> en la tesis por qué se eligieron estos 5 y no otros (por ejemplo, cryptojacking o S3 misconfiguration)?

**P15. ¿Cómo se mide el éxito de la respuesta automatizada?**
> ¿Cuáles son las métricas de evaluación? Candidatos: tiempo hasta detección (TTD), tiempo hasta
> respuesta (TTR), tasa de falsos positivos, tasa de falsos negativos, porcentaje de incidentes
> con respuesta exitosa. ¿Cuál de estos puede medirse con el prototipo actual?

---

## Resumen de comandos de verificación rápida

| Acción | Comando |
|--------|---------|
| Ver IPs bloqueadas | `awslocal s3 cp s3://tesis-security-logs/responses/blocked-ips.json -` |
| Ver credenciales revocadas | `awslocal s3 cp s3://tesis-security-logs/responses/revoked-credentials.json -` |
| Ver recursos aislados | `awslocal s3 cp s3://tesis-security-logs/responses/isolated-resources.json -` |
| Contar mensajes en cola | `awslocal sqs get-queue-attributes --queue-url ... --attribute-names ApproximateNumberOfMessages` |
| Ver logs del Dispatcher | `awslocal logs get-log-events --log-group-name /aws/lambda/tesis-dispatcher ...` |
| Verificar Event Source Mapping | `awslocal lambda list-event-source-mappings --function-name tesis-dispatcher` |
| Estado general de LocalStack | `curl -s http://localhost:4566/_localstack/health \| python3 -m json.tool` |
| Listar todas las Lambdas | `awslocal lambda list-functions --query 'Functions[].FunctionName' --output text` |
