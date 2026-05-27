# Ataque de Fuerza Bruta — Flujo Completo del Sistema
**Fecha:** 2026-05-12 | **Componente C — Automatización de Respuesta** | **Bryan**

---

## ¿Qué es este escenario?

Un atacante externo intenta adivinar la contraseña de un usuario IAM de AWS haciendo **10 intentos de login fallidos en ~2 minutos** desde la IP `185.220.101.5`.

El sistema detecta el patrón, genera una alerta y **toma acciones automáticas de contención** — todo sin intervención humana.

---

## Flujo de extremo a extremo

```
┌──────────────────────────────────────────────────────────────────────┐
│  FASE 1 — ATAQUE                                                      │
│                                                                        │
│  Atacante 185.220.101.5                                               │
│      │  10x ConsoleLogin FAILED (AccessDenied)                         │
│      │  usuario: admin  │  ventana: ~2 minutos                         │
│      ▼                                                                 │
│  cloudtrail_gen.py  →  genera 10 eventos JSON con estructura real     │
│  inject_logs.py     →  empaqueta y distribuye los eventos             │
│                                ├──▶ S3: cloudtrail/2026/.../brute-force-XXXX.json│
│                                └──▶ SQS: tesis-incident-queue (payload)│
└──────────────────────────────────────────────────────────────────────┘
                          │                        │
┌─────────────────────────▼──┐   ┌─────────────────▼─────────────────┐
│  FASE 2 — DETECCIÓN         │   │  FASE 3 — AUTOMATIZACIÓN           │
│                              │   │                                    │
│  queries/detect_brute_      │   │  Lambda: dispatcher                │
│  force.sql (DuckDB)         │   │      ├──▶ tesis-notify-alert       │
│                              │   │      └──▶ tesis-block-ip           │
│  SQL descarga logs de S3    │   │                                    │
│  y detecta el IoC:          │   │  Resultados guardados en S3:       │
│  ▸ misma IP                 │   │  responses/blocked-ips.json        │
│  ▸ mismo usuario            │   │                                    │
│  ▸ +5 intentos fallidos     │   │  Notificación publicada en SNS:    │
│  ▸ ventana < 5 min          │   │  tesis-security-alerts             │
└──────────────────────────────┘   └────────────────────────────────────┘
```

---

## Fase 1 — El ataque y cómo se inyecta al sistema

### Archivos que intervienen

| Archivo | Qué hace |
|---------|----------|
| `simulators/cloudtrail_gen.py` | **Genera** los 10 eventos JSON con estructura idéntica a CloudTrail real |
| `simulators/inject_logs.py` | **Orquesta**: llama al generador, sube a S3 y envía el payload a SQS |

### ¿Qué genera `cloudtrail_gen.py`?

La función `brute_force()` produce **10 eventos**, uno cada 15 segundos, con esta estructura:

```json
{
  "eventVersion": "1.08",
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "errorCode": "AccessDenied",
  "errorMessage": "Failed authentication",
  "sourceIPAddress": "185.220.101.5",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "admin"
  },
  "responseElements": {
    "ConsoleLogin": "Failure"
  }
}
```

> Este JSON es sintético pero tiene la **misma estructura** que un log real de AWS CloudTrail. El campo `eventName=ConsoleLogin` + `errorCode=AccessDenied` es la firma del intento fallido.

### ¿Qué hace `inject_logs.py`?

Toma esos 10 eventos y hace dos cosas:

**1. Los sube a S3** como archivo JSON (simula cómo CloudTrail almacena logs reales):
```
s3://tesis-security-logs/cloudtrail/2026/05/12/brute-force-51cbb9f1.json
```

**2. Envía un mensaje a SQS** con el resumen del incidente (el payload que activa la Lambda):
```json
{
  "incident_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "sourceIPAddress": "185.220.101.5",
  "affectedResource": "iam:user/admin",
  "s3_log_key": "cloudtrail/2026/05/12/.../brute-force-51cbb9f1.json",
  "event_count": 10,
  "timestamp": "2026-05-12T..."
}
```

---

## Fase 2 — La detección (DuckDB / equivalente a Athena)

### Archivo que interviene

| Archivo | Qué hace |
|---------|----------|
| `queries/detect_brute_force.sql` | Query SQL que analiza los logs y detecta el patrón de fuerza bruta |

### La consulta SQL

```sql
SELECT
    r.sourceIPAddress,
    r.userIdentity.userName   AS username,
    COUNT(*)                  AS failed_attempts,
    MIN(r.eventTime)          AS first_attempt,
    MAX(r.eventTime)          AS last_attempt
FROM (
    SELECT unnest(Records) AS r
    FROM read_json_auto('$LOG_PATH')   -- Lee el JSON descargado de S3
)
WHERE r.eventName = 'ConsoleLogin'
  AND r.errorCode = 'AccessDenied'    -- Solo intentos fallidos
GROUP BY r.sourceIPAddress, r.userIdentity.userName
HAVING COUNT(*) > 5                   -- Umbral: más de 5 intentos
ORDER BY failed_attempts DESC;
```

### Resultado que obtiene

| sourceIPAddress | username | failed_attempts | first_attempt | last_attempt |
|----------------|----------|-----------------|---------------|--------------|
| 185.220.101.5 | admin | **10** | 2026-05-12T...Z | 2026-05-12T...Z |

```
IoC detectado: 1 dirección IP atacante
Regla disparada: ConsoleLogin + AccessDenied > 5 intentos en ~2 min
Acción recomendada: notify-alert + block-ip
```

> **¿Por qué DuckDB?** En AWS real se usaría Amazon Athena. En el entorno local, DuckDB lee los mismos archivos JSON directamente sin necesidad de internet ni costo.

---

## Fase 3 — La automatización (Playbooks Lambda)

### La cadena de respuesta automática

```
SQS: tesis-incident-queue
        │ (payload BRUTE_FORCE)
        ▼
Lambda: dispatcher
        ├──▶ Lambda: notify-alert   → publica alerta en SNS
        └──▶ Lambda: block-ip       → registra IP en S3 + notifica SNS
```

### Archivos que intervienen

| Archivo | Playbook | Qué hace |
|---------|----------|----------|
| `lambdas/dispatcher/handler.py` | dispatcher | Recibe el evento SQS, lee el tipo de incidente y llama a los playbooks correctos |
| `lambdas/notify-alert/handler.py` | notify-alert | Publica una alerta estructurada al tópico SNS del equipo |
| `lambdas/block-ip/handler.py` | block-ip | Añade la IP atacante a la lista de bloqueo en S3 y notifica |

---

### Playbook 1: `dispatcher`
**Archivo:** `lambdas/dispatcher/handler.py`

**Rol:** El cerebro de la automatización. Es la única Lambda que escucha directamente la cola SQS. Su trabajo es leer `incident_type` del payload y decidir qué playbooks ejecutar.

**Tabla de enrutamiento interna:**
```
BRUTE_FORCE          → notify-alert  +  block-ip
CREDENTIAL_LEAK      → notify-alert  +  revoke-credentials
PRIVILEGE_ESCALATION → notify-alert  +  revoke-credentials
EXFILTRATION         → notify-alert  +  isolate-instance
PORT_SCAN            → notify-alert  +  block-ip
```

Para brute-force, ejecuta en secuencia `notify-alert` y luego `block-ip`, pasándole el mismo payload SQS original. El dispatcher **no toma acciones directas** — solo enruta.

---

### Playbook 2: `notify-alert`
**Archivo:** `lambdas/notify-alert/handler.py`

**Rol:** Primera respuesta ante cualquier incidente. Construye un mensaje de alerta estructurado y lo publica al canal SNS del equipo de seguridad.

**¿Qué recibe?**
El payload SQS con `incident_type`, `severity`, `sourceIPAddress`, `affectedResource`.

**¿Qué hace paso a paso?**
1. Extrae los campos del payload SQS
2. Construye un objeto de alerta con campos como `alert_type`, `detectedAt`, `respondedAt`, `playbook`, `status`
3. Llama a `sns.publish()` hacia `tesis-security-alerts`
4. Registra en CloudWatch: `[notify-alert] Alerta publicada: BRUTE_FORCE desde 185.220.101.5`

**Salida que produce (al tópico SNS):**
```json
{
  "alert_type": "SECURITY_INCIDENT",
  "incident_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "sourceIPAddress": "185.220.101.5",
  "affectedResource": "iam:user/admin",
  "detectedAt": "2026-05-12T...",
  "respondedAt": "2026-05-12T...",
  "playbook": "notify-alert",
  "status": "NOTIFIED"
}
```

**En AWS real:** este mensaje llegaría por email, SMS, o Slack vía suscripción SNS.

---

### Playbook 3: `block-ip`
**Archivo:** `lambdas/block-ip/handler.py`

**Rol:** Contención técnica. Registra la IP atacante en una lista persistente en S3 y notifica al equipo.

**¿Qué hace paso a paso?**
1. Lee el archivo `responses/blocked-ips.json` de S3 (la lista actual de IPs bloqueadas)
2. Verifica que la IP no esté ya bloqueada (evita duplicados)
3. Añade una nueva entrada con IP, fecha, motivo y severidad
4. Sube el archivo actualizado de vuelta a S3
5. Publica notificación al tópico SNS

**En AWS real:** en lugar de solo guardar en S3, actualizaría un **WAF IP Set** o modificaría **Security Groups** para bloquear el tráfico a nivel de red.

---

### Playbook extra referenciado: `revoke-credentials`
**Archivo:** `lambdas/revoke-credentials/handler.py`
*(No se activa en brute-force, pero está disponible para credential-leak y privilege-escalation)*

**¿Qué hace?**
1. Lista todas las access keys del usuario IAM comprometido
2. Desactiva cada key (`Status=Inactive` en IAM)
3. Adjunta una política `EmergencyDenyAll` al usuario (bloqueo total inmediato)
4. Notifica al equipo vía SNS

---

### Playbook extra referenciado: `isolate-instance`
**Archivo:** `lambdas/isolate-instance/handler.py`
*(Se activa para exfiltration)*

**¿Qué hace?**
1. Lee la lista de instancias en cuarentena de S3
2. Registra la instancia comprometida con fecha y razón
3. Simula 3 acciones: remover Security Group, aplicar DenyAll, disparar snapshot
4. Persiste en S3 y notifica vía SNS

---

## Archivos que genera la automatización

Estos son todos los archivos/objetos que el sistema **crea o modifica** como resultado del flujo brute-force:

### En S3 (`tesis-security-logs`)

| Ruta en S3 | Tipo | De dónde viene | Qué contiene |
|-----------|------|----------------|--------------|
| `cloudtrail/2026/05/12/HHMMSS/brute-force-XXXX.json` | JSON creado | `inject_logs.py` sube el output de `cloudtrail_gen.py` | Los 10 eventos CloudTrail simulados con estructura `{"Records": [...]}` |
| `responses/blocked-ips.json` | JSON creado/actualizado | Playbook `block-ip` lo escribe después de ejecutarse | Lista acumulativa de IPs bloqueadas con fecha, motivo y severidad |

**Ejemplo de `blocked-ips.json`:**
```json
[
  {
    "ip": "185.220.101.5",
    "blocked_at": "2026-05-12T...",
    "reason": "BRUTE_FORCE",
    "severity": "HIGH",
    "affectedResource": "iam:user/admin"
  }
]
```

> Este archivo persiste entre ejecuciones. Cada nuevo ataque detectado **añade una entrada** sin borrar las anteriores. Es el registro histórico de IPs bloqueadas.

### En SNS (`tesis-security-alerts`)

| Qué se publica | Lo publica | Cuándo |
|----------------|-----------|--------|
| Alerta JSON estructurada (`status: NOTIFIED`) | `notify-alert` | Inmediatamente al detectar el incidente |
| Confirmación de bloqueo (`status: BLOCKED`) | `block-ip` | Tras registrar la IP en S3 |

> En el entorno local SNS actúa como un bus de mensajes. En AWS real, estos mensajes se entregarían a suscriptores: email, SMS, Lambda adicional, HTTP endpoint.

### En CloudWatch Logs

| Log Group | Lo escribe | Qué registra |
|-----------|-----------|--------------|
| `/aws/lambda/tesis-dispatcher` | Lambda dispatcher | Qué incidente recibió y qué playbooks invocó |
| `/aws/lambda/tesis-notify-alert` | Lambda notify-alert | Confirmación de alerta publicada |
| `/aws/lambda/tesis-block-ip` | Lambda block-ip | Qué IP fue bloqueada y si ya estaba en la lista |

**Ejemplo de log en CloudWatch:**
```
START RequestId: abc123...
[dispatcher] Incidente: BRUTE_FORCE (HIGH) → playbooks: ['tesis-notify-alert', 'tesis-block-ip']
[dispatcher] tesis-notify-alert → success
[dispatcher] tesis-block-ip → success
END RequestId: abc123...
REPORT Duration: 312 ms  Billed Duration: 313 ms  Memory: 128 MB
```

---

## Mapa completo de archivos del proyecto en este flujo

```
localstack-tesis/
│
├── simulators/
│   ├── cloudtrail_gen.py       ← PASO 1: genera los eventos JSON del ataque
│   └── inject_logs.py          ← PASO 2: sube a S3 y envía a SQS
│
├── queries/
│   └── detect_brute_force.sql  ← PASO 3: SQL que detecta el patrón
│
├── lambdas/
│   ├── dispatcher/
│   │   └── handler.py          ← PASO 4a: enruta el incidente a los playbooks
│   ├── notify-alert/
│   │   ├── handler.py          ← PASO 4b: publica la alerta a SNS
│   │   └── test_event.json     ← evento de prueba para invocar la Lambda
│   └── block-ip/
│       ├── handler.py          ← PASO 4c: registra IP en S3 y notifica
│       └── test_event.json     ← evento de prueba para invocar la Lambda
│
└── infra/
    └── setup.sh                ← crea S3, SNS, SQS, IAM antes de todo

── ARCHIVOS GENERADOS POR EL SISTEMA ──────────────────────────────────
S3: cloudtrail/2026/.../brute-force-XXXX.json   ← log del ataque
S3: responses/blocked-ips.json                   ← lista de IPs bloqueadas
SNS: tesis-security-alerts                        ← mensajes de alerta
CloudWatch: /aws/lambda/tesis-*                  ← logs de ejecución
```

---

## Resumen visual del flujo en 5 pasos

```
PASO 1  Ataque simulado
        cloudtrail_gen.py genera 10 eventos ConsoleLogin+AccessDenied
        inject_logs.py los sube a S3 y al canal SQS

PASO 2  Almacenamiento
        S3: cloudtrail/brute-force-XXXX.json  (7 KB de logs)
        SQS: payload JSON con incident_type=BRUTE_FORCE, severity=HIGH

PASO 3  Detección
        detect_brute_force.sql descarga el JSON de S3 y lo analiza
        DuckDB agrupa por IP + usuario, cuenta intentos fallidos
        Umbral superado: 10 intentos > 5  →  IoC confirmado

PASO 4  Automatización
        SQS activa la Lambda dispatcher
        dispatcher lee BRUTE_FORCE y llama a:
          └─ notify-alert  →  alerta en SNS  →  status: NOTIFIED
          └─ block-ip      →  IP en S3       →  status: BLOCKED

PASO 5  Evidencia generada
        S3: responses/blocked-ips.json  (registro de la IP bloqueada)
        SNS: 2 mensajes publicados (alerta + confirmación bloqueo)
        CloudWatch: logs de ejecución de cada Lambda con duración y estado
```

---

## ¿Qué pasaría en AWS real?

| Entorno local (LocalStack) | AWS real equivalente |
|---------------------------|---------------------|
| `cloudtrail_gen.py` genera eventos JSON | CloudTrail captura automáticamente las llamadas a la API |
| `inject_logs.py` sube a S3 local | CloudTrail entrega los logs a S3 automáticamente |
| DuckDB ejecuta SQL sobre el JSON | Amazon Athena consulta la tabla de CloudTrail en S3 |
| SQS activa Lambda manualmente | EventBridge Rule o SQS trigger automático activa la Lambda |
| `block-ip` guarda en `blocked-ips.json` en S3 | `block-ip` actualizaría un WAF IP Set o Security Group |
| SNS publica en tópico local | SNS entregaría email/SMS/webhook al equipo de seguridad |
