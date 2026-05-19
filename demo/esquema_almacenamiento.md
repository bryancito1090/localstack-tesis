# Esquema de Almacenamiento de la Información

**Sistema de detección y respuesta ante incidentes en AWS** — Componente C (Automatización de Respuesta).
Documento de definición formal del modelo de almacenamiento, alineado con el Componente A (Arquitectura y Logs).

---

## 1. Principio de diseño

Toda la información del sistema se almacena en un **único *data lake* sobre Amazon S3**, particionado y consultable con SQL **sin mover los datos** (Athena en AWS real / **DuckDB** en el entorno local). Esto separa tres responsabilidades:

| Capa | Propósito | Servicio | Durabilidad |
|------|-----------|----------|-------------|
| **Forense / histórico** | Evidencia inmutable de eventos y respuestas | **S3** | Persistente (90 días) |
| **Tránsito / mensajería** | Entrega fiable del incidente al playbook | **SQS + DLQ** | Transitoria (hasta consumo) |
| **Operativa / ejecución** | Trazas de ejecución de las Lambdas | **CloudWatch Logs** | Operativa |

> Decisión de diseño del Componente C: se interpone **SQS + dispatcher + DLQ** entre la detección y los playbooks. Aporta durabilidad y reintentos (`maxReceiveCount=3`); si un playbook falla, el incidente no se pierde: pasa a la *Dead Letter Queue* para análisis forense.

---

## 2. Almacenamiento forense — Amazon S3

**Bucket único:** `s3://tesis-security-logs`

### 2.1 Estructura de prefijos

| Prefijo | Contenido | Fuente | Formato (AWS real) | Responsable |
|---------|-----------|--------|--------------------|-------------|
| `cloudtrail/` | Eventos de auditoría de la API (logins, IAM, S3) | CloudTrail | `.json.gz` | Componente A |
| `vpc-flow/` | Tráfico de red (conexiones aceptadas/rechazadas) | VPC Flow Logs | `.log.gz` | Componente A |
| `config/` | Snapshots de estado de recursos (políticas IAM) | AWS Config | `.json.gz` | Componente A |
| `guardduty/` | Hallazgos de amenazas | GuardDuty | `.json` | Componente A |
| `responses/` | **Evidencia de mitigación de los playbooks** | **Componente C** | `.json` | **Componente C (Bryan)** |

> En el entorno local los logs simulados se guardan como `.json` sin comprimir para facilitar la inspección en clase; en AWS real se comprimen (`.gz`) para reducir costo/espacio.

### 2.2 Particionamiento

Jerárquico por **fecha de ocurrencia**, para que las consultas de detección filtren solo las particiones relevantes (en AWS real se antepone cuenta/región):

```
s3://tesis-security-logs/
  cloudtrail/AAAA/MM/DD/HHMMSS/<tipo-incidente>-<id>.json
  responses/blocked-ips.json
  responses/<otros-playbooks>...
```

Ejemplo real generado por el sistema:
`cloudtrail/2026/05/19/000115/brute-force-0aec3b72.json`

### 2.3 Retención

90 días para los prefijos de logs (política del Componente A). El prefijo `responses/` se conserva como pista de auditoría de incidentes.

### 2.4 Catálogo (AWS Glue / esquema lógico)

Los archivos en S3 son texto plano. **AWS Glue Data Catalog** define un esquema virtual (mapea campos → tipos: IP, puerto, usuario…) que permite a **Athena / DuckDB** ejecutar SQL directamente sobre S3. En el entorno local, DuckDB cumple esta función con `read_json_auto()`.

---

## 3. Esquemas de registro (contratos de datos)

### 3.1 Evento CloudTrail (entrada — prefijo `cloudtrail/`)

Archivo `{"Records": [ ... ]}`. Cada evento (generado por `simulators/cloudtrail_gen.py`):

```json
{
  "eventVersion": "1.08",
  "eventTime": "2026-05-18T23:57:05Z",
  "eventSource": "signin.amazonaws.com",
  "eventName": "ConsoleLogin",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "185.220.101.5",
  "userIdentity": { "type": "IAMUser", "userName": "dev-operator",
                    "arn": "arn:aws:iam::123456789012:user/dev-operator" },
  "errorCode": "AccessDenied",
  "responseElements": { "ConsoleLogin": "Failure" }
}
```

### 3.2 Incidente (mensaje SQS — bus de respuesta)

Producido por `simulators/inject_logs.py`, consumido por el `dispatcher`:

```json
{
  "incident_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "sourceIPAddress": "185.220.101.5",
  "affectedResource": "iam:user/dev-operator",
  "s3_log_key": "cloudtrail/2026/05/19/000115/brute-force-0aec3b72.json",
  "event_count": 10,
  "timestamp": "2026-05-18T23:57:05Z"
}
```

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `incident_type` | enum | `BRUTE_FORCE`, `PRIVILEGE_ESCALATION`, `CREDENTIAL_LEAK`, `EXFILTRATION`, `PORT_SCAN` |
| `severity` | enum | `LOW` · `MEDIUM` · `HIGH` · `CRITICAL` |
| `sourceIPAddress` | string | IP del atacante (objetivo del bloqueo) |
| `affectedResource` | string | Recurso afectado |
| `s3_log_key` | string | Puntero al log forense que originó el incidente |

### 3.3 Evidencia de mitigación (salida — `responses/blocked-ips.json`)

**Responsabilidad del Componente C.** Escrito por el playbook `block-ip`. Es la **pista de auditoría** que prueba *qué* se bloqueó y *dónde* exactamente:

```json
[
  {
    "ip": "185.220.101.5",
    "blocked_at": "2026-05-18T23:57:10.194758+00:00",
    "reason": "BRUTE_FORCE",
    "severity": "HIGH",
    "affectedResource": "iam:user/dev-operator",
    "enforcement": {
      "enforced": true,
      "already_present": false,
      "network_acl_id": "acl-b2a704d3",
      "rule_number": 1,
      "cidr": "185.220.101.5/32"
    }
  }
]
```

| Campo `enforcement` | Significado |
|---------------------|-------------|
| `enforced` | `true` si el bloqueo se aplicó realmente en infraestructura |
| `network_acl_id` | **Punto de cumplimiento exacto**: la NACL donde se denegó la IP |
| `rule_number` | Nº de regla DENY (rango 1–99, < ALLOW 100 → tiene prioridad) |
| `cidr` | Rango bloqueado (`/32` = IP exacta del atacante) |

Este bloque es lo que diferencia *"avisar"* de *"bloquear"*: registra la prueba verificable de la acción defensiva.

---

## 4. Capa de consulta (detección — Componente B)

DuckDB lee los archivos de `cloudtrail/` como tablas externas y aplica las reglas. Ejemplo real (`queries/detect_brute_force.sql`):

```sql
SELECT r.sourceIPAddress, r.userIdentity.userName AS username,
       COUNT(*) AS failed_attempts
FROM (SELECT unnest(Records) AS r FROM read_json_auto('$LOG_PATH'))
WHERE r.eventName = 'ConsoleLogin' AND r.errorCode = 'AccessDenied'
GROUP BY r.sourceIPAddress, r.userIdentity.userName
HAVING COUNT(*) > 5;
```

Equivale a una consulta Athena sobre la tabla CloudTrail catalogada por Glue.

---

## 5. Almacenamiento transitorio y operativo

| Recurso | Tipo | Función |
|---------|------|---------|
| SQS `tesis-incident-queue` | Cola | Entrega del incidente al `dispatcher` |
| SQS `tesis-incident-queue-dlq` | DLQ | Incidentes que fallaron 3 veces (forense) |
| CloudWatch `/aws/lambda/tesis-*` | Log group | Trazas de ejecución de cada playbook |
| CloudWatch `/tesis/security-events` | Log group | Eventos de seguridad centralizados |

---

## 6. Ciclo de vida de un incidente (resumen end-to-end)

```
1. Ataque        → cloudtrail/AAAA/MM/DD/.../brute-force-xxxx.json   (S3, forense)
2. Detección     → DuckDB/SQL sobre esos logs                        (Componente B)
3. Incidente     → mensaje JSON en SQS tesis-incident-queue          (tránsito)
4. Enrutamiento  → dispatcher decide playbooks                       (CloudWatch traza)
5. Mitigación    → block-ip crea regla DENY en Network ACL           (INFRAESTRUCTURA)
6. Auditoría     → responses/blocked-ips.json con enforcement{}       (S3, evidencia)
```

El almacenamiento es la columna vertebral: cada fase deja una **evidencia consultable y trazable**, desde el log del ataque hasta la prueba del bloqueo real.
