# Implementación en AWS: Costos, Integración y Seguridad (Componente C)

Este documento resume los costos estimados, los requisitos de integración con los componentes de Melany y Aarón, el formato de datos de incidentes, y los mecanismos de seguridad necesarios para desplegar el **Componente C: Automatización de Respuesta** en un entorno real de AWS.

---

## 1. Costos Estimados en AWS Real
Para propósitos académicos, de prueba y demostración de la tesis, **el costo mensual aproximado es de $0.00 USD**, ya que todos los servicios del Componente C están cubiertos por la **Capa Gratuita de AWS (Free Tier)**.

A continuación se detalla el costo por servicio en caso de superar el Free Tier (bajo volumen):

| Servicio AWS | Concepto en Componente C | Capa Gratuita (Mensual) | Costo Fuera de Capa Gratuita | Costo Estimado (Pruebas de Tesis) |
| :--- | :--- | :--- | :--- | :--- |
| **AWS Lambda** | Ejecución de los 5 Playbooks y Dispatcher | 1 millón de peticiones | $0.20 por millón de peticiones | **$0.00** |
| **Amazon SQS** | Cola de incidentes y DLQ | 1 millón de peticiones | $0.40 por millón de peticiones | **$0.00** |
| **Amazon SNS** | Envío de notificaciones de alertas | 1 millón de publicaciones | $0.50 por millón de publicaciones (E-mail: 1,000 gratis, luego $2.00/10k) | **$0.00** |
| **Amazon S3** | Evidencias de bloqueos (`responses/`) | 5 GB de almacenamiento | $0.023 por GB almacenado | **<$0.01** |
| **AWS IAM** | Roles y políticas de seguridad | Siempre gratis | No tiene costo | **$0.00** |
| **EC2 / NACL** | Modificación de reglas del firewall de red | Siempre gratis | Cambiar reglas de NACL no tiene costo | **$0.00** |

---

## 2. Requisitos de Integración (Qué necesitas de tu equipo)

Para iniciar el despliegue del Componente C en la cuenta de AWS real, necesitas que tus compañeros te proporcionen los siguientes datos e infraestructura:

### De Melany (Componente A — Infraestructura y Logs)
1. **VPC ID & NACL ID**: El ID de la VPC de producción (`vpc-xxxxxx`) y el ID de la Network ACL pública (`nacl-xxxxxx`) donde el playbook `block-ip` creará las reglas `DENY`.
2. **Nombre del Bucket S3**: El nombre exacto del bucket de logs (`tesis-security-logs-prod`) para almacenar el registro de auditoría de contenciones (`responses/`).
3. **Instancias EC2 Objetivo**: Los IDs de las instancias EC2 (`i-xxxxxx`) que simularán estar comprometidas para probar el aislamiento en red del playbook `isolate-instance`.

### De Aarón (Componente B — Detección de Incidentes)
1. **ARN de la Cola SQS**: El ARN exacto de la cola SQS de producción (`arn:aws:sqs:us-east-1:123456789012:tesis-incident-queue`) a la cual el dispatcher de Lambda se suscribirá mediante un *Event Source Mapping*.
2. **Homologación de Payloads**: Asegurar que su motor de detección (DuckDB/Athena/Lambda) publique los mensajes con la estructura de variables exacta que se detalla en la siguiente sección.

---

## 3. Formato de Incidentes de Aarón (Payload SQS)
Aarón debe publicar un mensaje en formato **JSON** en la cola de SQS por cada incidente detectado. El esquema unificado es el siguiente:

### Variables Obligatorias del Payload

| Campo SQS | Tipo | Descripción | Formato / Ejemplo |
| :--- | :---: | :--- | :--- |
| `incident_type` | String | Tipo de incidente detectado (llave de ruteo). | `"BRUTE_FORCE"`, `"PORT_SCAN"`, `"PRIVILEGE_ESCALATION"`, `"CREDENTIAL_LEAK"`, `"EXFILTRATION"` |
| `severity` | String | Gravedad del incidente según la regla de detección. | `"MEDIUM"`, `"HIGH"`, `"CRITICAL"` |
| `sourceIPAddress` | String | IP origen del atacante (necesaria para bloquear la IP). | `"185.220.101.5"` |
| `affectedResource` | String | Recurso comprometido. **Crítico: usar prefijo exacto.** | `"iam:user/nombre-usuario"` o `"ec2:instance/i-0abc123def"` |
| `s3_log_key` | String | Ruta del log en S3 que contiene la evidencia. | `"cloudtrail/2026/05/19/archivo.json"` |
| `timestamp` | String | Fecha y hora en que ocurrió/detectó el incidente. | ISO 8601 UTC: `"2026-05-19T00:01:15Z"` |
| `event_count` | Integer | Número de eventos/logs que activaron la alerta. | `15` |

### Ejemplo de JSON de Entrada para SQS (Fuerza Bruta)
```json
{
  "incident_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "sourceIPAddress": "185.220.101.5",
  "affectedResource": "iam:user/dev-operator",
  "s3_log_key": "cloudtrail/2026/05/19/brute-force-xyz.json",
  "timestamp": "2026-05-19T00:01:15Z",
  "event_count": 10
}
```

---

## 4. Mecanismos de Seguridad de Conexión en AWS
Para garantizar que las conexiones a los recursos de AWS sean seguras y sigan las mejores prácticas de la nube, se deben implementar los siguientes tres mecanismos:

1. **Roles de Ejecución de IAM (Mínimo Privilegio)**:
   * **Sin credenciales estáticas**: Las Lambdas del Componente C no deben usar Access Keys ni Secret Keys. En su lugar, se les asigna un **IAM Execution Role** con una política de confianza (`AssumeRole`).
   * **Políticas Dedicadas**: Cada playbook de Lambda debe tener una política de acceso que conceda permisos estrictamente a su recurso objetivo (ej: el playbook `block-ip` solo debe tener permisos sobre la NACL específica, no sobre todo el servicio de EC2).

2. **VPC Endpoints (AWS PrivateLink)**:
   * Si las funciones Lambda se configuran dentro de la VPC privada para interactuar con recursos internos (como las interfaces de red de las EC2), la comunicación con SQS, SNS y S3 no debe salir a internet público.
   * Se deben desplegar **Interface VPC Endpoints** para SQS y SNS, y un **Gateway VPC Endpoint** para S3, permitiendo una conexión privada y segura a través de la red interna de AWS.

3. **Cifrado de Datos en Tránsito y Reposo**:
   * Las conexiones entre SQS, Lambdas y SNS se realizan por defecto utilizando **HTTPS (TLS 1.2/1.3)** asegurando el cifrado en tránsito.
   * El bucket de S3 de evidencias y la cola SQS de incidentes deben tener habilitado el **cifrado en reposo** utilizando llaves administradas por AWS (SSE-S3) o llaves personalizadas de KMS (SSE-KMS).
