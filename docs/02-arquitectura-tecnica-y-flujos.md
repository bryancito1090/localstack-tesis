# 02. Arquitectura Técnica y Flujos de Datos

## 1. Diagrama de Arquitectura Global

La infraestructura del laboratorio implementa un modelo **Serverless Event-Driven** (orientado a eventos) con alta disponibilidad y desacoplamiento mediante colas de mensajería (Amazon SQS) y tópicos de publicación/suscripción (Amazon SNS).

```mermaid
flowchart TB
    subgraph RedAWS ["AWS Virtual Private Cloud (10.10.0.0/16)"]
        subgraph SubredPub ["Subred Pública A (10.10.1.0/24)"]
            EC2["EC2 Portal Web Corporativo<br>(Amazon Linux 2023 / Nginx)"]
            CW_AGENT["CloudWatch Agent<br>(Daemon local)"]
        end
        NACL["Network Access Control List<br>(Contención Perimetral)"]
        ENI["Elastic Network Interface<br>(VPC Flow Logs)"]
    end

    subgraph Telemetria ["Captura y Almacenamiento Forense"]
        S3_LOGS[("S3 Logs Bucket<br>(Cifrado SSE-S3)")]
        S3_EVD[("S3 Evidence Bucket<br>(responses/ e incident-*)")]
        CT["AWS CloudTrail<br>(Gestión y S3 Data Events)"]
        CW_LOGS["Amazon CloudWatch Logs<br>(Filtros de Suscripción)"]
    end

    subgraph Deteccion ["Capa de Detección Serverless"]
        LAMBDA_DET["AWS Lambda: detector<br>(Python 3.12 / ZoneInfo)"]
        DDB_STATE[("DynamoDB: state_table<br>(Ventanas de Tiempo / TTL)")]
        DDB_INC[("DynamoDB: incidents_table<br>(Auditoría Operativa)")]
    end

    subgraph Colas ["Desacoplamiento con Amazon SQS"]
        Q_MAIN["tesis-ir-incident-queue<br>(Contrato Principal)"]
        Q_NOTIFY["tesis-ir-playbook-notify-alert-queue"]
        Q_BLOCK["tesis-ir-playbook-block-ip-queue"]
        Q_REVOKE["tesis-ir-playbook-revoke-credentials-queue"]
    end

    subgraph PlaybooksServerless ["Capa de Mitigación y Playbooks"]
        PB_NOTIFY["Lambda: playbook-notify-alert"]
        PB_BLOCK["Lambda: playbook-block-ip"]
        PB_REVOKE["Lambda: playbook-revoke-credentials"]
        PB_TG["Lambda: telegram-notifier"]
    end

    subgraph Canales ["Notificación y Alertas de Seguridad"]
        SES["Amazon SES<br>(DKIM @ soc.bryan-bano.com)"]
        SNS_TOPIC["Amazon SNS: alerts-topic"]
        GMAIL["Bandeja Gmail (HTML Card)"]
        TG_BOT["Telegram Bot (PNG Card Nativo)"]
    end

    EC2 -->|Escribe logs locales| CW_AGENT
    CW_AGENT -->|Transporte seguro| CW_LOGS
    ENI -->|Tráfico REJECT| CW_LOGS
    CT -->|Eventos de API| CW_LOGS
    CT -->|Auditoría forense| S3_LOGS

    CW_LOGS -->|Subscription Filters| LAMBDA_DET
    LAMBDA_DET <-->|Ventanas 5m / Deduplicación| DDB_STATE
    LAMBDA_DET -->|Registra incidente| DDB_INC
    LAMBDA_DET -->|Evidencia JSON crudo| S3_EVD

    LAMBDA_DET -->|Publicación| Q_MAIN
    LAMBDA_DET -->|Fan-Out Todos| Q_NOTIFY
    LAMBDA_DET -->|Fan-Out Red| Q_BLOCK
    LAMBDA_DET -->|Fan-Out Identidad| Q_REVOKE

    Q_NOTIFY -->|Trigger SQS| PB_NOTIFY
    Q_BLOCK -->|Trigger SQS| PB_BLOCK
    Q_REVOKE -->|Trigger SQS| PB_REVOKE

    PB_BLOCK -->|Crea regla DENY Inbound| NACL
    PB_REVOKE -->|Inactiva llaves + EmergencyDenyAll| IAM["AWS IAM Identity"]

    PB_NOTIFY -->|Envío de correo firmado| SES
    SES --> GMAIL

    PB_NOTIFY -->|Publica evento formateado| SNS_TOPIC
    PB_BLOCK -->|Publica estado de mitigación| SNS_TOPIC
    PB_REVOKE -->|Publica estado de contención| SNS_TOPIC

    SNS_TOPIC -->|Trigger SNS| PB_TG
    PB_TG -->|Renderiza PNG & sendPhoto| TG_BOT
```

---

## 2. Flujo Detallado de Telemetría e Ingesta

### 2.1. Aplicación Web y CloudWatch Agent
1. La aplicación corporativa simula un portal de autenticación empresarial desarrollado en Python (`app.py`), ejecutándose bajo el usuario del sistema `tesisportal` y detrás de un reverse proxy **Nginx**.
2. Por principio de mínimo privilegio, la instancia EC2 **no tiene permisos para invocar directamente CloudWatch, DynamoDB ni S3**.
3. La aplicación escribe eventos JSON puros en un archivo local: `/var/log/tesis-portal/app.log`.
4. El demonio oficial **Amazon CloudWatch Agent** lee continuamente el archivo local y lo transfiere de manera cifrada (TLS) al grupo de logs `/aws/ec2/tesis-ir-portal-app`.

### 2.2. Tráfico de Red (VPC Flow Logs)
1. Sobre la Elastic Network Interface (ENI) de la EC2 se habilitan VPC Flow Logs en formato estándar v2.
2. Cada paquete rechazado (`REJECT`) por los Security Groups se captura y se entrega directamente a CloudWatch Logs en `/aws/vpc/tesis-ir-flowlogs`.

### 2.3. Auditoría de Actividades (AWS CloudTrail)
1. CloudTrail captura todos los `Management Events` (eventos de administración como `CreateUser`, `AttachUserPolicy`, `GetCallerIdentity`, etc.) y los entrega en tiempo real al grupo `/aws/cloudtrail/tesis-ir-management`.
2. Opcionalmente (mediante la variable `enable_s3_data_events`), CloudTrail monitoriza llamadas a nivel de objeto S3 (`GetObject`, `PutObject`) sobre el bucket clasificado como confidencial.

---

## 3. Patrón de Desacoplamiento Fan-Out con SQS

Para evitar condiciones de carrera y la competencia de consumidores en colas únicas, el sistema implementa un **patrón de abanico (Fan-Out) gobernado por el Lambda Detector**:

1. **Cola de Contrato (`tesis-ir-incident-queue`):** Almacena todo incidente para cumplimiento con el Componente B y para posibilitar la conexión de consumidores externos futuros.
2. **Cola de Notificaciones (`tesis-ir-playbook-notify-alert-queue`):** Recibe **todos** los incidentes confirmados. Su consumidor (`playbook-notify-alert`) genera la notificación primaria para el equipo SOC.
3. **Cola de Mitigación de Red (`tesis-ir-playbook-block-ip-queue`):** Solo recibe incidentes clasificados como de amenaza perimetral (`BRUTE_FORCE`, `PORT_SCAN`). Su consumidor (`playbook-block-ip`) interactúa con la Network ACL.
4. **Cola de Mitigación de Identidad (`tesis-ir-playbook-revoke-credentials-queue`):** Solo recibe incidentes de compromiso de credenciales (`PRIVILEGE_ESCALATION`, `CREDENTIAL_LEAK`). Su consumidor (`playbook-revoke-credentials`) interactúa con AWS IAM.

---

## 4. Pipeline de Notificación y Generación Gráfica

```mermaid
sequenceDiagram
    autonumber
    participant D as Lambda Detector
    participant Q as SQS Playbook Queue
    participant N as Lambda notify-alert
    participant SES as Amazon SES (DKIM)
    participant SNS as Amazon SNS Topic
    participant TG as Lambda telegram-notifier
    participant BOT as Telegram Bot API

    D->>Q: Encola evento normalizado
    Q->>N: Despacha lote (Batch size = 1)
    N->>N: Genera HTML formal (3 bloques, sin emojis)
    N->>SES: SendRawEmail con encabezados DKIM / soc.bryan-bano.com
    SES-->>N: ID de mensaje enviado (250 OK)
    N->>SNS: Publish (Payload estructurado para Telegram)
    SNS->>TG: Notificación Push vía SNS Subscription
    TG->>TG: card_image.py rasteriza imagen PNG (800x480px, fuente 5x7)
    TG->>BOT: HTTP POST multipart/form-data (sendPhoto)
    BOT-->>TG: Confirmación de entrega al canal móvil
```

### Características de las Notificaciones:
- **Estructura Estricta de 3 Bloques:**
  1. `INFORMACION GENERAL`: Tipo de incidente, ID único, estado y playbook activo.
  2. `RECURSO Y ORIGEN / CONTENCION`: IP atacante, recurso AWS afectado, servicio y activo.
  3. `CRITERIO Y TRAZABILIDAD`: Umbrales de detección superados, timestamp local de Ecuador (`America/Guayaquil`) y URI del objeto en S3.
- **Identidad Gráfica:**
  - Código cromático según severidad: Rojo (`CRITICAL`), Naranja (`HIGH`), Ámbar (`MEDIUM`), Azul (`LOW` / `CONTAINED`).
  - Cero dependencias binarias externas: el renderizado visual de la imagen PNG se realiza mediante álgebra de bytes pura (`zlib` + `struct`).
