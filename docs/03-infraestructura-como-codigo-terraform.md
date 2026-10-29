# 03. Infraestructura como Código (IaC) con Terraform

## 1. Organización del Código de Infraestructura

Toda la infraestructura en la nube está declarada de forma declarativa dentro del directorio [`terraform-tesis-ir-secure-portal/`](file:///home/bryan/Projects/LOCALSTACK/localstack-tesis/terraform-tesis-ir-secure-portal/):

```text
terraform-tesis-ir-secure-portal/
├── main.tf                    # Declaración de todos los recursos AWS (~1,850 líneas)
├── variables.tf               # Variables parametrizables, tipos, valores por defecto y validaciones
├── outputs.tf                 # Salidas públicas, URIs, ARNs y nombres de recursos generados
├── terraform.tfvars.example   # Plantilla base para configuración local de credenciales y red
├── scripts/
│   └── user_data.sh.tpl       # Plantilla Bash de provisionamiento de la instancia EC2
├── lambda/
│   └── lambda_function.py     # Código fuente del Motor de Detección (Detector B)
└── playbooks/                 # Código fuente de los playbooks serverless en Python
    ├── notify_alert/
    ├── block_ip/
    ├── revoke_credentials/
    └── telegram_notifier/
```

---

## 2. Catálogo de Recursos Aprovisionados

### 2.1. Red y Perímetro (Networking)
| Recurso Terraform | Identificador AWS | Propósito Técnico |
|---|---|---|
| `aws_vpc.this` | `10.10.0.0/16` | Red virtual aislada para el laboratorio. |
| `aws_internet_gateway.this` | IGW del proyecto | Puerta de enlace hacia Internet para la subred pública. |
| `aws_subnet.public_a` | `10.10.1.0/24` | Subred pública donde reside la EC2 del portal web corporativo. |
| `aws_subnet.public_b` | `10.10.2.0/24` | Subred pública redundante en zona de disponibilidad B. |
| `aws_subnet.private_a` | `10.10.11.0/24` | Subred privada reservada para bases de datos o servicios internos. |
| `aws_subnet.private_b` | `10.10.12.0/24` | Subred privada secundaria reservada. |
| `aws_route_table.public` | Tabla pública | Enruta `0.0.0.0/0` hacia el Internet Gateway. |
| `aws_security_group.portal` | SG de la EC2 | Permite tráfico HTTP (80) filtrado por `http_allowed_cidrs` y SSH (22) estrictamente desde `ssh_allowed_cidr`. Bloquea todo lo demás. |

### 2.2. Computo y Servidor Web (Compute)
| Recurso Terraform | Tipo | Propósito Técnico |
|---|---|---|
| `aws_instance.portal` | `t3.micro` / `t2.micro` | Instancia EC2 con Amazon Linux 2023. Ejecuta Nginx como reverse proxy y la aplicación Python local en el puerto 8080. |
| `aws_iam_instance_profile.ec2` | Instance Profile | Asocia el rol IAM `ec2` a la instancia. |
| `aws_iam_role.ec2` | Rol IAM | Otorga únicamente permisos para `AmazonSSMManagedInstanceCore` y `cloudwatch:PutLogEvents` restringido al grupo del portal. **No posee permisos sobre S3, DynamoDB ni Lambda.** |

### 2.3. Almacenamiento Forense y Clasificación (S3)
| Recurso Terraform | Nombre generado | Propósito y Contenido |
|---|---|---|
| `aws_s3_bucket.logs` | `<prefix>-logs-<id>` | Almacena los registros históricos brutos de CloudTrail y VPC Flow Logs. |
| `aws_s3_bucket.evidence` | `<prefix>-evidence-<id>` | Repositorio de evidencias forenses inmutables. Estructurado en prefijos: `incident-01-bruteforce/`, `incident-02-port-scan/`, `incident-03-privilege-escalation/`, `incident-04-credential-leak/`, `incident-05-exfiltration/`, y respuestas: `responses/notify-alert/`, `responses/block-ip/`, `responses/revoke-credentials/`. |
| `aws_s3_bucket.sensitive` | `<prefix>-sensitive-<id>` | Bucket que contiene datos ficticios clasificados (`sensible/clientes_demo.json`) para la prueba de exfiltración de información. |

> [!NOTE]
> Todos los buckets S3 cuentan con `aws_s3_bucket_public_access_block` activo (bloqueo público total), versionado habilitado (`aws_s3_bucket_versioning`) y cifrado en reposo SSE-S3 (`AES256`).

### 2.4. Bases de Datos Serverless (DynamoDB)
| Recurso Terraform | Tabla | Claves | Propósito |
|---|---|---|---|
| `aws_dynamodb_table.incidents` | `tesis-ir_incidents` | HASH: `incident_id` | Registro histórico persistente de cada incidente detectado, con estado, severidad, IP atacante, activo y link a la evidencia S3. |
| `aws_dynamodb_table.state` | `tesis-ir_state` | HASH: `pk`, RANGE: `sk` | Tabla de alta velocidad con atributo TTL habilitado. Almacena contadores de ventanas deslizantes (5 minutos) para fuerza bruta y escaneo de puertos, y llaves de deduplicación de alertas. |

### 2.5. Mensajería y Desacoplamiento (SQS y SNS)
| Recurso Terraform | Nombre | Tipo | Consumidor |
|---|---|---|---|
| `aws_sqs_queue.incident_queue` | `tesis-ir-incident-queue` | SQS Estándar | Consumidores externos / Componente B |
| `aws_sqs_queue.playbook_notify_queue` | `tesis-ir-playbook-notify-alert-queue` | SQS Estándar | Lambda `playbook_notify` |
| `aws_sqs_queue.playbook_block_ip_queue` | `tesis-ir-playbook-block-ip-queue` | SQS Estándar | Lambda `playbook_block_ip` |
| `aws_sqs_queue.playbook_revoke_credentials_queue` | `tesis-ir-playbook-revoke-credentials-queue` | SQS Estándar | Lambda `playbook_revoke_credentials` |
| `aws_sns_topic.alerts` | `tesis-ir-alerts` | SNS Topic | Lambda `telegram_notifier` |

### 2.6. Identidad de Correo y Criptografía (Amazon SES)
| Recurso Terraform | Propósito |
|---|---|
| `aws_ses_domain_identity.soc` | Registra el dominio `soc.bryan-bano.com` en Amazon SES. |
| `aws_ses_domain_dkim.soc` | Genera los 3 tokens criptográficos DKIM para configuración CNAME en DNS. |
| `aws_ses_email_identity.alert` | Valida la dirección del remitente del SOC (`alertas@soc.bryan-bano.com`). |

### 2.7. Funciones Serverless (AWS Lambda)
| Recurso Terraform | Nombre de la Función | Runtime | Trigger |
|---|---|---|---|
| `aws_lambda_function.detector` | `lambda-tesis-ir-detector-b` | Python 3.12 | CloudWatch Log Subscription Filters |
| `aws_lambda_function.playbook_notify` | `lambda-tesis-ir-playbook-notify-alert` | Python 3.12 | SQS `playbook_notify_queue` |
| `aws_lambda_function.playbook_block_ip` | `lambda-tesis-ir-playbook-block-ip` | Python 3.12 | SQS `playbook_block_ip_queue` |
| `aws_lambda_function.playbook_revoke_credentials` | `lambda-tesis-ir-playbook-revoke-credentials` | Python 3.12 | SQS `playbook_revoke_credentials_queue` |
| `aws_lambda_function.telegram_notifier` | `lambda-tesis-ir-telegram-notifier` | Python 3.12 | SNS Topic `alerts` |

---

## 3. Matriz de Variables de Configuración (`variables.tf`)

| Variable | Tipo | Valor por Defecto | Descripción |
|---|---|---|---|
| `aws_region` | `string` | `"ca-central-1"` | Región AWS de despliegue. |
| `project_name` | `string` | `"tesis-ir"` | Prefijo unificado para nombres de recursos. |
| `ssh_allowed_cidr` | `string` | *Obligatorio* | Tu IP pública para acceso administrativo SSH (`x.x.x.x/32`). |
| `http_allowed_cidrs` | `list(string)` | `[]` | IPs autorizadas para acceder al portal web. Si se omite, usa `ssh_allowed_cidr`. |
| `alert_email` | `string` | `""` | Dirección de Gmail donde se recibirán los reportes del SOC. |
| `ses_domain` | `string` | `""` | Dominio institucional para firma DKIM (`soc.bryan-bano.com`). |
| `ses_sender_email` | `string` | `""` | Dirección remitente autorizada (`alertas@soc.bryan-bano.com`). |
| `telegram_bot_token` | `string` | `""` | Token del bot de Telegram expedido por @BotFather. |
| `telegram_chat_id` | `string` | `""` | ID numérico del canal o chat de Telegram donde se entregan las alertas. |
| `monthly_budget_limit_usd` | `number` | `5` | Límite mensual de gasto en dólares antes de generar alertas de costo. |
| `enable_s3_data_events` | `bool` | `false` | Activa eventos de datos S3 en CloudTrail (usar solo en pruebas de exfiltración). |
| `enable_aws_config` | `bool` | `false` | Habilita grabador de configuración de AWS Config. |
| `force_destroy_buckets` | `bool` | `true` | Permite a Terraform vaciar y destruir los buckets durante `terraform destroy`. |

---

## 4. Salidas Operativas (`outputs.tf`)

Al culminar exitosamente `terraform apply`, la consola expone las siguientes variables de conexión:

```hcl
portal_url                            = "http://15.222.x.x"
portal_public_ip                      = "15.222.x.x"
portal_instance_id                    = "i-0abc123456789def0"
vpc_id                                = "vpc-0123456789abcdef0"
logs_bucket                           = "tesis-ir-logs-a1b2c3d4"
evidence_bucket                       = "tesis-ir-evidence-a1b2c3d4"
sensitive_bucket                      = "tesis-ir-sensitive-a1b2c3d4"
dynamodb_incidents_table              = "tesis-ir_incidents"
dynamodb_state_table                  = "tesis-ir_state"
incident_queue_url                    = "https://sqs.ca-central-1.amazonaws.com/.../tesis-ir-incident-queue"
playbook_notify_lambda_name           = "lambda-tesis-ir-playbook-notify-alert"
playbook_block_ip_lambda_name         = "lambda-tesis-ir-playbook-block-ip"
playbook_revoke_credentials_lambda_name = "lambda-tesis-ir-playbook-revoke-credentials"
ses_dkim_tokens                       = ["token1", "token2", "token3"]
warning_optional_cost_resources       = "AWS Config=false, S3 Data Events=false, CloudTrail multi-region=false."
```
