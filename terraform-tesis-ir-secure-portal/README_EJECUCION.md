# Terraform - Laboratorio AWS de detección de incidentes

Este proyecto crea una infraestructura de laboratorio para detección de incidentes en AWS con enfoque de bajo costo/capa gratuita. La versión actual reemplaza el botón simple de generación de logs por un portal realista de autenticación con login, dashboard, bloqueo temporal e instrucciones de prueba.

## Qué crea

- VPC `10.10.0.0/16`
- 2 subredes públicas y 2 subredes privadas reservadas
- Internet Gateway y tabla de rutas pública
- Security Group para portal HTTP restringible por CIDR y SSH limitado a tu IP
- EC2 Amazon Linux 2023 con portal web de autenticación de laboratorio
- Nginx como reverse proxy hacia la app Python local
- CloudWatch Agent para logs de Nginx y aplicación
- CloudWatch Logs `/aws/ec2/tesis-ir-portal-app`
- S3 para logs, evidencia e información sensible ficticia
- CloudTrail hacia S3 y CloudWatch Logs
- VPC Flow Logs sobre la ENI de la EC2
- DynamoDB para incidentes y estado temporal
- SQS `tesis-ir-incident-queue` para publicar el JSON normalizado requerido por el componente B
- Lambda Detector B
- SNS para alertas
- Metric filters y alarmas CloudWatch
- Athena Workgroup
- Budget opcional si defines `alert_email`
- AWS Config opcional

## Seguridad aplicada

- El portal web NO tiene credenciales AWS y NO puede consultar CloudWatch, Lambda, DynamoDB ni S3.
- El portal solo escribe eventos JSON locales en `/var/log/tesis-portal/app.log`.
- CloudWatch Agent, instalado en la EC2, lee ese archivo y lo envía a CloudWatch Logs.
- La EC2 usa IMDSv2 obligatorio.
- El volumen EBS está cifrado.
- Los buckets S3 tienen bloqueo total de acceso público, versionado y cifrado SSE-S3.
- SSH se limita a `ssh_allowed_cidr`.
- HTTP se limita a `http_allowed_cidrs`; si queda vacío, usa automáticamente `ssh_allowed_cidr`.
- Lambda usa un rol IAM separado y solo puede escribir en DynamoDB, S3 Evidence, SNS, SQS y métricas `TesisIR`.

## Importante sobre costos

Para reducir costos, este proyecto NO crea:

- NAT Gateway
- Load Balancer
- RDS
- OpenSearch
- Network Firewall
- Elastic IP

Por defecto deja apagados:

```hcl
enable_s3_data_events = false
enable_aws_config     = false
cloudtrail_multi_region = false
```

Activa `enable_s3_data_events=true` solo cuando vayas a probar EXFILTRATION. Activa `enable_aws_config=true` solo cuando necesites evidencia adicional de cambios de configuración/IAM.

## Uso

Copia el ejemplo:

```powershell
copy terraform.tfvars.example terraform.tfvars
```

Edita:

```hcl
ssh_allowed_cidr = "TU_IP_PUBLICA/32"
http_allowed_cidrs = []
alert_email = "tu_correo@ejemplo.com"
```

Inicializa:

```powershell
terraform init
```

Revisa:

```powershell
terraform validate
terraform plan -out=tfplan
```

Aplica:

```powershell
terraform apply "tfplan"
```

Cuando termine, Terraform mostrará:

```text
portal_url
portal_public_ip
evidence_bucket
dynamodb_incidents_table
lambda_detector_name
incident_queue_url
```

Abre `portal_url` en el navegador.

## Usuarios del portal

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin.demo` | `AdminDemo#2026` | Administrador AWS simulado |
| `soc.demo` | `SocDemo#2026` | Analista SOC simulado |
| `usuario.demo` | `UsuarioDemo#2026` | Usuario estándar simulado |

## Flujo de logs del portal

```text
Navegador
→ EC2/Nginx
→ App Python /opt/tesis-portal/app.py
→ /var/log/tesis-portal/app.log
→ CloudWatch Agent
→ CloudWatch Logs /aws/ec2/tesis-ir-portal-app
→ Subscription Filter
→ Lambda Detector B
→ DynamoDB + S3 Evidence + SQS + SNS
```

## Incidentes normalizados en SQS

Lambda publica en `tesis-ir-incident-queue` un JSON con las variables obligatorias por incidente:

- `incident_type`
- `severity`
- `sourceIPAddress`
- `affectedResource`
- `s3_log_key`
- `timestamp`
- `event_count`

También añade variables opcionales como `failed_attempts`, `scanned_ports_count`, `suspicious_actions`, `service_accessed`, `total_downloads` o `affected_bucket`, según el incidente.

## Destruir laboratorio

```powershell
terraform plan -destroy -out=tfdestroy
terraform apply "tfdestroy"
```

Por defecto `force_destroy_buckets=true`, así que Terraform puede eliminar buckets con objetos. Para evidencia real usa:

```hcl
force_destroy_buckets = false
```


## Playbooks de mitigación para Incidente 1

Esta versión integra dos playbooks Lambda para `BRUTE_FORCE`:

- `lambda-tesis-ir-playbook-notify-alert`: recibe el incidente desde una cola SQS dedicada, publica una alerta en SNS y guarda auditoría en `S3 Evidence/responses/notify-alert/`.
- `lambda-tesis-ir-playbook-block-ip`: recibe el mismo incidente desde otra cola SQS dedicada y aplica contención real creando una regla `DENY` de entrada en la Network ACL de la VPC para la IP origen del ataque. También guarda evidencia en `S3 Evidence/responses/block-ip/`.

El detector sigue publicando el JSON normalizado principal en `tesis-ir-incident-queue`, pero para evitar que dos Lambdas compitan por el mismo mensaje SQS se agregaron dos colas internas de playbooks: `tesis-ir-playbook-notify-alert-queue` y `tesis-ir-playbook-block-ip-queue`.

Advertencia operacional: cuando `block-ip` bloquee tu IP pública, el portal puede dejar de cargar desde esa IP. Esto es esperado porque representa la mitigación real del incidente. Para recuperar el acceso, elimina la regla DENY creada en la Network ACL o vuelve a desplegar/ajustar la infraestructura con Terraform.
