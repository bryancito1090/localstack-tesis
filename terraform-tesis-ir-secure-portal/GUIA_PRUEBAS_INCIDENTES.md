# Guía de pruebas de incidentes

## Incidente 1: BRUTE_FORCE

1. Abre `portal_url`.
2. Usa `admin.demo` con contraseña incorrecta 5 veces.
3. Verifica:
   - CloudWatch Logs → `/aws/ec2/tesis-ir-portal-app`
   - Lambda → `/aws/lambda/lambda-tesis-ir-detector-b`
   - DynamoDB → `tesis-ir_incidents`
   - S3 Evidence → `incident-01-bruteforce/`
   - SQS → `tesis-ir-incident-queue`

Variables publicadas:

```json
{
  "incident_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "sourceIPAddress": "IP origen",
  "affectedResource": "iam:user/admin.demo",
  "s3_log_key": "incident-01-bruteforce/INC-....json",
  "timestamp": "fecha deteccion",
  "event_count": 5,
  "failed_attempts": 5,
  "detection_window": "5 minutes"
}
```

## Incidente 2: PORT_SCAN

Prueba solo contra tu propia EC2.

```powershell
$ip = terraform output -raw portal_public_ip
81..92 | ForEach-Object { Test-NetConnection $ip -Port $_ -InformationLevel Quiet }
```

Verifica:

- CloudWatch Logs → `/aws/vpc/tesis-ir-flowlogs`
- S3 Evidence → `incident-02-port-scan/`
- SQS → `tesis-ir-incident-queue`

## Incidente 3: PRIVILEGE_ESCALATION

Ejemplo controlado:

```powershell
aws iam create-user --user-name tesis-ir-temp-escalation-test
aws iam attach-user-policy --user-name tesis-ir-temp-escalation-test --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

Limpieza:

```powershell
aws iam detach-user-policy --user-name tesis-ir-temp-escalation-test --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam delete-user --user-name tesis-ir-temp-escalation-test
```

Verifica:

- CloudTrail Event history → `CreateUser` o `AttachUserPolicy`
- CloudWatch Logs → `/aws/cloudtrail/tesis-ir-management`
- S3 Evidence → `incident-03-privilege-escalation/`
- SQS → `tesis-ir-incident-queue`

## Incidente 4: CREDENTIAL_LEAK

Este incidente se detecta cuando una identidad válida ejecuta acciones como `GetCallerIdentity` desde una IP no autorizada.

Para probarlo de forma controlada, configura `authorized_ip_cidrs` con una IP ficticia y ejecuta:

```powershell
aws sts get-caller-identity
```

Verifica:

- CloudTrail Event history → `GetCallerIdentity`
- CloudWatch Logs → `/aws/cloudtrail/tesis-ir-management`
- S3 Evidence → `incident-04-credential-leak/`
- SQS → `tesis-ir-incident-queue`

Luego restaura `authorized_ip_cidrs = []` o tu IP real.

## Incidente 5: EXFILTRATION

Activa temporalmente:

```hcl
enable_s3_data_events = true
```

Aplica:

```powershell
terraform apply
```

Luego ejecuta descargas repetidas del objeto ficticio:

```powershell
$bucket = terraform output -raw sensitive_bucket
1..55 | ForEach-Object { aws s3 cp "s3://$bucket/sensible/clientes_demo.json" ".\clientes_demo_$_.json" }
```

Verifica:

- CloudTrail Event history → `GetObject`
- CloudWatch Logs → `/aws/cloudtrail/tesis-ir-management`
- S3 Evidence → `incident-05-exfiltration/`
- SQS → `tesis-ir-incident-queue`

Después apaga:

```hcl
enable_s3_data_events = false
```

```powershell
terraform apply
```


## Playbooks de mitigación para Incidente 1

Esta versión integra dos playbooks Lambda para `BRUTE_FORCE`:

- `lambda-tesis-ir-playbook-notify-alert`: recibe el incidente desde una cola SQS dedicada, publica una alerta en SNS y guarda auditoría en `S3 Evidence/responses/notify-alert/`.
- `lambda-tesis-ir-playbook-block-ip`: recibe el mismo incidente desde otra cola SQS dedicada y aplica contención real creando una regla `DENY` de entrada en la Network ACL de la VPC para la IP origen del ataque. También guarda evidencia en `S3 Evidence/responses/block-ip/`.

El detector sigue publicando el JSON normalizado principal en `tesis-ir-incident-queue`, pero para evitar que dos Lambdas compitan por el mismo mensaje SQS se agregaron dos colas internas de playbooks: `tesis-ir-playbook-notify-alert-queue` y `tesis-ir-playbook-block-ip-queue`.

Advertencia operacional: cuando `block-ip` bloquee tu IP pública, el portal puede dejar de cargar desde esa IP. Esto es esperado porque representa la mitigación real del incidente. Para recuperar el acceso, elimina la regla DENY creada en la Network ACL o vuelve a desplegar/ajustar la infraestructura con Terraform.
