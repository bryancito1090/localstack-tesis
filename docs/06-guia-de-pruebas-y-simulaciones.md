# 06. Guía Práctica de Pruebas y Simulaciones

Esta guía detalla el procedimiento paso a paso para simular y validar de manera controlada los 5 tipos de incidentes soportados por la arquitectura en AWS.

> Para una campaña del TIC, aplicar primero el [plan de evaluación cuantitativa](12-plan-evaluacion-cuantitativa-tic.md): define actores desechables, ventanas, controles, recuperación y evidencia. Los ejemplos siguientes son guiones funcionales originales, no un protocolo estadístico. No provocar revocaciones usando el usuario administrativo del despliegue; el detector señala al actor de la llamada y un administrador autorizado desde una IP permitida está exento.

---

## 1. Preparación del Entorno

### 1.1. Despliegue de la Infraestructura
Ubícate en la carpeta del proyecto Terraform:
```bash
cd terraform-tesis-ir-secure-portal
```

Verifica tu archivo de variables locales `terraform.tfvars`:
```hcl
aws_region       = "ca-central-1"
project_name     = "tesis-ir"
ssh_allowed_cidr = "TU_IP_PUBLICA/32"
alert_email      = "tu_correo@gmail.com"
ses_domain       = "soc.bryan-bano.com"
ses_sender_email = "alertas@soc.bryan-bano.com"
telegram_bot_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
telegram_chat_id   = "-1001234567890"
```

Aplica el plan de infraestructura:
```bash
terraform init
terraform apply -auto-approve
```

Guarda las salidas en variables de entorno de tu terminal:
```bash
export PORTAL_IP=$(terraform output -raw portal_public_ip)
export EVIDENCE_BUCKET=$(terraform output -raw evidence_bucket)
export SENSITIVE_BUCKET=$(terraform output -raw sensitive_bucket)
export VPC_ID=$(terraform output -raw vpc_id)
```

---

## 2. Simulación de Incidentes

### 2.1. Incidente 1: Ataque de Fuerza Bruta (`BRUTE_FORCE`)

#### Ejecución del Ataque:
Simula 5 intentos fallidos de autenticación contra el portal web:
```bash
for i in {1..5}; do
  curl -s -X POST "http://$PORTAL_IP/login" \
    -d "username=admin.demo&password=PasswordInvalido$i" \
    -o /dev/null
  echo "Intento fallido $i enviado"
  sleep 1
done
```

#### Validación de Resultados:
1. **CloudWatch Logs:** Revisa el log de la app en `/aws/ec2/tesis-ir-portal-app` (deben verse 5 eventos `login_failed`).
2. **Lambda Detector:** Revisa `/aws/lambda/lambda-tesis-ir-detector-b` (debe indicar que el contador superó el umbral 5).
3. **Mitigación en Network ACL:**
   ```bash
   aws ec2 describe-network-acls \
     --filters "Name=vpc-id,Values=$VPC_ID" \
     --query "NetworkAcls[*].Entries[?RuleAction=='deny']"
   ```
   *Debe existir una regla de entrada (Ingress) con acción `deny` hacia tu IP pública.*
4. **Notificaciones:**
   - **Gmail:** Correo con cabecera naranja (`HIGH`) y tarjeta HTML detallando el incidente.
   - **Telegram:** Imagen PNG con badge `BLOCKED` y datos del ataque.

#### Desbloqueo / Rollback:
Para recuperar el acceso al portal desde tu IP:
```bash
# Identifica el ID de la Network ACL y el número de regla (ej. 1)
NACL_ID=$(aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$VPC_ID" --query "NetworkAcls[0].NetworkAclId" --output text)
aws ec2 delete-network-acl-entry --network-acl-id $NACL_ID --rule-number 1 --ingress
```

---

### 2.2. Incidente 2: Escaneo de Puertos (`PORT_SCAN`)

#### Ejecución del Ataque:
Envía paquetes TCP hacia puertos cerrados de la instancia EC2 para forzar paquetes `REJECT` en el firewall:
```bash
# En Bash / Linux:
for port in {81..92}; do
  nc -z -v -w 1 $PORTAL_IP $port 2>/dev/null || true
done
```
*(Alternativa en PowerShell):*
```powershell
81..92 | ForEach-Object { Test-NetConnection $env:PORTAL_IP -Port $_ -InformationLevel Quiet }
```

#### Validación de Resultados:
1. **CloudWatch Logs:** Consulta el grupo `/aws/vpc/tesis-ir-flowlogs` (se reflejarán eventos con flag `REJECT` y puertos de destino 81 a 92).
2. **DynamoDB:** Consulta los registros de la tabla `tesis-ir_state` bajo la partición `portscan#<IP>#window#...`.
3. **Mitigación:** Se inserta una regla `DENY` en la Network ACL para la IP de origen y se envía la tarjeta visual de notificación a Telegram y Gmail.

---

### 2.3. Incidente 3: Escalada de Privilegios (`PRIVILEGE_ESCALATION`)

#### Ejecución del Ataque:
Crea un usuario IAM temporal y adjúntale una política administrativa:
```bash
# 1. Crear identidad de prueba
aws iam create-user --user-name tesis-ir-temp-escalation-test

# 2. Adjuntar política de privilegios (detonador del incidente)
aws iam attach-user-policy \
  --user-name tesis-ir-temp-escalation-test \
  --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess"
```

#### Validación de Resultados:
1. **CloudTrail:** El evento `AttachUserPolicy` es capturado y transferido a CloudWatch Logs.
2. **Lambda Detector:** Detecta la asignación y clasifica la severidad como `CRITICAL` (Rojo).
3. **Contención Real (Playbook `revoke-credentials`):**
   - Verifica que se haya adjuntado la política de contención:
     ```bash
     aws iam get-user-policy \
       --user-name tesis-ir-temp-escalation-test \
       --policy-name EmergencyDenyAll
     ```
4. **Notificaciones:** Se recibe la alerta en Gmail y Telegram con estado `CONTAINED`.

#### Limpieza:
```bash
aws iam delete-user-policy --user-name tesis-ir-temp-escalation-test --policy-name EmergencyDenyAll 2>/dev/null
aws iam detach-user-policy --user-name tesis-ir-temp-escalation-test --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess" 2>/dev/null
aws iam delete-user --user-name tesis-ir-temp-escalation-test
```

---

### 2.4. Incidente 4: Fuga de Credenciales (`CREDENTIAL_LEAK`)

#### Ejecución del Ataque:
Este incidente se gatilla cuando credenciales válidas realizan llamadas a la API de AWS desde una dirección IP no autorizada.

1. Configura temporalmente en `terraform.tfvars`:
   ```hcl
   authorized_ip_cidrs = ["10.0.0.1/32"] # IP ficticia para simular que tu IP actual es desconocida
   ```
2. Ejecuta `terraform apply -auto-approve`.
3. Llama a la API de AWS desde tu terminal habitual:
   ```bash
   aws sts get-caller-identity
   ```

#### Validación de Resultados:
- CloudTrail registra la invocación desde tu IP pública real.
- El detector compara la IP con `authorized_ip_cidrs`, constata que no está autorizada y despacha el incidente `CREDENTIAL_LEAK` con severidad `CRITICAL`.
- El playbook `revoke-credentials` inactiva las claves de acceso del usuario y le asigna `EmergencyDenyAll`.

*Restaura `authorized_ip_cidrs = []` y ejecuta `terraform apply` al finalizar.*

---

### 2.5. Incidente 5: Exfiltración de Datos S3 (`EXFILTRATION`)

#### Ejecución del Ataque:
1. Habilita temporalmente los eventos de datos S3 en `terraform.tfvars`:
   ```hcl
   enable_s3_data_events = true
   ```
2. Aplica la configuración:
   ```bash
   terraform apply -auto-approve
   ```
3. Ejecuta descargas consecutivas del archivo de datos sensibles simulados:
   ```bash
   for i in {1..55}; do
     aws s3 cp "s3://$SENSITIVE_BUCKET/sensible/clientes_demo.json" "/tmp/test_download_$i.json" > /dev/null
   done
   ```

#### Validación de Resultados:
- CloudTrail registra más de 50 eventos `GetObject` en la ventana de una hora.
- El detector genera la alerta `EXFILTRATION` con severidad `HIGH`.
- El playbook `notify-alert` emite el reporte forense completo vía SES a Gmail y vía SNS a Telegram.

*Al concluir la prueba, restablece `enable_s3_data_events = false` en `terraform.tfvars` y aplica con `terraform apply -auto-approve` para evitar cargos adicionales de CloudTrail.*

---

## 3. Destrucción de la Infraestructura (Control de Costos)

Al finalizar la sesión de pruebas o demostración, apaga toda la infraestructura con un solo comando:
```bash
terraform destroy -auto-approve
```
*Tus configuraciones en `terraform.tfvars` y los registros DNS en Cloudflare permanecerán intactos y listos para la próxima prueba.*
