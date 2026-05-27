# Incidente 2 — PORT_SCAN MEDIUM

**Qué pasa:** Alguien enumera la infraestructura (`DescribeInstances`, `DescribeVpcs`, etc.) o intenta conectar a múltiples puertos cerrados. Es el primer paso de reconocimiento antes de un ataque real.

┌───────────────────────┬────────────────────────────────────────────────┐
│        Acción         │                    Por qué                     │
├───────────────────────┼────────────────────────────────────────────────┤
│ 🔔 notify-alert →     │ Avisar al equipo: hay alguien mapeando la red  │
│ SNS/email             │                                                │
├───────────────────────┼────────────────────────────────────────────────┤
│ 🚫 block-ip → regla   │ Cortar el reconocimiento antes de que el       │
│ DENY en NACL          │ atacante pueda actuar. Respuesta proactiva     │
└───────────────────────┴────────────────────────────────────────────────┘

---

# Guía de Escaneo de Puertos y Respuesta Automatizada

Ejecuta este flujo paso a paso en tu terminal de Zsh dentro de `/home/bryan/localstack-tesis/terraform-tesis-ir-secure-portal`.

## 🗑️ PASO PREVIO (Hazlo AHORA mismo para borrar todo)

Deja tu cuenta en cero para que no gaste nada durante el día:

```bash
terraform destroy -auto-approve

```

## 🔑 PASO 1 (En la Noche) — Cargar Credenciales

Abre tu terminal limpia frente al profesor y carga tus llaves de AWS (asegúrate de usar tus credenciales activas y sin comillas extrañas):

```bash
export AWS_ACCESS_KEY_ID=TU_ACCESS_KEY_ACTIVA
export AWS_SECRET_ACCESS_KEY=TU_SECRET_KEY_ACTIVA
export AWS_DEFAULT_REGION=ca-central-1

```

Valida rápido ante el jurado que estás conectado a AWS:

```bash
aws sts get-caller-identity

```

## 🚀 PASO 2 — Inicializar y Desplegar (~3-4 min)

Inicializa los componentes locales de Terraform:

```bash
terraform init

```

Lanza la creación automática de tus 103 recursos en Canadá:

```bash
terraform apply -auto-approve

```

> [!NOTE]
> **Acción en vivo:** Abre tu correo `banobryan1090@gmail.com`. Busca el email de AWS con el asunto "Subscription Confirmation" y dale clic en "Confirm subscription" para que se activen las alertas por correo en vivo.

---

## 🎯 PASO 3 — Simular el Ataque de Escaneo de Puertos

### 🧠 Fundamento Técnico (Para explicar al jurado)

El comando que vas a ejecutar realiza un escaneo de puertos en paralelo usando loops de shell nativos:

```bash
for port in $(seq 81 92); do
    nc -zv -w 1 "$ip" "$port" &   # Intento de conexión TCP al puerto
done

```

`nc` (netcat) intenta abrir una conexión TCP real a cada puerto de la EC2. Como esos puertos están cerrados en el Security Group, AWS los rechaza inmediatamente.

### ⛓️ La Cadena de Eventos

```
Tu PC (IP Pública)
    │
    │  SYN → puerto 81
    │  SYN → puerto 82   (12 intentos en paralelo)
    │  ...
    │  SYN → puerto 92
    ▼
EC2 en AWS (IP pública)
    │
    │  Security Group: solo permite puertos autorizados (ej. 22 y 80)
    │  → Todos los demás: REJECT
    ▼
VPC Flow Logs captura cada rechazo en caliente:
    "190.9.182.58 → 10.10.1.10 puerto 81  REJECT"
    "190.9.182.58 → 10.10.1.10 puerto 82  REJECT"
    ...
    ▼
CloudWatch Logs ➔ Subscription Filter ➔ Lambda Detector
    │
    │  Cuenta: 12 puertos distintos rechazados desde la misma IP en 5 minutos.
    │  Threshold (Umbral) = 10 ➔ ¡PORT_SCAN detectado con éxito!
    ▼
Respuesta Automatizada (Playbooks):
    ├── DynamoDB: Incidente registrado de manera estructurada.
    ├── S3: Evidencia forense y respuestas guardadas de forma inmutable.
    ├── SNS: Email de alerta crítico enviado al equipo SOC.
    └── NACL: Regla DENY para la IP atacante (Aislamiento perimetral).

```

### ⚠️ Consecuencia Importante para la Demo

Tu PC es el "atacante" en esta simulación. Cuando el sistema responda, **bloqueará tu propia IP pública en la NACL**. Esto significa que tras el bloqueo:

* ❌ Ya no podrás hacer SSH a la EC2.
* ❌ Ya no podrás cargar el portal web desde tu navegador (dará Timeout).
* Puedes seguir usando la consola web de AWS (es tráfico HTTPS diferente mediante la API global).
* Puedes seguir usando `aws cli` y `terraform` desde tu terminal (también viajan por la API de AWS y no por la red interna atacada).

> **Consejo de oro:** Explícale esta consecuencia al profesor **antes** de correr el scan. Así entenderá que la pérdida de acceso web posterior es la prueba rotunda de que tu sistema funciona de verdad.

### 💻 Ejecución del Ataque

*Espera 2 minutos tras el apply para que la EC2 inicie servicios.* Ejecuta el comando:

```bash
ip=$(terraform output -raw portal_public_ip) && echo "Target IP: $ip" && for port in $(seq 81 92); do nc -zv -w 1 "$ip" "$port" 2>&1 & done && wait && echo "Scan listo"

```

---

## 🔍 PASO 4 — Demostración Forense y de Respuesta Automatizada

*Espera 2 minutos para dar tiempo a que las funciones Lambda procesen los flujos de red y disparen los playbooks.*

### 🗄️ 4a — Evidencia en Base de Datos (Éxito de la Lambda de Análisis)

Muestra la tabla de incidentes para validar que el Port Scan se guardó con su severidad:

```bash
aws dynamodb scan --table-name tesis-ir_incidents --region ca-central-1 --output table

```

### 📨 4b — Mensaje Normalizado en la Cola SQS

Comprueba la existencia del evento en formato estándar dentro de la cola de mensajería:

```bash
aws sqs receive-message --queue-url $(terraform output -raw incident_queue_url) --region ca-central-1

```

### 📁 4c — Almacenamiento Forense Inmutable en S3

Muestra que los artefactos crudos del ataque y las respuestas de mitigación se archivaron en el bucket:

```bash
aws s3 ls "s3://$(terraform output -raw evidence_bucket)/incident-02-port-scan/" --region ca-central-1

```

### 🚫 4d — Verificación de Contención Activa en la NACL (Capa de Red)

Ejecuta esto para auditar la regla perimetral. Deberá aparecer una regla **DENY** apuntando directamente a tu IP de origen:

```bash
aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$(terraform output -raw vpc_id)" --query "NetworkAcls[0].Entries[?Egress==\`false\` && RuleAction==\`deny\`].[RuleNumber,CidrBlock,RuleAction]" --output table --region ca-central-1

```

---

## 🛠️ PASO 5 — Desbloqueo Manual en Vivo (Opcional para recuperar acceso)

Si después de verificar la NACL quieres demostrarle al profesor que puedes revertir la mitigación manualmente desde la terminal para recuperar el acceso a la web sin destruir el entorno, corre este comando limpio:

```bash
aws ec2 delete-network-acl-entry --network-acl-id $(terraform output -raw vpc_id | xargs -I {} aws ec2 describe-network-acls --filters "Name=vpc-id,Values={}" --query "NetworkAcls[0].NetworkAclId" --output text --region ca-central-1) --rule-number 1 --ingress --region ca-central-1

```

*(Nota: Revisa el número de regla en el paso 4d, usualmente la regla inyectada es la número 1).*

---

## 🗑️ PASO 6 — Cierre de la Defensa (Destrucción de Recursos)

Termina tu ronda de preguntas demostrando que la infraestructura es efímera y se limpia por completo para no generar costos:

```bash
terraform destroy -auto-approve

```