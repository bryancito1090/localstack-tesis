# Incidente 3 — PRIVILEGE_ESCALATION CRITICAL

**Qué pasa:** Un usuario o identidad ejecuta acciones críticas de IAM que no le corresponden, como adjuntar políticas de administrador (`AttachUserPolicy` con `AdministratorAccess`), crear llaves de acceso (`CreateAccessKey`) o crear usuarios/grupos sin autorización. Es una fase crítica donde un atacante busca consolidar control total del plano de control de AWS.

┌───────────────────────┬────────────────────────────────────────────────┐
│        Acción         │                    Por qué                     │
├───────────────────────┼────────────────────────────────────────────────┤
│ 🔔 notify-alert →     │ Alerta de máxima prioridad (CRITICAL). Alguien │
│ SNS/email             │ está intentando escalar privilegios en IAM.    │
├───────────────────────┼────────────────────────────────────────────────┤
│ 🚫 revoke-credentials │ Invalidación de credenciales en caliente:      │
│ (Playbook automático) │ Desactiva las Access Keys del usuario y le     │
│                       │ aplica una política EmergencyDenyAll en IAM.  │
└───────────────────────┴────────────────────────────────────────────────┘

---

# Guía de Simulación de Escalada de Privilegios y Respuesta Automatizada

Ejecuta este flujo paso a paso en tu terminal dentro de `/home/bryan/localstack-tesis/terraform-tesis-ir-secure-portal` o en el directorio raíz según corresponda.

## 🗑️ PASO PREVIO (Desplegar y Verificar)

Asegúrate de que la infraestructura esté desplegada con Terraform:
```bash
terraform apply -auto-approve
```
*(Esto desplegará la cola SQS `playbook-revoke-credentials-queue`, la Lambda del detector y el playbook de revocación de credenciales)*

---

## 🎯 PASO 1 — Simular el Ataque de Escalada de Privilegios

### 🧠 Fundamento Técnico (Para el jurado)
El ataque consiste en que una identidad comprometida abusa de permisos para crear un nuevo usuario de persistencia y adjuntarse políticas administrativas, generando eventos CloudTrail críticos:
1. `CreateUser`: Creación de un usuario no autorizado.
2. `AttachUserPolicy`: Intento de adjuntar la política de lectura o administración.

El Detector Lambda monitorea CloudTrail y genera una alerta automática de severidad **CRITICAL** al identificar llamadas a `iam.amazonaws.com` con estos nombres de eventos. Luego, la Lambda despacha el incidente a la cola del playbook `revoke-credentials` para realizar la mitigación inmediata.

### ⛓️ La Cadena de Eventos
```
Atacante (API / CLI)
    │
    │  1. CreateUser (tesis-ir-temp-escalation-test)
    │  2. AttachUserPolicy (ReadOnlyAccess / AdministratorAccess)
    ▼
AWS IAM plano de control
    │
    │  Genera eventos CloudTrail ("CreateUser", "AttachUserPolicy")
    ▼
CloudWatch Logs ➔ Subscription Filter ➔ Lambda Detector
    │
    │  Detecta evento crítico de IAM.
    │  Envía el incidente a SQS (incident-queue y playbook-revoke-credentials-queue).
    ▼
Playbook Automatizado (revoke-credentials):
    ├── IAM: Desactiva todas las Access Keys del usuario de forma inmediata (Active -> Inactive).
    ├── IAM: Adjunta la política inline "EmergencyDenyAll" (Deny * en Resource *).
    ├── S3: Log de auditoría en responses/revoke-credentials/revoked-credentials.json.
    └── SNS: Envío de alerta crítica por correo electrónico informando la mitigación exitosa.
```

### 💻 Ejecución del Ataque (Simulación)

Puedes simular el ataque mediante comandos de terminal (Opción A) o directamente desde la consola web (Opción B). Ambas opciones generarán los mismos eventos de CloudTrail e invocarán la automatización de mitigación.

#### Opción A: Usando AWS CLI (Terminal)
```bash
# 1. Crear el usuario de prueba
aws iam create-user --user-name tesis-ir-temp-escalation-test --region ca-central-1

# 2. Adjuntar política de lectura (Simula la escalada)
aws iam attach-user-policy --user-name tesis-ir-temp-escalation-test --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --region ca-central-1
```

#### Opción B: Simulación Visual Segura desde la Consola Web de AWS
Para mostrar al jurado el flujo de mitigación en vivo de forma 100% gráfica y segura (evitando que tu usuario administrador principal `desarrollador-cli` se bloquee a sí mismo):

**Fase 1: Preparación (Como Administrador)**
1. Inicia sesión en la **Consola de Administración de AWS** con tu cuenta administradora (`desarrollador-cli`).
2. Navega al servicio **IAM** y haz clic en **Users** (Usuarios) en el menú lateral izquierdo.
3. Haz clic en el botón **Create user** (Crear usuario):
   - **User name:** Escribe exactamente `tesis-ir-temp-escalation-test`.
   - **Console access:** Marca la casilla **Provide user access to the AWS Management Console**.
   - **Identity Center:** Elige **I want to create an IAM user**.
   - **Password:** Selecciona **Custom password** e ingresa una contraseña que recuerdes. Desmarca la opción de cambiar contraseña en el primer inicio de sesión.
   - Haz clic en **Next** (Siguiente).
4. En opciones de permisos, selecciona **Attach policies directly** (Asociar políticas directamente), busca y marca la política **`IAMReadOnlyAccess`** (esto le dará permisos mínimos de lectura, pero no de escritura).
5. Haz clic en **Next** y luego en **Create user** (Crear usuario).
6. Selecciona el usuario recién creado `tesis-ir-temp-escalation-test` de la lista de usuarios:
   - Ve a la pestaña **Security credentials** (Credenciales de seguridad).
   - En la sección **Access keys** (Claves de acceso), haz clic en **Create access key** (Crear clave de acceso).
   - Selecciona **Command Line Interface (CLI)** u **Other**, acepta el checkbox de confirmación, haz clic en **Next** y luego en **Create access key**.
   - *(Esto creará una clave de acceso en estado **Active** asignada al usuario de prueba, que servirá como blanco de mitigación).*

**Fase 2: Simulación del Ataque (Como el Atacante)**
1. Abre una ventana en **Modo Incógnito** en tu navegador.
2. Inicia sesión en la consola de AWS utilizando la URL de inicio de sesión de tu cuenta con el usuario de prueba `tesis-ir-temp-escalation-test` y la contraseña que creaste.
3. Una vez dentro de la sesión limitada, ve al servicio **IAM** e intenta realizar un cambio no autorizado (escalada de privilegios):
   - Intenta crear un nuevo usuario o intenta asociarte a ti mismo la política `AdministratorAccess`.
   - El sistema te mostrará un mensaje de **Access Denied** (Acceso Denegado) en letras rojas. Esto es normal y generará un evento de auditoría en CloudTrail.

**Fase 3: Verificación del Bloqueo (Como Administrador)**
1. Vuelve a tu ventana del navegador normal (donde tienes la sesión de administrador `desarrollador-cli`).
2. Espera de 1 a 2 minutos (tiempo de entrega de logs de CloudTrail) y **actualiza (refresca) la página del navegador** del usuario `tesis-ir-temp-escalation-test`:
   - Ve a la pestaña **Security credentials**: Verás que el estado de la clave de acceso de prueba cambió automáticamente a **Inactive** (desactivada por la automatización).
   - Ve a la pestaña **Permissions**: Verás que ahora tiene asociada la política inline de bloqueo llamada **`EmergencyDenyAll`** (quitándole todos los accesos).
   - En la ventana de Incógnito del atacante, si intentas navegar a cualquier otro recurso, verás que ha sido completamente bloqueado.

---

## 🔍 PASO 2 — Demostración de Mitigación y Respuesta Automatizada

*Espera de 1 a 2 minutos para permitir que CloudTrail registre los eventos de IAM, se envíen a CloudWatch Logs y las Lambdas procesen la alerta y la mitigación.*

### 🚫 2a — Contención Activa en IAM (Verificación del Bloqueo)
Una vez mitigado el incidente, las Access Keys del usuario objetivo deben haber sido desactivadas y su cuenta debe estar bajo una política Deny-All:

```bash
# Verificar que las Access Keys están "Inactive"
aws iam list-access-keys --user-name tesis-ir-temp-escalation-test --region ca-central-1 --output table

# Verificar la política inline de bloqueo "EmergencyDenyAll"
aws iam get-user-policy --user-name tesis-ir-temp-escalation-test --policy-name EmergencyDenyAll --region ca-central-1
```

### 📁 2b — Pista de Auditoría en S3
Muestra que el log del playbook registrando las acciones de revocación tomadas se archivó en el bucket de evidencias:

```bash
aws s3 cp "s3://$(terraform output -raw evidence_bucket)/responses/revoke-credentials/revoked-credentials.json" - --region ca-central-1
```

### 🗄️ 2c — Registro en Base de Datos (DynamoDB)
Consulta la tabla de incidentes. Deberá figurar un incidente de tipo `PRIVILEGE_ESCALATION` con severidad `CRITICAL` y el affectedResource en formato `iam:user/tesis-ir-temp-escalation-test`:

```bash
aws dynamodb scan --table-name tesis-ir_incidents --region ca-central-1 --output table
```

### 📨 2d — Mensaje Normalizado en la Cola SQS
Verifica si el mensaje estructurado llegó a la cola del Componente B/C:

```bash
aws sqs receive-message --queue-url $(terraform output -raw incident_queue_url) --region ca-central-1
```

---

## 🧹 PASO 3 — Limpieza del Entorno de Simulación

Para restaurar el entorno a su estado original sin dejar residuos de seguridad en IAM:

```bash
# Eliminar política EmergencyDenyAll
aws iam delete-user-policy --user-name tesis-ir-temp-escalation-test --policy-name EmergencyDenyAll --region ca-central-1

# Desasociar política ReadOnlyAccess
aws iam detach-user-policy --user-name tesis-ir-temp-escalation-test --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --region ca-central-1

# Eliminar usuario de prueba
aws iam delete-user --user-name tesis-ir-temp-escalation-test --region ca-central-1
```
