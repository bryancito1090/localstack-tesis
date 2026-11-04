# 10. Guía Operativa: Configuración de Nueva Cuenta AWS y Migración a Forgejo

Esta guía detalla de manera exhaustiva y paso a paso el procedimiento manual para aprovisionar credenciales en tu nueva cuenta de AWS (**Idea Incubator**, Account ID `056176271407`), configurarlas de forma 100% segura en tu máquina local sin exponer secretos, y sincronizar el repositorio completo con tu servidor personal de **Forgejo** (`https://git.bryan-bano.com`).

---

## 1. Contexto de la Nueva Cuenta de AWS

En la consola de administración de AWS se observa la siguiente configuración activa:
- **Organización / Proyecto:** `Idea Incubator | ElBryan1090`
- **Account ID:** `056176271407`
- **Región Activa:** `us-east-2` (EE.UU. Este - Ohio)
- **Créditos Disponibles:** `$100.00 USD` con vigencia de 182 días (hasta mayo de 2027)
- **Servicios Principales:** EC2, S3, CloudWatch, IAM, SQS, SNS, SES, DynamoDB, Lambda

> [!NOTE]
> En la parte superior de la consola aparece un banner que indica *"Connect your AI coding agent to AWS - [Copy agent prompt]"*. Ese botón sirve para exportar un prompt conversacional, pero para que herramientas de infraestructura como **Terraform**, **Ansible** y la **AWS CLI** interactúen con la nube, se requiere obligatoriamente un par de credenciales programáticas estables (**Access Key ID** y **Secret Access Key**) creadas mediante el servicio **AWS IAM**.

---

## 2. Paso a Paso Clic por Clic en la Consola de AWS

### Paso 2.1. Navegar al Servicio IAM
1. En tu navegador web, dentro de la consola de AWS activa (`us-east-2`), haz clic en la barra de búsqueda global superior (o presiona el atajo `Alt + S`).
2. Escribe `IAM` y presiona `Enter` (o haz clic en el primer resultado: **IAM - Manage access to AWS resources**).
3. Aparecerá el panel principal de **Identity and Access Management (IAM)**.

### Paso 2.2. Crear el Usuario de Administración para la Tesis
1. En el menú de navegación lateral izquierdo, haz clic en **Users** (Usuarios).
2. En la esquina superior derecha de la tabla, haz clic en el botón naranja **Create user** (Crear usuario).
3. **Paso 1: Especificar detalles de usuario:**
   - **User name:** Escribe `admin-tesis` (o `admin-terraform`).
   - Deja **desmarcada** la casilla *"Provide user access to the AWS Management Console"* (este usuario es exclusivamente para uso de terminal, Terraform y Ansible, no para iniciar sesión en la web).
   - Haz clic en el botón naranja **Next** (Siguiente).
4. **Paso 2: Establecer permisos:**
   - En las opciones superiores, selecciona la tercera pestaña: **Attach policies directly** (Adjuntar políticas directamente).
   - En el campo de búsqueda de políticas (*Filter policies*), escribe: `AdministratorAccess`.
   - Marca la casilla de verificación a la izquierda de la política **`AdministratorAccess`** (Política de tipo *AWS managed*).
   - Haz clic en el botón naranja **Next** (Siguiente).
5. **Paso 3: Revisar y crear:**
   - Verifica que el nombre sea `admin-tesis` y que tenga asignada la política `AdministratorAccess`.
   - Haz clic en el botón naranja **Create user** (Crear usuario).

### Paso 2.3. Generar las Credenciales Programáticas (Access Keys)
1. Volverás a la lista de usuarios. Haz clic sobre el nombre del usuario recién creado: **`admin-tesis`**.
2. En la página de detalles del usuario, haz clic en la pestaña **Security credentials** (Credenciales de seguridad).
3. Desplázate hacia abajo hasta la sección titulada **Access keys** (Claves de acceso).
4. Haz clic en el botón **Create access key** (Crear clave de acceso).
5. **Seleccionar caso de uso:**
   - Elige la primera opción: **Command Line Interface (CLI)**.
   - En la parte inferior de la página aparecerá un aviso de recomendación. Marca la casilla de confirmación:
     `☑ I understand the above recommendation and want to proceed to create an access key.`
   - Haz clic en el botón naranja **Next** (Siguiente).
6. **Descripción de la clave (Opcional):**
   - Puedes escribir una etiqueta como `Clave local tesis Linux` o dejarla vacía.
   - Haz clic en **Create access key**.
7. **Guardar las credenciales (¡ACCIÓN CRÍTICA!):**
   - Verás dos valores en pantalla:
     - **Access key:** Cadena de 20 caracteres que comienza por `AKIA...` (ej: `AKIA[REPLACE_EXAMPLE]`).
     - **Secret access key:** Cadena secreta de 40 caracteres. Haz clic en el botón *"Show"* para visualizarla.
   - Haz clic en el botón **Download .csv file** para guardar una copia de seguridad local en tu disco duro (guárdala en una ubicación privada como `~/.aws/` o en tu gestor de contraseñas, jamás en la carpeta del repositorio Git).
   - Haz clic en **Done** (Listo).

---

## 3. Configuración Segura en tu Máquina Local

### Paso 3.1. Configuración del Perfil con AWS CLI
En tu terminal local de Linux, ejecuta el comando de configuración asistida:

```bash
aws configure
```

La herramienta te solicitará cuatro datos consecutivos. Ingrésalos tal como se indica:

```text
AWS Access Key ID [****************EPYG]: AKIA[REPLACE_EXAMPLE]    <-- Pega tu Access Key nueva
AWS Secret Access Key [****************/f9c]: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX <-- Pega tu Secret Key nueva
Default region name [ca-central-1]: us-east-2                      <-- Región de tu nueva cuenta (Ohio)
Default output format [json]: json                                 <-- Formato estándar JSON
```

### Paso 3.2. Verificación Inmediata de Identidad
Comprueba que el CLI de tu máquina ahora se comunica efectivamente con la nueva cuenta:

```bash
aws sts get-caller-identity
```

La respuesta debe confirmar de forma inequívoca el nuevo número de cuenta:

```json
{
    "UserId": "AIDXXXXXXXXXXXXXXXXXX",
    "Account": "056176271407",
    "Arn": "arn:aws:iam::056176271407:user/admin-tesis"
}
```

### Paso 3.3. Actualización de Parámetros en Terraform
Abre tu archivo local privado [`terraform-tesis-ir-secure-portal/terraform.tfvars`](file:///home/bryan/Projects/LOCALSTACK/localstack-tesis/terraform-tesis-ir-secure-portal/terraform.tfvars) y ajusta la región a la nueva cuenta:

```hcl
aws_region       = "us-east-2"
project_name     = "tesis-ir"
ssh_allowed_cidr = "TU_IP_PUBLICA/32" # Obtén tu IP con: curl -s ifconfig.me
alert_email      = "tu_correo@gmail.com"
ses_domain       = "soc.bryan-bano.com"
ses_sender_email = "alertas@soc.bryan-bano.com"
telegram_bot_token = "TU_BOT_TOKEN"
telegram_chat_id   = "TU_CHAT_ID"
```

---

## 4. Política de Protección de Secretos (Cero Fugas)

Para garantizar que ninguna credencial, clave privada ni estado de infraestructura se filtre jamás al repositorio, el archivo [`.gitignore`](file:///home/bryan/Projects/LOCALSTACK/localstack-tesis/.gitignore) mantiene activas las siguientes reglas de exclusión:

```gitignore
# Archivos de estado y variables de Terraform (contienen credenciales e IPs)
.terraform/
*.tfstate
*.tfstate.*
.terraform.lock.hcl
terraform.tfvars
terraform.tfvars.json

# Llaves criptográficas y variables de entorno locales
.env
.env.*
*.pem
*.key

# Paquetes compilados y logs
*.zip
*.log
__pycache__/
```

> [!CAUTION]
> Nunca ejecutes `git add -f` (forzado) sobre archivos `.env` o `terraform.tfvars`. Las credenciales permanecen exclusivamente en tu sistema local en `~/.aws/credentials`.

---

## 5. Migración y Publicación en Forgejo Personal

Tu servidor Forgejo personal está operativo en `https://git.bryan-bano.com`. Sigue estos pasos para subir tu repositorio:

### Paso 5.1. Crear el Repositorio Vacío en Forgejo Web
1. Abre tu navegador e ingresa a: **[https://git.bryan-bano.com](https://git.bryan-bano.com)**.
2. Inicia sesión con tus credenciales de usuario: `Bryan.bano`.
3. En la barra superior derecha, haz clic en el botón con el icono **`+`** y selecciona **Nuevo repositorio** (*New Repository*).
4. Configura el formulario:
   - **Propietario:** `Bryan.bano`
   - **Nombre del repositorio:** `localstack-tesis`
   - **Visibilidad:** Privado o Público (según tu requerimiento académico).
   - **MUY IMPORTANTE:** **NO marques** ninguna de las casillas de inicialización:
     - ❌ *Inicializar repositorio*
     - ❌ *Añadir README*
     - ❌ *Añadir .gitignore*
     - ❌ *Añadir licencia*
   *(El repositorio debe crearse completamente vacío porque ya poseemos todo el historial y ramas en local).*
5. Haz clic en el botón verde **Crear repositorio**.

### Paso 5.2. Vincular el Remoto en tu Terminal Local
En tu terminal, ubicado dentro del directorio raíz del proyecto (`/home/bryan/Projects/LOCALSTACK/localstack-tesis`), ejecuta:

```bash
# 1. Agregar el nuevo origen remoto apuntando a Forgejo
git remote add forgejo https://git.bryan-bano.com/Bryan.bano/localstack-tesis.git

# 2. Verificar que ambos remotos estén registrados
git remote -v
```

Verás una salida similar a:
```text
forgejo  https://git.bryan-bano.com/Bryan.bano/localstack-tesis.git (fetch)
forgejo  https://git.bryan-bano.com/Bryan.bano/localstack-tesis.git (push)
origin   https://github.com/bryancito1090/localstack-tesis.git (fetch)
origin   https://github.com/bryancito1090/localstack-tesis.git (push)
```

### Paso 5.3. Subir las Ramas Principales a Forgejo
Dado que tu configuración global de Git ya tiene activo el helper de almacenamiento (`credential.https://git.bryan-bano.com.helper=store`), la autenticación será inmediata:

```bash
# Subir la rama de producción 'main'
git push -u forgejo main

# Subir la rama de integración 'develop'
git push -u forgejo develop
```

### Paso 5.4. Configurar la Rama por Defecto en Forgejo
1. En la página web de tu repositorio en Forgejo, ve a la pestaña **Configuración** (*Settings*).
2. En la sección **Ramas** (*Branches*), selecciona **`develop`** como rama por defecto (*Default Branch*) y guarda los cambios.
3. De esta forma, cualquier Pull Request o trabajo diario se sincronizará automáticamente bajo el flujo de trabajo establecido.
