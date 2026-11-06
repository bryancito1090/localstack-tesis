# Sistema de Detección y Respuesta Automatizada ante Incidentes en AWS

**Trabajo de Integración Curricular (Tesis de Grado)**  
**Tema:** Diseño e Implementación de un Sistema de Detección y Respuesta ante Incidentes de Seguridad en Entornos Cloud (AWS)  
**Autor (Componente C - Automatización de Respuesta):** Bryan Baño  
**Dominio SOC Institucional:** `soc.bryan-bano.com` (Certificado con Firma Digital DKIM / SPF / DMARC)  

---

## 1. Descripción del Proyecto

Este repositorio contiene la arquitectura completa de **Detección y Respuesta Automatizada a Incidentes de Seguridad (IR - Incident Response)** implementada como **Infraestructura como Código (IaC)** en Amazon Web Services (AWS) con Terraform, complementada con un entorno de pruebas emulado en LocalStack.

El sistema monitoriza telemetría en tiempo real (logs de aplicaciones web, VPC Flow Logs, AWS CloudTrail y S3 Data Events), detecta Indicadores de Compromiso (IoCs) mediante funciones Lambda de correlación temporal y ejecuta playbooks de mitigación inmediata (bloqueo de red en Network ACLs y revocación de credenciales IAM con contención `EmergencyDenyAll`), despachando alertas enriquecidas y firmadas digitalmente por múltiples canales (Gmail y Telegram).

---

## 2. Componentes del Proyecto

| Componente | Rol / Responsable | Descripción Técnica |
|---|---|---|
| **Componente A — Arquitectura y Logs** | Melany | CloudTrail, VPC Flow Logs, GuardDuty, S3, Glue y retención forense |
| **Componente B — Detección de Incidentes** | Aarón | Reglas de correlación temporal, filtros de logs y análisis forense |
| **Componente C — Automatización de Respuesta** | **Bryan** | **Motor de detección Lambda, Playbooks serverless, contención en NACL/IAM, firma DKIM SES y bot visual de Telegram** |

---

## 3. Matriz de Cobertura de Incidentes

El sistema implementa 5 playbooks de detección y respuesta automatizada estandarizados bajo un esquema formal de 3 bloques (`INFORMACION GENERAL`, `RECURSO Y ORIGEN / CONTENCION`, `CRITERIO Y TRAZABILIDAD`) y sin uso de emojis:

| # | Tipo de Incidente | Fuente de Telemetría | Severidad / Color | Playbooks Ejecutados | Acción de Mitigación Real | Canales de Notificación |
|---|---|---|---|---|---|---|
| **1** | `BRUTE_FORCE` | Logs Nginx EC2 / ConsoleLogin | `HIGH` (Naranja) | `notify-alert`, `block-ip` | Inserción de regla `DENY` en Network ACL de VPC | Gmail (HTML) + Telegram (PNG) |
| **2** | `PORT_SCAN` | VPC Flow Logs (`REJECT` > umbral) | `MEDIUM` (Ámbar) | `notify-alert`, `block-ip` | Inserción de regla `DENY` en Network ACL de VPC | Gmail (HTML) + Telegram (PNG) |
| **3** | `PRIVILEGE_ESCALATION` | AWS CloudTrail (`AttachUserPolicy`) | `CRITICAL` (Rojo) | `notify-alert`, `revoke-credentials` | Desactiva llaves IAM + Adjunta `EmergencyDenyAll` | Gmail (HTML) + Telegram (PNG) |
| **4** | `CREDENTIAL_LEAK` | CloudTrail (`GetCallerIdentity` IP no autorizada) | `CRITICAL` (Rojo) | `notify-alert`, `revoke-credentials` | Desactiva llaves IAM + Adjunta `EmergencyDenyAll` | Gmail (HTML) + Telegram (PNG) |
| **5** | `EXFILTRATION` | CloudTrail S3 Data Events (`GetObject` > 50/h) | `HIGH` (Naranja) | `notify-alert` | Alerta forense y trazabilidad en S3 | Gmail (HTML) + Telegram (PNG) |

---

## 4. Arquitectura de Notificaciones y Firma Digital

```text
               ┌────────────────────────────────────────────────────────┐
               │              TELEMETRIA Y FUENTES DE LOGS              │
               │   (EC2 Portal / VPC Flow Logs / AWS CloudTrail / S3)   │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │          LAMBDA DETECTOR (Correlación de IoCs)         │
               └───────────────┬────────────────────────┬───────────────┘
                               │                        │
                    (SQS Notify Queue)         (SQS Playbook Queue)
                               │                        │
                               ▼                        ▼
               ┌────────────────────────┐    ┌────────────────────────┐
               │ PLAYBOOK: notify-alert │    │ PLAYBOOK: block-ip /   │
               │                        │    │ revoke-credentials     │
               └───────────────┬────────┘    └──────────┬─────────────┘
                               │                        │
            ┌──────────────────┴────────────────────────┴──────────────────┐
            │                                                              │
            ▼ (Amazon SES HTML Directo)                                    ▼ (Amazon SNS Topic)
┌───────────────────────────────────────┐                    ┌──────────────────────────────┐
│                GMAIL                  │                    │ LAMBDA: telegram-notifier    │
│  - Tarjeta HTML con estilos CSS       │                    │  - Motor gráfico PNG puro    │
│  - Firma Digital Criptográfica DKIM   │                    │  - API sendPhoto (Multipart) │
│  - Remitente: alertas@soc.bryan-bano.com                   └──────────────┬───────────────┘
└───────────────────────────────────────┘                                   │
                                                                            ▼
                                                             ┌──────────────────────────────┐
                                                             │           TELEGRAM           │
                                                             │ - Tarjeta Gráfica en Imagen  │
                                                             │ - Sin texto plano            │
                                                             └──────────────────────────────┘
```

### Características de las Notificaciones:
1. **Firma Digital DKIM (Amazon SES + Cloudflare):**
   - Subdominio `soc.bryan-bano.com` validado con registros CNAME DKIM, SPF TXT y DMARC TXT en Cloudflare DNS.
   - Reputación 100% libre de Spam y entrega garantizada en la bandeja principal de Gmail.
2. **Tarjetas Gráficas para Telegram (`card_image.py`):**
   - Motor rasterizador en Python puro con `zlib` y `struct` (cero dependencias externas en AWS Lambda).
   - Genera imágenes PNG con cabecera coloreada por severidad, insignias, tablas estructuradas y bloques de diagnóstico.

---

## 5. Estructura del Repositorio

```text
localstack-tesis/
├── ansible/                               ← Portal, Nginx y CloudWatch Agent por SSM/SSH
├── .forgejo/workflows/validate.yml         ← Validacion de PR hacia develop
├── docs/                                  ← Documentación técnica integral de tesis
│   ├── README.md                          ← Índice general y mapa de navegación
│   ├── 01-contexto-tesis-y-roles.md       ← Marco académico, roles A/B/C y contratos
│   ├── 02-arquitectura-tecnica-y-flujos.md← Flujo end-to-end de telemetría y respuesta
│   ├── 03-infraestructura-como-codigo-terraform.md ← Recursos AWS en main.tf y variables
│   ├── 04-motor-deteccion-e-incidentes.md ← Lógica del Lambda Detector B y matriz IoC
│   ├── 05-playbooks-de-respuesta-automatizada.md ← Playbooks de contención y notificaciones
│   ├── 06-guia-de-pruebas-y-simulaciones.md ← Guía paso a paso de validación forense
│   ├── 07-convencion-de-ramas-y-gitflow.md ← Estándares de GitFlow y ciclo de PRs
│   ├── 08-estrategia-costos-y-entornos.md ← Arquitectura serverless de bajo costo (< $5)
│   ├── 09-integracion-ansible-gestion-configuracion.md ← Integración de Ansible (CM) y roles
│   └── 10-guia-configuracion-aws-cuenta-nueva-y-forgejo.md ← Manual de cuenta AWS y Forgejo
│
├── terraform-tesis-ir-secure-portal/      ← Infraestructura principal en AWS (Terraform)
│   ├── main.tf                            ← Recursos AWS (VPC, EC2, Lambdas, SQS, SES, SNS)
│   ├── variables.tf                       ← Declaración de variables configurables
│   ├── outputs.tf                         ← Salidas de red, DNS DKIM y buckets
│   ├── terraform.tfvars.example           ← Plantilla pública de variables
│   ├── .gitignore                         ← Exclusión de secretos y estados locales
│   │
│   ├── lambda/                            ← Motor de Detección
│   │   └── lambda_function.py             ← Correlación de logs y despacho SQS
│   │
│   ├── playbooks/                         ← Playbooks de Respuesta Serverless
│   │   ├── notify_alert/                  ← Genera y envía tarjetas HTML vía SES y SNS
│   │   ├── block_ip/                      ← Aplica contención en VPC Network ACL
│   │   ├── revoke_credentials/            ← Revoca accesos IAM con EmergencyDenyAll
│   │   └── telegram_notifier/             ← Renderiza imágenes PNG y envía a Telegram
│   │       ├── handler.py                 ← Consumidor SNS y cliente sendPhoto
│   │       └── card_image.py              ← Motor gráfico nativo en Python puro
│   │
│   ├── GUIA_PRUEBAS_INCIDENTES.md         ← Manual paso a paso de pruebas de incidentes
│   └── README_EJECUCION.md                ← Instrucciones locales de ejecución
│
└── README.md                              ← Este documento
```

---

## 6. Guía Rápida de Despliegue en AWS

### Paso 1: Configurar Variables Locales
Copia la plantilla y configura tus valores personales en `terraform.tfvars`:
```bash
cd terraform-tesis-ir-secure-portal
cp terraform.tfvars.example terraform.tfvars
```
Edita `terraform.tfvars`:
```hcl
aws_region       = "ca-central-1"
project_name     = "tesis-ir"
ssh_allowed_cidr = "TU_IP_PUBLICA/32"
alert_email      = "tu_correo@gmail.com"
ses_domain       = "soc.bryan-bano.com"
ses_sender_email = "alertas@soc.bryan-bano.com"
telegram_bot_token = "TU_TELEGRAM_BOT_TOKEN"
telegram_chat_id   = "TU_TELEGRAM_CHAT_ID"
```

### Paso 2: Desplegar la Infraestructura
```bash
terraform init
terraform apply -auto-approve
```

### Paso 3: Configurar el Portal con Ansible

Instala las dependencias siguiendo [la guia operativa de Ansible](ansible/README.md). Desde la raiz:

```bash
python ansible/scripts/generate_inventory.py
cd ansible
ansible-playbook playbook.yml
```

El primer cambio de `user_data` puede reemplazar EC2; revisa el plan antes de aplicar. Los checks y la proteccion de `develop` se describen en [Forgejo Actions](docs/11-forgejo-actions-y-proteccion-develop.md).

Para las mediciones del TIC consulta el [plan de evaluación cuantitativa](docs/12-plan-evaluacion-cuantitativa-tic.md): tiempos HTTP, detección y contención, calidad, comparación manual/automática y plantillas de evidencia. Si cambias de red, sigue [la guía de Ansible](ansible/README.md#cambio-de-red-o-vpn) para actualizar el acceso y las IP autorizadas.

---

## 7. Ejecución de Pruebas de Incidentes

### Prueba 1: Fuerza Bruta en el Portal Web (`BRUTE_FORCE`)
```bash
PORTAL_IP=$(terraform output -raw portal_public_ip)
for i in {1..5}; do
  curl -s -X POST "http://$PORTAL_IP/login" -d "username=admin.demo&password=wrongpassword$i" -o /dev/null
done
```
* **Resultado:** Alerta Naranja (`HIGH`) y Mitigación Roja (`BLOCKED`) en Gmail y Telegram (NACL bloquea la IP).

### Prueba 2: Escalada de Privilegios IAM (`PRIVILEGE_ESCALATION`)
```bash
aws iam create-user --user-name tesis-ir-temp-escalation-test
aws iam attach-user-policy --user-name tesis-ir-temp-escalation-test --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess"
```
* **Resultado:** Alerta Roja (`CRITICAL`) y Mitigación Azul (`CONTAINED`) revocando credenciales con `EmergencyDenyAll`.
* **Limpieza:**
```bash
aws iam delete-user-policy --user-name tesis-ir-temp-escalation-test --policy-name EmergencyDenyAll 2>/dev/null
aws iam detach-user-policy --user-name tesis-ir-temp-escalation-test --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess" 2>/dev/null
aws iam delete-user --user-name tesis-ir-temp-escalation-test
```

---

## 8. Apagado y Destrucción de Recursos (Control de Costos)

Para apagar la infraestructura completa y no incurrir en costos de AWS:
```bash
terraform destroy -auto-approve
```
*Los registros DNS en Cloudflare y los archivos de configuración local se mantendrán listos para el próximo despliegue sin requerir reconfiguración manual.*
