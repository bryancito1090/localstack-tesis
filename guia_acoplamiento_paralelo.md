# Guía de Acoplamiento y Desarrollo en Paralelo (Componentes A, B y C)

Este documento detalla el paso a paso técnico para integrar los tres componentes de la tesis (A: Logs, B: Detección, C: Respuesta) en AWS de forma simultánea, permitiendo que cada miembro trabaje de manera independiente sin bloquear a los demás.

---

## 1. El Concepto: Desarrollo Desacoplado

Para evitar depender de que un compañero termine su parte para poder probar la tuya, utilizaremos **Contratos de Interfaz** (esquemas de datos acordados). Cada componente interactuará con el siguiente a través de un recurso de AWS intermedio (S3 o SQS), actuando como amortiguador.

```
 [Componente A — Melany]   ==== (Contrato 1: S3) ====>   [Componente B — Aarón]   ==== (Contrato 2: SQS) ====>   [Componente C — Bryan]
 (Logs en cloudtrail/)                                   (Queries Athena/DuckDB)                                (Dispatcher & Playbooks)
```

---

## 2. Paso a Paso para el Acoplamiento

### Paso 1: Definición de Interfaces (Alineación Inicial)
Antes de escribir código en AWS, el equipo debe acordar y fijar dos contratos:

* **Contrato 1 (Rutas en S3)**: Melany y Aarón acuerdan la estructura de carpetas en S3.
  * Ruta CloudTrail: `s3://<bucket-nombre>/cloudtrail/YYYY/MM/DD/`
  * Ruta VPC Flow Logs: `s3://<bucket-nombre>/vpc-flow/YYYY/MM/DD/`
* **Contrato 2 (Formato JSON de Incidentes)**: Aarón y Bryan acuerdan el formato de datos que se enviará por SQS.
  * *Estructura obligatoria:*
    ```json
    {
      "incident_type": "BRUTE_FORCE",
      "severity": "HIGH",
      "sourceIPAddress": "185.220.101.5",
      "affectedResource": "iam:user/admin",
      "s3_log_key": "cloudtrail/2026/05/26/archivo.json",
      "timestamp": "2026-05-26T21:00:00Z",
      "event_count": 10
    }
    ```

---

### Paso 2: Aprovisionamiento de Infraestructura Base en AWS
Uno de los miembros (o usando un archivo de Terraform compartido) debe crear los siguientes recursos en la cuenta de AWS real:

1. **S3 Bucket:** `tesis-security-logs-prod` (para Melany y Aarón).
2. **Cola SQS:** `tesis-incident-queue` (para Aarón y Bryan).
3. **Tópico SNS:** `tesis-security-alerts` (para Bryan).
4. **VPC y NACL por defecto** (para las pruebas de bloqueo de red de Bryan).

---

### Paso 3: Fase de Desarrollo Independiente (En Paralelo)

Con los recursos base creados, cada componente puede avanzar de forma independiente:

#### 💻 ¿Cómo trabaja Melany (Componente A)?
* **Tarea**: Configurar CloudTrail y VPC Flow Logs para que escriban en el bucket S3 real.
* **Cómo probar sola**: Puede forzar eventos en AWS (ej. fallar logins o hacer escaneos de puertos) y verificar que los archivos de logs aparezcan en las carpetas correctas de S3.

#### 💻 ¿Cómo trabaja Aarón (Componente B)?
* **Tarea**: Escribir la Lambda de detección (programada con EventBridge Scheduler cada 5 min) que corre consultas Athena en S3 y publica incidentes en SQS.
* **Cómo probar solo sin Melany**: Aarón no necesita esperar que los logs reales de CloudTrail estén configurados. Él puede **subir manualmente archivos JSON de logs sintéticos** (como los de `sample_cloudtrail.json`) a su bucket S3 y correr sus queries de Athena para verificar que detecte el ataque e inserte el JSON acordado en la SQS.

#### 💻 ¿Cómo trabajas tú (Componente C - Bryan)?
* **Tarea**: Escribir la Lambda Dispatcher y los Playbooks (Block-IP, Revoke-Credentials, Isolate-Instance).
* **Cómo probar solo sin Aarón**: No necesitas que el detector de Aarón funcione. Puedes abrir la consola web de AWS, ir a la cola SQS `tesis-incident-queue` y **enviar un mensaje de prueba con el formato JSON acordado**. Esto disparará tu flujo completo automáticamente y podrás verificar:
  * Si tu IP fue bloqueada en la NACL real de AWS.
  * Si el usuario de prueba de IAM fue bloqueado (política `EmergencyDenyAll`).
  * Si recibiste la notificación por correo de SNS.

---

### Paso 4: Fase de Integración (Unión de Piezas)

Una vez que cada módulo funcione por separado, la integración final en AWS real se realiza en tres simples pasos:

1. **Vincular SQS a Dispatcher**: Configurar el *Event Source Mapping* en la Lambda Dispatcher apuntando a la cola SQS.
2. **Apuntar Detección a SQS Real**: Asegurarse de que la Lambda de Detección de Aarón envíe los mensajes a la URL de SQS real de producción en AWS, no a LocalStack.
3. **Apuntar Detección a Logs Reales**: Cambiar la ruta de origen en la consulta de Athena de Aarón para que analice los logs reales ingestados por Melany.

---

## 3. Estrategia de Pruebas Cruzadas para la Demo del Profesor

Para demostrar el avance completo del flujo al profesor, ejecuten el siguiente caso de prueba interactivo:

1. **Ataque**: Desde una máquina externa, ejecuten un pequeño script de fuerza bruta hacia la consola de AWS (Melany captura el log en S3).
2. **Detección**: Muestren la consola de Athena en AWS donde la query SQL identifica a la IP atacante (Aarón muestra los IoC detectados).
3. **Alerta**: El mensaje de alerta viaja a SQS y activa tu Dispatcher.
4. **Respuesta**: Muestren la pestaña de Network ACL en AWS EC2 en tiempo real. Al refrescar, la IP atacante debe aparecer con una regla `DENY` número `1` (Bryan demuestra la contención exitosa).
