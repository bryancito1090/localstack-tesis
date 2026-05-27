# Análisis de Costos Fijos en AWS: Infraestructura Permanente para Trabajo en Paralelo

Este documento evalúa el impacto financiero de mantener la infraestructura del proyecto activa 24/7 en AWS real durante la fase de desarrollo en paralelo. El objetivo es determinar si dejar levantados los recursos de manera permanente generará cobros en la cuenta de AWS.

---

## 1. Regla General: Serverless vs. Provisionado

En AWS existen dos modelos de facturación principales:
* **Serverless / Bajo Demanda (Costo $0 en reposo)**: Solo pagas por uso activo (ejecuciones de código, peticiones, mensajes enviados). Si el recurso está creado pero inactivo, el costo es **cero**.
* **Provisionado (Cobro por Hora)**: Pagas por tener el recurso reservado y encendido, sin importar si lo estás usando o si el tráfico es cero.

---

## 2. Inventario de Recursos Permanentemente Activos ($0 USD)

Los siguientes recursos del proyecto **pueden permanecer creados las 24 horas del día, los 7 días de la semana** sin generar ningún costo si no hay simulaciones de ataques ejecutándose:

| Servicio AWS | Recurso en la Tesis | Tipo de Cobro | Costo en Reposo (24/7) |
| :--- | :--- | :--- | :--- |
| **AWS Lambda** | Dispatcher y Playbooks | Por petición (milisegundos) | **$0.00 USD** |
| **Amazon SQS** | Cola de incidentes y DLQ | Por petición (mensajes) | **$0.00 USD** |
| **Amazon SNS** | Tópico de alertas de seguridad | Por petición (publicaciones) | **$0.00 USD** |
| **Amazon Athena** | Motor de consultas SQL | Por datos escaneados (TB) | **$0.00 USD** |
| **AWS IAM** | Roles y políticas de seguridad | Gratis siempre | **$0.00 USD** |
| **Amazon VPC** | Red virtual y subredes | Gratis siempre | **$0.00 USD** |
| **Network ACL** | Firewall de subred (bloqueos) | Gratis siempre | **$0.00 USD** |
| **Amazon S3** | Logs históricos y evidencias | Por almacenamiento (GB) | **<$0.001 USD/mes** (despreciable) |

---

## 3. Alertas de Costo: Recursos a Apagar o Evitar

Estos son los únicos componentes que **sí generan cobros por hora** y deben ser gestionados con cuidado durante el desarrollo:

### 1. Instancias EC2 (`t2.micro` / `t3.micro`) — *Apagar en reposo*
* **Impacto**: Una instancia EC2 encendida consume horas de cómputo de forma continua. La capa gratuita de AWS regala **750 horas mensuales** para una sola instancia. Si dejas encendida la máquina de simulación de Melany 24/7, consumirás todo el Free Tier. Si levantan una segunda máquina, o se exceden del mes, les cobrarán **~$9.00 USD/mes** por cada instancia activa.
* **Solución**: Creen la instancia EC2 en AWS, pero **deténganla (stop)** desde la consola cuando no estén realizando pruebas activas de tráfico. Una EC2 apagada solo cobra centavos por el disco EBS asociado.

### 2. NAT Gateways (VPC) — *Evitar por completo*
* **Impacto**: Si asocian las funciones Lambda a subredes privadas de su VPC, necesitarán un NAT Gateway para que las Lambdas se conecten a internet. Un NAT Gateway cobra una tarifa fija de **~$32.00 USD/mes** solo por estar creado.
* **Solución**: **Desplieguen las Lambdas fuera de la VPC** (en la red pública de AWS). Usen roles de IAM para la seguridad. Así, se comunicarán con SQS, SNS y la API de EC2 (NACL) a través de los endpoints públicos de AWS de forma segura y a **costo cero**.

### 3. VPC Endpoints de Interfaz — *Evitar en desarrollo*
* **Impacto**: Son alternativas privadas al NAT Gateway, pero cobran **~$7.20 USD/mes** por cada endpoint activo por Zona de Disponibilidad.
* **Solución**: No crearlos en la fase de desarrollo/pruebas locales.

---

## 4. Buenas Prácticas para el Equipo durante la Tesis

1. **Mantener la Infraestructura Base Levantada**: Creen y dejen creados de forma permanente los buckets S3, colas SQS, tópicos SNS, VPC, NACLs y funciones Lambda. Esto facilita que Aarón y Bryan hagan pruebas de integración rápidas sin tener que reconstruir el entorno.
2. **Apagar las Máquinas de Prueba**: Asegurar que la instancia EC2 objetivo esté apagada y solo se encienda durante las demos o pruebas conjuntas.
3. **Monitorear con AWS Budgets**: Configurar una alarma en AWS Budgets para que envíe un correo de alerta si el costo acumulado supera los **$1.00 USD** en el mes.
