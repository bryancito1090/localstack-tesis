# Estrategia de Trabajo en Paralelo e Integración en AWS (Componente C)

Este documento describe la estrategia recomendada para que Bryan (Componente C), Melany (Componente A) y Aarón (Componente B) colaboren en paralelo para construir y demostrar el flujo completo en AWS reduciendo los costos mensuales a cero.

---

## 1. Arquitectura a Costo Cero ($0 USD)
Para evitar cobros fijos en la cuenta de AWS de pruebas, la regla de diseño principal es **desplegar las Lambdas fuera de la VPC (sin asociarlas a subredes privadas)**.

* **Sin NAT Gateway**: Una Lambda dentro de una VPC privada requiere un NAT Gateway para enviar mensajes a SQS, publicar en SNS o conectarse al bucket S3 por su endpoint público. El costo del NAT Gateway es de ~$32 USD/mes fijo.
* **Seguridad y Costo Cero**: Al mantener las Lambdas en la red pública de AWS, estas se conectan a los servicios administrados (SQS, SNS, IAM, S3, EC2) a través de internet de manera cifrada (HTTPS) utilizando sus permisos de IAM execution role. No se genera ningún cargo fijo de infraestructura de red.

---

## 2. Plan de Desarrollo en Paralelo (Contratos de Integración)
El equipo no necesita esperar a que los componentes estén finalizados para empezar a probar. El flujo se divide en interfaces claras:

```
[Melany — Comp. A]   -> Genera logs (CloudTrail/VPC Flow) en S3.
                             | (Formato de Archivos)
[Aarón — Comp. B]    -> Lee logs, aplica Queries Athena en S3 y publica detección en SQS.
                             | (Formato JSON de Incidentes)
[Bryan — Comp. C]    -> Recibe alertas de SQS, ejecuta dispatcher y activa Playbooks.
```

### Acción 1: Contrato de Cola de Entrada SQS
Se debe crear una única cola SQS real en AWS (`tesis-incident-queue`) que actuará como el canal de comunicación entre el Componente B y el Componente C.

### Acción 2: Pruebas Independientes
* **Aarón** puede probar su Lambda de detección subiendo archivos de logs de prueba (mock logs) en S3, ejecutando Athena y verificando que el payload JSON llegue a SQS.
* **Bryan** puede probar el dispatcher y los playbooks inyectando mensajes JSON de prueba manualmente en la cola SQS de AWS desde la consola web, confirmando que las NACLs se bloquean y que el correo de alerta de SNS se envía.

---

## 3. Demostración del Flujo Completo
Para la presentación del avance ante el profesor, se pueden utilizar dos opciones de demostración:

1. **Opción Real (End-to-End)**: Se realiza una actividad real (ej. intentar loggearse falsamente en la cuenta) -> CloudTrail registra en S3 -> Aarón detecta con Lambda/Athena -> Aarón publica en SQS -> Lambda Dispatcher se activa -> Playbook `block-ip` deniega el acceso a la IP del atacante en la NACL real.
2. **Opción Híbrida (Simulada para Contingencias)**: Si hay demoras de propagación en los logs de CloudTrail (~15 minutos en AWS real), Bryan ejecuta un script Python local que inyecta el incidente directamente en la SQS de AWS, demostrando la respuesta automatizada en vivo en menos de 5 segundos.
