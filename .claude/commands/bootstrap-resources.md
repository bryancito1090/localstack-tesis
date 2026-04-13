Crea todos los recursos AWS locales necesarios para el Componente C (Automatización de Respuesta) en LocalStack.

Contexto del proyecto: Sistema de detección y respuesta ante incidentes en AWS, emulado con LocalStack en localhost:4566. El componente C maneja Lambda Playbooks, IAM, SNS y SQS.
Directorio del proyecto: /home/bryan/localstack-tesis
Usa `/home/bryan/localstack-tesis/.venv/bin/awslocal` (o activa el venv: `source /home/bryan/localstack-tesis/.venv/bin/activate`).
Forma rápida: ejecuta `bash /home/bryan/localstack-tesis/infra/setup.sh` y reporta el resultado.

Recursos a crear (usa `awslocal` que apunta a localhost:4566):

**S3:**
- Bucket `tesis-security-logs` con prefijos: cloudtrail/, vpc-flow/, guardduty/, responses/

**SNS:**
- Tópico `tesis-security-alerts` (notificaciones de incidentes al equipo)
- Tópico `tesis-lambda-triggers` (triggers para Lambdas de respuesta)

**SQS:**
- Cola `tesis-incident-queue` (cola principal de eventos de incidentes)
- Cola `tesis-incident-queue-dlq` (dead letter queue para errores)

**CloudWatch Logs:**
- Grupo `/tesis/security-events`
- Grupo `/tesis/lambda-responses`

**IAM:**
- Rol `tesis-lambda-response-role` con política de mínimo privilegio (permisos solo sobre los recursos anteriores)

Después de crear cada recurso, verifica que exista y muestra su ARN o URL. Al final, muestra un resumen tipo tabla con todos los recursos creados y su estado.

Si algún recurso ya existe, no lo recrees, solo confirma que está disponible.
