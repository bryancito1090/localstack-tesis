Genera y simula un evento de incidente de seguridad completo en el entorno LocalStack para probar el Componente C (Automatización de Respuesta).

Contexto: Proyecto de tesis sobre detección y respuesta ante incidentes en AWS. LocalStack corre en localhost:4566. Los logs van al bucket S3 `tesis-security-logs`.
Directorio del proyecto: /home/bryan/localstack-tesis
Venv: /home/bryan/localstack-tesis/.venv — usa .venv/bin/python3 y .venv/bin/awslocal
Script de inyección: /home/bryan/localstack-tesis/simulators/inject_logs.py

El argumento (si se provee) indica el tipo de incidente a simular: $ARGUMENTS
Tipos disponibles: `brute-force`, `privilege-escalation`, `credential-leak`, `exfiltration`, `port-scan`
Si no se especifica, usa `brute-force` por defecto.

Pasos a ejecutar:
1. Ejecuta el script inyector: `cd /home/bryan/localstack-tesis && .venv/bin/python3 simulators/inject_logs.py <tipo>`
   Esto generará los eventos CloudTrail, los subirá a S3 y enviará el mensaje SQS automáticamente.
2. Verifica que el archivo llegó a S3: `.venv/bin/awslocal s3 ls s3://tesis-security-logs/cloudtrail/ --recursive`
3. Verifica el mensaje en SQS: `.venv/bin/awslocal sqs get-queue-attributes --queue-url http://localhost:4566/000000000000/tesis-incident-queue --attribute-names ApproximateNumberOfMessages`
4. Muestra el payload que recibiría la Lambda de respuesta

Al final, muestra el payload exacto que recibiría la Lambda de respuesta (evento SQS).
