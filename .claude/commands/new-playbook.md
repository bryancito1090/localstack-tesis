Crea un nuevo Lambda Playbook de respuesta automatizada para el Componente C de la tesis.

Contexto: Sistema de respuesta ante incidentes en AWS (emulado con LocalStack). Los playbooks son funciones Lambda Python que responden automáticamente a alertas de seguridad. Se activan via SQS o SNS. Deben usar boto3 con endpoint_url apuntando a LocalStack (http://localhost:4566). El código vive en `/home/bryan/localstack-tesis/lambdas/`.

El argumento describe el playbook a crear: $ARGUMENTS

Proceso:
1. Analiza el argumento para determinar:
   - Nombre del playbook (snake_case, descriptivo)
   - Trigger: qué tipo de incidente activa este playbook
   - Acción: qué hace exactamente (aislar, revocar, bloquear, notificar, etc.)
   - Recursos AWS que necesita manipular (EC2, IAM, S3, SNS, SQS, etc.)

2. Crea la estructura del directorio: `/home/bryan/localstack-tesis/lambdas/<nombre>/`
   - `handler.py` — código principal de la Lambda
   - `policy.json` — política IAM de mínimo privilegio para este playbook
   - `test_event.json` — evento de prueba realista (formato SQS/SNS)

3. El `handler.py` debe seguir este patrón obligatorio:
   - Función `lambda_handler(event, context)` como entrypoint
   - Parseo del evento (SQS records o SNS message)
   - Validación del payload antes de actuar
   - Acción principal usando boto3 (con endpoint LocalStack)
   - Registro en CloudWatch Logs con nivel de detalle
   - Return estructurado: `{"status": "success|error", "action": "...", "details": {...}, "timestamp": "..."}`
   - Manejo de excepciones con rollback si aplica

4. El `policy.json` debe seguir el principio de mínimo privilegio: solo los permisos estrictamente necesarios para las acciones que ejecuta el playbook, limitados por Resource ARN donde sea posible.

5. Explica brevemente cómo encaja este playbook en la arquitectura: qué lo activa, qué hace y cómo se verifica en el entorno local.
