Despliega o actualiza una función Lambda (Playbook de respuesta) en LocalStack.

Contexto: Proyecto de tesis, Componente C — Automatización de Respuesta. Las Lambdas son playbooks que responden automáticamente a incidentes de seguridad. LocalStack en localhost:4566. Código de Lambdas en `/home/bryan/localstack-tesis/lambdas/`.
Venv: /home/bryan/localstack-tesis/.venv — usa .venv/bin/awslocal para todos los comandos aws.
Rol IAM: arn:aws:iam::000000000000:role/tesis-lambda-response-role

El argumento indica el playbook a desplegar: $ARGUMENTS
Playbooks disponibles: `isolate-instance`, `revoke-credentials`, `block-ip`, `notify-alert`
Si no se especifica, lista los playbooks disponibles y pregunta cuál desplegar.

Pasos a ejecutar:
1. Lee el código de la Lambda en `/home/bryan/localstack-tesis/lambdas/<playbook>/handler.py`
2. Si el directorio no existe, crea la estructura base del playbook con un `handler.py` funcional y mínimo que:
   - Recibe el evento de SQS/SNS
   - Ejecuta la lógica de respuesta usando boto3 apuntando a LocalStack (endpoint_url='http://localhost:4566')
   - Retorna un resultado estructurado con: action, status, timestamp, details
3. Empaqueta: `zip -j /tmp/<playbook>.zip /home/bryan/localstack-tesis/lambdas/<playbook>/handler.py`
4. Despliega con awslocal: verifica si existe primero (`awslocal lambda get-function --function-name tesis-<playbook>`) y usa create-function o update-function-code según corresponda
5. Usa runtime python3.12 (LocalStack Community soporta hasta 3.12), timeout 30s, handler `handler.lambda_handler`
6. Verifica que quedó en estado Active
7. Invoca con el test_event.json del playbook y muestra el resultado

Variables de entorno a pasar a la Lambda: AWS_ENDPOINT_URL=http://localhost:4566, AWS_DEFAULT_REGION=us-east-1, SNS_ALERTS_ARN=arn:aws:sns:us-east-1:000000000000:tesis-security-alerts
