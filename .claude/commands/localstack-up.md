Verifica que el stack de LocalStack esté corriendo y healthy. Si no está corriendo, levántalo.

Directorio del proyecto: /home/bryan/localstack-tesis
El venv del proyecto está en /home/bryan/localstack-tesis/.venv — usa .venv/bin/awslocal para todos los comandos awslocal.

Pasos a ejecutar:
1. Corre `docker compose -f /home/bryan/localstack-tesis/docker-compose.yml ps` para ver el estado actual
2. Si localstack no está corriendo, ejecuta `docker compose -f /home/bryan/localstack-tesis/docker-compose.yml up -d`
3. Verifica el health endpoint: `curl -s http://localhost:4566/_localstack/health | python3 -m json.tool`
4. Confirma que s3, sns, sqs, lambda, iam, logs estén en estado "running" o "available"
5. Reporta el estado final de cada servicio relevante para el Componente C (Automatización de Respuesta)

Si hay errores, muestra los últimos 20 líneas de `docker compose -f /home/bryan/localstack-tesis/docker-compose.yml logs localstack`.
