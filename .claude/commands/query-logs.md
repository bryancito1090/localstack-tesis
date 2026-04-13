Ejecuta una consulta SQL sobre los logs de seguridad almacenados localmente usando DuckDB (equivalente a Amazon Athena en el entorno local).

Contexto: Proyecto de tesis, el bucket S3 local (`tesis-security-logs`) contiene archivos JSON de logs de CloudTrail y VPC Flow Logs. DuckDB lee directamente esos archivos JSON para simular las consultas que en producción se harían con Athena + Glue.
Directorio del proyecto: /home/bryan/localstack-tesis
Venv: /home/bryan/localstack-tesis/.venv — usa .venv/bin/python3 y .venv/bin/awslocal
Queries SQL predefinidas: /home/bryan/localstack-tesis/queries/

El argumento indica qué analizar: $ARGUMENTS
Consultas predefinidas disponibles: `brute-force`, `privilege-escalation`, `exfiltration`, `summary`, `recent`
Si se pasa texto libre, ejecútalo como consulta personalizada sobre los logs.

Pasos a ejecutar:
1. Descarga los logs: `.venv/bin/awslocal s3 sync s3://tesis-security-logs/cloudtrail/ /tmp/tesis-logs/`
2. Si /tmp/tesis-logs/ está vacío, usa los logs de referencia locales: `/home/bryan/localstack-tesis/logs/sample_cloudtrail.json`
3. Según el argumento, construye y ejecuta con `/home/bryan/localstack-tesis/.venv/bin/python3`:
   - `brute-force`: usa /home/bryan/localstack-tesis/queries/detect_brute_force.sql como referencia
   - `privilege-escalation`: usa /home/bryan/localstack-tesis/queries/detect_privilege_esc.sql
   - `exfiltration`: usa /home/bryan/localstack-tesis/queries/detect_exfiltration.sql
   - `summary`: cuenta eventos por eventName y eventSource
   - `recent`: últimos 20 eventos por eventTime DESC
4. Ajusta $LOG_PATH en la query al path real del archivo descargado
5. Muestra resultados en tabla y determina: ¿hay IoC? ¿qué Lambda debería activarse?

Los archivos JSON de CloudTrail tienen estructura `{"Records": [...]}` — usa `read_json_auto(path, format='array')` apuntando al array Records.
