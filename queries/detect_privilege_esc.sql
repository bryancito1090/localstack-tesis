-- Detección de Escalada de Privilegios
-- Busca eventos IAM sospechosos: adjuntar políticas admin, crear keys, modificar roles
-- Sintaxis DuckDB: acceso por campo de struct (r.campo), no por operador JSON (->>)

SELECT
    r.userIdentity.userName  AS username,
    r.sourceIPAddress,
    r.eventName,
    r.eventTime,
    r.requestParameters
FROM (
    SELECT unnest(Records) AS r
    FROM read_json_auto('$LOG_PATH')
)
WHERE r.eventSource = 'iam.amazonaws.com'
  AND r.eventName IN (
      'AttachUserPolicy',
      'AttachRolePolicy',
      'CreateAccessKey',
      'PutUserPolicy',
      'AddUserToGroup',
      'CreateLoginProfile',
      'UpdateLoginProfile'
  )
ORDER BY r.eventTime DESC;
