-- Detección de Escalada de Privilegios
-- Busca eventos IAM sospechosos: adjuntar políticas admin, crear keys, modificar roles

SELECT
    userIdentity.userName      AS username,
    sourceIPAddress,
    eventName,
    eventTime,
    requestParameters
FROM read_json_auto('$LOG_PATH', format='array')
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN (
      'AttachUserPolicy',
      'AttachRolePolicy',
      'CreateAccessKey',
      'PutUserPolicy',
      'AddUserToGroup',
      'CreateLoginProfile',
      'UpdateLoginProfile'
  )
  AND epoch_ms(eventTime) >= now() - INTERVAL '24 hours'
ORDER BY eventTime DESC;
