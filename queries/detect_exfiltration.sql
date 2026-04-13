-- Detección de Exfiltración de Datos
-- Busca acceso masivo a S3 GetObject (>50 objetos) desde la misma IP en 1 hora

SELECT
    sourceIPAddress,
    userIdentity.userName  AS username,
    COUNT(*)               AS total_downloads,
    MIN(eventTime)         AS first_access,
    MAX(eventTime)         AS last_access
FROM read_json_auto('$LOG_PATH', format='array')
WHERE eventSource = 's3.amazonaws.com'
  AND eventName   = 'GetObject'
  AND epoch_ms(eventTime) >= now() - INTERVAL '1 hour'
GROUP BY sourceIPAddress, userIdentity.userName
HAVING COUNT(*) > 50
ORDER BY total_downloads DESC;
