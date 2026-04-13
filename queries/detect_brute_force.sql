-- Detección de Fuerza Bruta
-- Busca >5 intentos fallidos de ConsoleLogin desde la misma IP en una ventana de 5 minutos
-- Equivalente a una regla Athena sobre la tabla de CloudTrail

SELECT
    sourceIPAddress,
    userIdentity.userName                                   AS username,
    COUNT(*)                                                AS failed_attempts,
    MIN(eventTime)                                          AS first_attempt,
    MAX(eventTime)                                          AS last_attempt,
    epoch_ms(MAX(epoch_ms(last_attempt)) - MIN(epoch_ms(first_attempt))) AS window_seconds
FROM read_json_auto('$LOG_PATH', format='array')
WHERE eventName     = 'ConsoleLogin'
  AND errorCode     = 'AccessDenied'
  AND epoch_ms(eventTime) >= now() - INTERVAL '1 hour'
GROUP BY sourceIPAddress, userIdentity.userName
HAVING COUNT(*) > 5
ORDER BY failed_attempts DESC;
