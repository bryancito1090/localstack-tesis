-- Detección de Fuerza Bruta
-- Busca >5 intentos fallidos de ConsoleLogin desde la misma IP en una ventana de 5 minutos
-- Equivalente a una regla Athena sobre la tabla de CloudTrail
-- Sintaxis DuckDB: acceso por campo de struct (r.campo), no por operador JSON (->>)

SELECT
    r.sourceIPAddress,
    r.userIdentity.userName                                    AS username,
    COUNT(*)                                                   AS failed_attempts,
    MIN(r.eventTime)                                           AS first_attempt,
    MAX(r.eventTime)                                           AS last_attempt
FROM (
    SELECT unnest(Records) AS r
    FROM read_json_auto('$LOG_PATH')
)
WHERE r.eventName = 'ConsoleLogin'
  AND r.errorCode = 'AccessDenied'
GROUP BY r.sourceIPAddress, r.userIdentity.userName
HAVING COUNT(*) > 5
ORDER BY failed_attempts DESC;
