-- Detección de Exfiltración de Datos
-- Busca acceso masivo a S3 GetObject (>50 objetos) desde la misma IP en 1 hora
-- Sintaxis DuckDB: acceso por campo de struct (r.campo), no por operador JSON (->>)

SELECT
    r.sourceIPAddress,
    r.userIdentity.userName  AS username,
    COUNT(*)                 AS total_downloads,
    MIN(r.eventTime)         AS first_access,
    MAX(r.eventTime)         AS last_access
FROM (
    SELECT unnest(Records) AS r
    FROM read_json_auto('$LOG_PATH')
)
WHERE r.eventSource = 's3.amazonaws.com'
  AND r.eventName   = 'GetObject'
GROUP BY r.sourceIPAddress, r.userIdentity.userName
HAVING COUNT(*) > 50
ORDER BY total_downloads DESC;
