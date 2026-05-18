# Demo Brute-Force — 2026-05-12

> Escribir los skills en el chat de Claude Code. Solo los últimos 2 pasos usan terminal.

---

## Pasos en orden

| # | Dónde | Qué escribir | Qué hace |
|---|-------|-------------|----------|
| 1 | Claude Code | `/localstack-up` | Levanta LocalStack y verifica servicios |
| 2 | Claude Code | `/bootstrap-resources` | Crea S3, SNS, SQS e IAM |
| 3 | Claude Code | `/deploy-lambda notify-alert` | Despliega playbook de alertas |
| 4 | Claude Code | `/deploy-lambda block-ip` | Despliega playbook de bloqueo de IPs |
| 5 | Claude Code | `/deploy-lambda dispatcher` | Despliega el coordinador de playbooks |
| 6 | Claude Code | `/simulate-incident brute-force` | Genera el ataque y lo sube a S3 + SQS |
| 7 | Claude Code | `/query-logs brute-force` | Detecta el IoC con SQL (equivale a Athena) |
| 8 | Terminal | ver abajo | Activa la respuesta automática |
| 9 | Terminal | ver abajo | Muestra los archivos generados |

---

## Paso 8 — Activar respuesta automática (terminal)

```bash
cd ~/localstack-tesis && source activate.sh
.venv/bin/awslocal lambda invoke \
  --function-name tesis-dispatcher \
  --cli-binary-format raw-in-base64-out \
  --payload file://lambdas/dispatcher/test_event.json \
  /tmp/respuesta-dispatcher.json
python3 -m json.tool /tmp/respuesta-dispatcher.json
```

---

## Paso 9 — Ver archivos generados (terminal)

```bash
# Qué hay en S3
.venv/bin/awslocal s3 ls s3://tesis-security-logs/ --recursive

# IP bloqueada
.venv/bin/awslocal s3 cp s3://tesis-security-logs/responses/blocked-ips.json - | python3 -m json.tool

# Logs de las Lambdas
for fn in tesis-dispatcher tesis-notify-alert tesis-block-ip; do
  echo "=== $fn ==="
  stream=$(.venv/bin/awslocal logs describe-log-streams \
    --log-group-name /aws/lambda/$fn \
    --query 'logStreams[-1].logStreamName' --output text 2>/dev/null)
  [ "$stream" != "None" ] && .venv/bin/awslocal logs get-log-events \
    --log-group-name /aws/lambda/$fn --log-stream-name "$stream" \
    --query 'events[].message' --output text 2>/dev/null
done
```

---

## Archivos generados por el sistema

| Archivo | Dónde | Lo crea |
|---------|-------|---------|
| `cloudtrail/.../brute-force-XXXX.json` | S3 `tesis-security-logs` | Paso 6 — `/simulate-incident` |
| `responses/blocked-ips.json` | S3 `tesis-security-logs` | Paso 8 — Lambda `block-ip` |
| `/tmp/respuesta-dispatcher.json` | Disco local | Paso 8 — `lambda invoke` |
| Logs de ejecución | CloudWatch `/aws/lambda/tesis-*` | Pasos 3–5 y 8 |

---

## Para la presentación — leer estos archivos

| Qué explica | Archivo |
|-------------|---------|
| Flujo completo con diagrama y detalle de cada playbook | `presentacion_bruteforce_2026-05-12.md` |
| Pasos de la demo (este archivo) | `demo_profesor_2026-05-12.md` |
| Análisis técnico completo con hallazgos y correcciones | `analisis_flujo1_bruteforce.md` |

---

> Si algo falla: repetir el skill del paso que falló. Si LocalStack se reinició, empezar desde el Paso 1.
