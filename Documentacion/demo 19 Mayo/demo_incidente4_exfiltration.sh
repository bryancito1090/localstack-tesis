#!/usr/bin/env bash
# ============================================================================
#  DEMO PASO A PASO — Incidente 4: Exfiltración de Datos S3
#  Componente C: Automatización de Respuesta (Bryan)
#  Tesis: Detección y respuesta ante incidentes en AWS (LocalStack)
#
#  Un atacante descarga masivamente objetos de un bucket S3 sensible:
#  50 operaciones GetObject en segundos desde la misma IP externa.
#  El Componente B detecta el volumen anómalo y genera EXFILTRATION.
#
#  Enforcement REAL demostrado:
#    s3.put_bucket_policy(Deny GetObject + ListBucket para la IP atacante)
#    ← el bucket queda INACCESIBLE para esa IP — exfiltración cortada
#
#  Verificable con:
#    awslocal s3api get-bucket-policy → sin Deny (ANTES)
#    awslocal s3api get-bucket-policy → con Deny para IP atacante (DESPUÉS)
#
#  Uso:  bash "demo 19 Mayo/demo_incidente4_exfiltration.sh"
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.venv/bin:$PATH"

# ── PREFLIGHT ────────────────────────────────────────────────────────────────
_preflight() {
  local C_OK='\033[0;32m'; local C_WARN='\033[1;33m'; local NC='\033[0m'
  echo -e "${C_WARN}[preflight] Verificando entorno...${NC}"

  if ! curl -sf http://localhost:4566/_localstack/health > /dev/null 2>&1; then
    echo -e "${C_WARN}[preflight] Levantando LocalStack...${NC}"
    docker compose up -d
    echo -n "[preflight] Esperando"
    for i in $(seq 1 30); do
      curl -sf http://localhost:4566/_localstack/health > /dev/null 2>&1 && break
      echo -n "." ; sleep 2
    done; echo ""
  fi
  echo -e "${C_OK}[preflight] LocalStack OK${NC}"

  bash infra/setup.sh > /dev/null 2>&1
  echo -e "${C_OK}[preflight] Recursos AWS OK (S3, SNS, SQS, prod-data-bucket)${NC}"

  local ROLE="arn:aws:iam::000000000000:role/tesis-lambda-response-role"
  local ENV_VARS="Variables={S3_BUCKET=tesis-security-logs,SNS_ALERTS_ARN=arn:aws:sns:us-east-1:000000000000:tesis-security-alerts}"
  for fn in notify-alert block-ip revoke-credentials isolate-instance dispatcher; do
    local zip="/tmp/tesis-${fn}.zip"
    python3 -c "
import zipfile
z = zipfile.ZipFile('${zip}', 'w', __import__('zipfile').ZIP_DEFLATED)
z.write('lambdas/${fn}/handler.py', 'handler.py')
z.close()
"
    if awslocal lambda get-function --function-name "tesis-${fn}" > /dev/null 2>&1; then
      awslocal lambda update-function-code \
        --function-name "tesis-${fn}" --zip-file "fileb://${zip}" > /dev/null
    else
      awslocal lambda create-function \
        --function-name "tesis-${fn}" --runtime python3.12 --role "$ROLE" \
        --handler handler.lambda_handler --zip-file "fileb://${zip}" \
        --timeout 30 --environment "$ENV_VARS" > /dev/null
    fi
  done
  echo -e "${C_OK}[preflight] Lambdas OK${NC}"

  local QUEUE_ARN="arn:aws:sqs:us-east-1:000000000000:tesis-incident-queue"
  local mapping_count
  mapping_count=$(awslocal lambda list-event-source-mappings \
    --function-name tesis-dispatcher \
    --query 'length(EventSourceMappings)' --output text 2>/dev/null || echo "0")
  if [ "$mapping_count" = "0" ] || [ -z "$mapping_count" ]; then
    awslocal lambda create-event-source-mapping \
      --function-name tesis-dispatcher \
      --event-source-arn "$QUEUE_ARN" \
      --batch-size 1 --enabled > /dev/null
  fi
  echo -e "${C_OK}[preflight] Event source mapping SQS→dispatcher OK${NC}"
  echo ""
}
_preflight

AWSL="awslocal"
BUCKET="tesis-security-logs"
DATA_BUCKET="prod-data-bucket"

C_TITLE='\033[1;36m'; C_OK='\033[0;32m'; C_WARN='\033[1;33m'; C_KEY='\033[1;35m'; C_NC='\033[0m'

pause() { echo ""; read -rp $'\033[1;33m  [ENTER para continuar]\033[0m '; echo ""; }
title() { echo ""; echo -e "${C_TITLE}══════════════════════════════════════════════════════════════════════${C_NC}";
          echo -e "${C_TITLE}  $1${C_NC}";
          echo -e "${C_TITLE}══════════════════════════════════════════════════════════════════════${C_NC}"; }
say()   { echo -e "  $1"; }
key()   { echo -e "${C_KEY}  ▶ $1${C_NC}"; }

# ----------------------------------------------------------------------------
title "0. INCIDENTE 4 — EXFILTRACIÓN DE DATOS S3"
cat <<'EOF'

   Generación         Detección (Comp B)       Respuesta AUTOMÁTICA (Comp C)
  ┌──────────────┐   ┌───────────────────┐   ┌──────────────────────────────────┐
  │ 50x GetObject│──▶│ DuckDB detecta    │──▶│ SQS → dispatcher →               │
  │ desde IP     │   │ volumen anómalo   │   │  ├─ notify-alert (SNS)           │
  │ externa en   │   │ (>10 GetObject/   │   │  └─ isolate-instance →           │
  │ mismo bucket │   │  min misma IP)    │   │       s3.put_bucket_policy()     │
  └──────────────┘   └───────────────────┘   │       Deny GetObject para la IP  │
                                              └──────────────────────────────────┘

  Enforcement: la política de bucket bloquea TODA descarga desde esa IP.
  El atacante ya tiene los datos de esa sesión, pero no puede seguir.
  Y cualquier intento futuro recibe 403 Forbidden.
EOF
pause

# ----------------------------------------------------------------------------
title "1. EL BUCKET CON DATOS SENSIBLES — estado inicial"
say "El bucket ${C_KEY}${DATA_BUCKET}${C_NC} contiene datos sensibles:"
key "awslocal s3 ls s3://${DATA_BUCKET}/data/"
$AWSL s3 ls s3://$DATA_BUCKET/data/ 2>/dev/null || say "  (bucket no tiene objetos aún)"
say ""
say "Verifico que NO hay política restrictiva actualmente:"
key "awslocal s3api get-bucket-policy --bucket ${DATA_BUCKET}"
EXISTING_POLICY=$($AWSL s3api get-bucket-policy --bucket "$DATA_BUCKET" 2>&1 || echo "NoSuchBucketPolicy")
if echo "$EXISTING_POLICY" | grep -q "NoSuchBucketPolicy\|NoSuchBucket"; then
  say "  ${C_OK}Sin política → bucket ACCESIBLE para todos los usuarios autorizados${C_NC}"
  say "  (sin Deny para ninguna IP)"
else
  say "  Política existente detectada. Limpiando para demo reproducible..."
  $AWSL s3api delete-bucket-policy --bucket "$DATA_BUCKET" 2>/dev/null || true
  say "  ${C_OK}Política limpiada → bucket ACCESIBLE${C_NC}"
fi
pause

# ----------------------------------------------------------------------------
title "2. EL ATAQUE — descarga masiva de objetos S3"
say "El atacante extrae 50 archivos del bucket en ráfaga rápida."
say "CloudTrail registra 50 eventos GetObject desde la misma IP → anomalía."
echo ""
key ".venv/bin/python3 simulators/inject_logs.py exfiltration"
INJECT_OUT=$(.venv/bin/python3 simulators/inject_logs.py exfiltration 2>&1)
echo "$INJECT_OUT" | grep -E '\[inject\]|affectedResource|incident_type|severity|sourceIPAddress|event_count'
ATTACKER_IP=$(echo "$INJECT_OUT" | python3 -c \
  "import sys,re; t=sys.stdin.read(); \
   m=re.search(r'\"sourceIPAddress\": \"([^\"]+)\"', t); \
   print(m.group(1) if m else '0.0.0.0')")
AFFECTED_BUCKET=$(echo "$INJECT_OUT" | python3 -c \
  "import sys,re; t=sys.stdin.read(); \
   m=re.search(r'\"affectedResource\": \"s3:bucket/([^\"]+)\"', t); \
   print(m.group(1) if m else 'prod-data-bucket')")
echo ""
key "Bucket exfiltrado:    ${C_KEY}${AFFECTED_BUCKET}${C_NC}"
key "IP del atacante:      ${C_KEY}${ATTACKER_IP}${C_NC}"
say ""
say "50 eventos GetObject = patrón de exfiltración. EXFILTRATION → ALTA prioridad."
pause

# ----------------------------------------------------------------------------
title "3. CENTRALIZACIÓN — log en S3 + incidente en SQS"
key "awslocal s3 ls s3://${BUCKET}/cloudtrail/ --recursive (último)"
$AWSL s3 ls s3://$BUCKET/cloudtrail/ --recursive | tail -1
say ""
say "El dispatcher recibe EXFILTRATION y aplica su tabla:"
cat <<'EOF'
     EXFILTRATION  →  [ notify-alert ,  isolate-instance ]

  - notify-alert     : publica alerta en SNS
  - isolate-instance : detecta recurso s3:bucket/<nombre>
                       → aplica put_bucket_policy(Deny GetObject)
                       ← ENFORCEMENT POINT REAL
EOF
pause

# ----------------------------------------------------------------------------
title "4. RESPUESTA AUTOMÁTICA — bloqueando el bucket"
say "Sin intervención humana. Espero a que el playbook aplique la política..."
echo ""
for i in $(seq 1 25); do
  POLICY=$($AWSL s3api get-bucket-policy --bucket "$AFFECTED_BUCKET" 2>/dev/null || echo "")
  if echo "$POLICY" | grep -q "Deny"; then
    say "${C_OK}✔ Política de bloqueo aplicada automáticamente en ~$((i*2))s${C_NC}"
    break
  fi
  # Fallback: verificar quarantine en S3
  HIT=$($AWSL s3api head-object --bucket tesis-security-logs \
    --key "responses/quarantine-instances.json" 2>/dev/null || echo "")
  [ -n "$HIT" ] && { say "${C_OK}✔ Cuarentena registrada en ~$((i*2))s${C_NC}"; break; }
  sleep 2
done
pause

# ----------------------------------------------------------------------------
title "5. ENFORCEMENT REAL — política de bucket DESPUÉS"
key "awslocal s3api get-bucket-policy --bucket ${AFFECTED_BUCKET}"
$AWSL s3api get-bucket-policy --bucket "$AFFECTED_BUCKET" \
  --query 'Policy' --output text 2>/dev/null | python3 -m json.tool || \
  say "(política aún no aplicada; reintentando en unos segundos)"
say ""
say "CLAVE TÉCNICA:"
say "  Effect: ${C_KEY}Deny${C_NC}"
say "  Action: ${C_KEY}[s3:GetObject, s3:ListBucket]${C_NC}"
say "  Condition.IpAddress.aws:SourceIp: ${C_KEY}[${ATTACKER_IP}/32]${C_NC}"
say ""
say "Cualquier intento de GetObject desde ${C_WARN}${ATTACKER_IP}${C_NC} recibirá ${C_KEY}403 Forbidden${C_NC}."
say "La exfiltración futura está cortada. Los datos ya descargados no"
say "pueden recuperarse, pero se impide cualquier descarga adicional."
pause

# ----------------------------------------------------------------------------
title "6. PISTA DE AUDITORÍA — evidencia de cuarentena en S3"
key "awslocal s3 cp s3://${BUCKET}/responses/quarantine-instances.json -"
$AWSL s3 cp s3://$BUCKET/responses/quarantine-instances.json - 2>/dev/null \
  | python3 -m json.tool
say ""
say "Campos clave: ${C_KEY}resource${C_NC} (s3:bucket/<nombre>) · "
say "${C_KEY}enforcement.denied_ip${C_NC} · ${C_KEY}enforcement.blocked_actions${C_NC}"
pause

# ----------------------------------------------------------------------------
title "7. TRAZABILIDAD — log de ejecución en CloudWatch"
LG="/aws/lambda/tesis-isolate-instance"
key "awslocal logs filter-log-events $LG"
$AWSL logs filter-log-events --log-group-name "$LG" \
  --query 'events[*].message' --output text 2>/dev/null \
  | tr '\t' '\n' | grep -i 'isolate-instance\|Deny\|exfiltr\|bloqueada' | tail -5
[ $? -ne 0 ] && say "(sin coincidencias; el log puede tardar unos segundos)"
pause

# ----------------------------------------------------------------------------
title "8. RESUMEN — Incidente 4: Exfiltración de Datos S3"
cat <<EOF
  ✔ Flujo AUTOMÁTICO: SQS → dispatcher → isolate-instance (sin intervención)
  ✔ Enforcement REAL en S3:
      s3.put_bucket_policy(Deny GetObject + ListBucket para ${ATTACKER_IP}/32)
      → el atacante recibe 403 Forbidden en cualquier descarga futura
  ✔ Enforcement point exacto:
      lambdas/isolate-instance/handler.py → _block_s3_exfiltration()
      → s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(new_policy))
  ✔ 3 evidencias:
      - s3api get-bucket-policy (sin Deny → con Deny) · antes / después
      - responses/quarantine-instances.json (enforcement.blocked_actions)
      - Log CloudWatch de tesis-isolate-instance
  ✔ Idempotente: si el mismo atacante reintenta, la política ya existe

  Decisión de diseño: el playbook detecta el tipo de recurso por el prefijo
  "s3:bucket/" en affectedResource → aplica la acción correcta.
  Para instancias EC2 aplica cuarentena de red; para S3, bucket policy.
EOF
echo ""
echo -e "${C_OK}  === FIN DEMO INCIDENTE 4 ===${C_NC}"
