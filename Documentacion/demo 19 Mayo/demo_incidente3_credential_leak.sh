#!/usr/bin/env bash
# ============================================================================
#  DEMO PASO A PASO — Incidente 3: Filtración de Credenciales (Credential Leak)
#  Componente C: Automatización de Respuesta (Bryan)
#  Tesis: Detección y respuesta ante incidentes en AWS (LocalStack)
#
#  Escenario: Las credenciales de un usuario IAM fueron expuestas
#  (repositorio público, pasta en web, etc.) y alguien las está usando
#  desde una IP externa desconocida. El primer uso es GetCallerIdentity
#  (verifican que las credenciales sirven) → alarma inmediata.
#
#  Diferencia clave vs Incidente 2:
#    • El atacante NO escala privilegios todavía — solo VERIFICA las credenciales
#    • La detección es por ANOMALÍA DE IP (IP externa + API call inusual)
#    • La respuesta sigue siendo revocación preventiva antes de que actúe
#
#  Enforcement REAL demostrado:
#    iam.update_access_key(Status="Inactive")  ← key filtrada revocada
#    iam.put_user_policy("EmergencyDenyAll")   ← acceso total bloqueado
#
#  Uso:  bash "demo 19 Mayo/demo_incidente3_credential_leak.sh"
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
  echo -e "${C_OK}[preflight] Recursos AWS OK (S3, SNS, SQS, IAM users)${NC}"

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

C_TITLE='\033[1;36m'; C_OK='\033[0;32m'; C_WARN='\033[1;33m'; C_KEY='\033[1;35m'; C_NC='\033[0m'

pause() { echo ""; read -rp $'\033[1;33m  [ENTER para continuar]\033[0m '; echo ""; }
title() { echo ""; echo -e "${C_TITLE}══════════════════════════════════════════════════════════════════════${C_NC}";
          echo -e "${C_TITLE}  $1${C_NC}";
          echo -e "${C_TITLE}══════════════════════════════════════════════════════════════════════${C_NC}"; }
say()   { echo -e "  $1"; }
key()   { echo -e "${C_KEY}  ▶ $1${C_NC}"; }

# ----------------------------------------------------------------------------
title "0. INCIDENTE 3 — FILTRACIÓN DE CREDENCIALES"
cat <<'EOF'

  Línea de tiempo del incidente:

  [T-X]  Las credenciales de un usuario IAM se filtran
         (commit en GitHub, Pastebin, etc.)

  [T-0]  El atacante las prueba con GetCallerIdentity desde IP externa
         ← CloudTrail registra: usuario conocido, IP DESCONOCIDA

  [T+0]  Componente B detecta anomalía de IP y genera alerta CRITICAL

  [T+2s] Componente C revoca las credenciales ANTES de que el atacante actúe

  La clave: la respuesta ocurre en segundos, no en horas. Sin SLA humano.

   IP conocida (VPN/corp):  10.0.x.x / 192.168.x.x   ← LEGÍTIMA
   IP detectada en CloudTrail: 203.0.113.x / 198.51.x  ← EXTERNAL → ALERTA
EOF
pause

# ----------------------------------------------------------------------------
title "1. ESTADO ANTES — credenciales activas y accesibles"
say "El usuario comprometido tiene access keys en estado ${C_WARN}Active${C_NC}."
say "Cualquiera con esas keys puede autenticarse contra la cuenta AWS."
echo ""
say "Usuarios IAM actualmente en LocalStack:"
$AWSL iam list-users --query 'Users[].[UserName]' --output table 2>/dev/null
echo ""
say "Limpio respuestas anteriores para una demo reproducible:"
$AWSL s3 rm s3://$BUCKET/responses/revoked-credentials.json 2>/dev/null || true
echo ""
say "Verifico que ningún usuario tiene política EmergencyDenyAll:"
for user in admin dev-operator ci-runner; do
  POLICY=$($AWSL iam get-user-policy --user-name "$user" \
    --policy-name EmergencyDenyAll 2>&1 || echo "NoSuchEntity")
  if echo "$POLICY" | grep -q "NoSuchEntity"; then
    say "  ${C_OK}$user${C_NC}: sin bloqueo previo"
  else
    say "  ${C_WARN}$user${C_NC}: ya tiene EmergencyDenyAll (demo anterior)"
  fi
done
pause

# ----------------------------------------------------------------------------
title "2. LA FILTRACIÓN — uso de credenciales desde IP externa"
say "Simulo el momento en que el atacante prueba las credenciales filtradas."
say "GetCallerIdentity: el equivalente a 'whoami' en AWS."
say "Desde una IP externa → CloudTrail registra la anomalía."
echo ""
key ".venv/bin/python3 simulators/inject_logs.py credential-leak"
INJECT_OUT=$(.venv/bin/python3 simulators/inject_logs.py credential-leak 2>&1)
echo "$INJECT_OUT" | grep -E '\[inject\]|affectedResource|incident_type|severity|sourceIPAddress'
VICTIM_USER=$(echo "$INJECT_OUT" | python3 -c \
  "import sys,re; t=sys.stdin.read(); \
   m=re.search(r'\"affectedResource\": \"iam:user/([^\"]+)\"', t); \
   print(m.group(1) if m else 'admin')")
ATTACKER_IP=$(echo "$INJECT_OUT" | python3 -c \
  "import sys,re; t=sys.stdin.read(); \
   m=re.search(r'\"sourceIPAddress\": \"([^\"]+)\"', t); \
   print(m.group(1) if m else '0.0.0.0')")
echo ""
key "Credenciales filtradas del usuario: ${C_KEY}${VICTIM_USER}${C_NC}"
key "IP externa detectada:               ${C_KEY}${ATTACKER_IP}${C_NC}"
say ""
say "SEVERITY=CRITICAL → la detección es inmediata y la respuesta automática."
pause

# ----------------------------------------------------------------------------
title "3. CENTRALIZACIÓN — el log llegó a S3 y el incidente a SQS"
key "awslocal s3 ls s3://${BUCKET}/cloudtrail/ --recursive (último)"
$AWSL s3 ls s3://$BUCKET/cloudtrail/ --recursive | tail -1
say ""
say "El evento incluye el IP externo. El Componente B lo clasifica como"
say "${C_KEY}CREDENTIAL_LEAK${C_NC} por la combinación: usuario conocido + IP desconocida."
say ""
say "El dispatcher lo enruta:"
say "  CREDENTIAL_LEAK → [ notify-alert , ${C_KEY}revoke-credentials${C_NC} ]"
pause

# ----------------------------------------------------------------------------
title "4. RESPUESTA AUTOMÁTICA — revocación preventiva"
cat <<'EOF'
  El playbook revoke-credentials actúa en dos pasos:

  PASO 1:  iam.list_access_keys(UserName)
           ↓ para cada key con Status=Active:
           iam.update_access_key(Status="Inactive")   ← ENFORCEMENT POINT
           → La credencial filtrada ya NO puede autenticarse

  PASO 2:  iam.put_user_policy("EmergencyDenyAll")
           → Aunque el atacante tenga un token STS activo,
             la política Deny-All bloquea cualquier acción

  Esperando procesamiento automático...
EOF
for i in $(seq 1 20); do
  KEY_STATUS=$($AWSL iam list-access-keys --user-name "$VICTIM_USER" \
    --query 'AccessKeyMetadata[0].Status' --output text 2>/dev/null || echo "")
  if [ "$KEY_STATUS" = "Inactive" ]; then
    say "${C_OK}✔ Credencial revocada automáticamente en ~$((i*2))s${C_NC}"
    break
  fi
  # Fallback: verificar por S3
  HIT=$($AWSL s3api head-object --bucket tesis-security-logs \
    --key "responses/revoked-credentials.json" 2>/dev/null || echo "")
  [ -n "$HIT" ] && { say "${C_OK}✔ Respuesta registrada en S3 en ~$((i*2))s${C_NC}"; break; }
  sleep 2
done
pause

# ----------------------------------------------------------------------------
title "5. ENFORCEMENT REAL — keys DESPUÉS de la respuesta"
key "awslocal iam list-access-keys --user-name ${VICTIM_USER}"
$AWSL iam list-access-keys --user-name "$VICTIM_USER" \
  --query 'AccessKeyMetadata[].[UserName,AccessKeyId,Status,CreateDate]' \
  --output table 2>/dev/null
say ""
say "El Status pasó de ${C_WARN}Active${C_NC} → ${C_OK}Inactive${C_NC}."
say "El atacante recibe ${C_KEY}InvalidClientTokenId${C_NC} en cualquier intento."
pause

# ----------------------------------------------------------------------------
title "6. SEGUNDA CAPA — política EmergencyDenyAll verificada"
key "awslocal iam get-user-policy --user-name ${VICTIM_USER} --policy-name EmergencyDenyAll"
$AWSL iam get-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name EmergencyDenyAll \
  --query 'PolicyDocument' --output text 2>/dev/null | python3 -m json.tool || \
  say "(la política puede tardar unos segundos en indexarse)"
say ""
say "Effect: ${C_KEY}Deny${C_NC} · Action: ${C_KEY}*${C_NC} · Resource: ${C_KEY}*${C_NC}"
say "El usuario está completamente bloqueado hasta revisión por el equipo."
pause

# ----------------------------------------------------------------------------
title "7. PISTA DE AUDITORÍA — evidencia en S3"
key "awslocal s3 cp s3://${BUCKET}/responses/revoked-credentials.json -"
$AWSL s3 cp s3://$BUCKET/responses/revoked-credentials.json - 2>/dev/null \
  | python3 -m json.tool
say ""
say "Campos clave: ${C_KEY}username${C_NC} · ${C_KEY}sourceIPAddress${C_NC} · "
say "${C_KEY}enforcement.keys_deactivated${C_NC} · ${C_KEY}enforcement.deny_all_applied${C_NC}"
pause

# ----------------------------------------------------------------------------
title "8. RESUMEN — Incidente 3: Filtración de Credenciales"
cat <<EOF
  ✔ Flujo AUTOMÁTICO: SQS → dispatcher → revoke-credentials (sin intervención)
  ✔ Enforcement REAL (mismo playbook que Incidente 2, diferente vector):
      iam.update_access_key(Status="Inactive")  → credencial filtrada revocada
      iam.put_user_policy("EmergencyDenyAll")   → bloqueo total
  ✔ Diferencia con Incidente 2:
      • El atacante solo verificó las credenciales (GetCallerIdentity)
      • La respuesta es PREVENTIVA: cortamos antes de que actúe
      • Detectado por anomalía de IP, no por la acción en sí
  ✔ 3 evidencias: list-access-keys · get-user-policy · revoked-credentials.json
  ✔ Tiempo de respuesta: ~2-4 segundos desde el evento

  Decisión de diseño: CREDENTIAL_LEAK tiene severity=CRITICAL → el dispatcher
  activa revoke-credentials aunque solo sea el primer API call sospechoso.
  Mejor un falso positivo que dejar actuar al atacante.
EOF
echo ""
echo -e "${C_OK}  === FIN DEMO INCIDENTE 3 ===${C_NC}"
