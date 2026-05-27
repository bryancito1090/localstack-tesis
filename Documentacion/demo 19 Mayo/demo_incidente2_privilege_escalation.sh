#!/usr/bin/env bash
# ============================================================================
#  DEMO PASO A PASO — Incidente 2: Escalada de Privilegios IAM
#  Componente C: Automatización de Respuesta (Bryan)
#  Tesis: Detección y respuesta ante incidentes en AWS (LocalStack)
#
#  Un atacante compromete un usuario IAM y:
#    1. Lista roles disponibles (reconocimiento)
#    2. Se adjunta la política AdministratorAccess a sí mismo
#    3. Crea una nueva access key para persistencia
#
#  Enforcement REAL demostrado:
#    iam.update_access_key(Status="Inactive")  ← key del atacante revocada
#    iam.put_user_policy("EmergencyDenyAll")   ← acceso total bloqueado
#
#  Verificable con:
#    awslocal iam list-access-keys   → Active → Inactive
#    awslocal iam get-user-policy    → EmergencyDenyAll existe
#
#  Uso:  bash "demo 19 Mayo/demo_incidente2_privilege_escalation.sh"
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.venv/bin:$PATH"

# ── PREFLIGHT ────────────────────────────────────────────────────────────────
_preflight() {
  local C_OK='\033[0;32m'; local C_WARN='\033[1;33m'; local NC='\033[0m'
  echo -e "${C_WARN}[preflight] Verificando entorno...${NC}"

  # 1. LocalStack
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

  # 2. Bootstrap (idempotente — crea usuarios IAM de prueba si no existen)
  bash infra/setup.sh > /dev/null 2>&1
  echo -e "${C_OK}[preflight] Recursos AWS OK (S3, SNS, SQS, IAM users)${NC}"

  # 3. Desplegar / actualizar lambdas
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

  # 4. Event source mapping dispatcher → SQS
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
QUEUE_URL="http://localhost:4566/000000000000/tesis-incident-queue"

C_TITLE='\033[1;36m'; C_OK='\033[0;32m'; C_WARN='\033[1;33m'; C_KEY='\033[1;35m'; C_NC='\033[0m'

pause() { echo ""; read -rp $'\033[1;33m  [ENTER para continuar]\033[0m '; echo ""; }
title() { echo ""; echo -e "${C_TITLE}══════════════════════════════════════════════════════════════════════${C_NC}";
          echo -e "${C_TITLE}  $1${C_NC}";
          echo -e "${C_TITLE}══════════════════════════════════════════════════════════════════════${C_NC}"; }
say()   { echo -e "  $1"; }
key()   { echo -e "${C_KEY}  ▶ $1${C_NC}"; }

# ----------------------------------------------------------------------------
title "0. INCIDENTE 2 — ESCALADA DE PRIVILEGIOS IAM"
cat <<'EOF'

   Ataque           Detección (Comp B)      Respuesta AUTOMÁTICA (Comp C)
  ┌────────────┐    ┌──────────────────┐    ┌────────────────────────────────┐
  │ AttachUser │───▶│ CloudTrail →     │───▶│ SQS → dispatcher →             │
  │ Policy     │    │ DuckDB detecta   │    │  ├─ notify-alert (SNS)         │
  │ (AdminAccs)│    │ AttachUserPolicy │    │  └─ revoke-credentials →       │
  │ CreateAccss│    │ + CreateAccessKey│    │       iam.update_access_key()  │
  │ Key        │    └──────────────────┘    │       (Active → Inactive)      │
  └────────────┘                            │       iam.put_user_policy()    │
                                            │       (EmergencyDenyAll)       │
                                            └────────────────────────────────┘
   ← Componente A ──────────────────────────── Componente C (Bryan) ──────────

  El atacante logró adjuntarse AdministratorAccess y crear una nueva key.
  Respuesta: keys revocadas y DenyAll policy → acceso cortado en segundos.
EOF
pause

# ----------------------------------------------------------------------------
title "1. LA INFRAESTRUCTURA — IAM + LocalStack"
say "Servicios relevantes para este incidente:"
curl -s http://localhost:4566/_localstack/health | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['services']; \
   [print(f'   - {k:12s}: {v}') for k,v in d.items() if k in \
   ('s3','sns','sqs','lambda','iam','logs')]"
say ""
say "IAM disponible → permite desactivar keys y adjuntar políticas de bloqueo."
pause

# ----------------------------------------------------------------------------
title "2. USUARIOS IAM — inventario de usuarios comprometibles"
say "Usuarios IAM de prueba creados en LocalStack:"
key "awslocal iam list-users"
$AWSL iam list-users --query 'Users[].[UserName,UserId]' --output table
pause

# ----------------------------------------------------------------------------
title "3. ESTADO ANTES — access keys activas"
say "Reviso el estado INICIAL de las access keys de los usuarios de prueba."
say "Esperamos ver keys con Status=${C_KEY}Active${C_NC} — las que el atacante puede usar."
echo ""
for user in admin dev-operator ci-runner; do
  key "awslocal iam list-access-keys --user-name $user"
  $AWSL iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[].[UserName,AccessKeyId,Status]' \
    --output table 2>/dev/null || say "  (sin keys)"
done
say ""
say "Política inline activa: ${C_KEY}ninguna${C_NC} (sin bloqueos previos)."
pause

# ----------------------------------------------------------------------------
title "4. EL ATAQUE — inyectar escalada de privilegios"
say "Un atacante accede con credenciales comprometidas y ejecuta:"
say "  1. ListRoles         → reconocimiento de permisos disponibles"
say "  2. AttachUserPolicy  → se adjunta AdministratorAccess"
say "  3. CreateAccessKey   → crea key de persistencia backdoor"
echo ""
key ".venv/bin/python3 simulators/inject_logs.py privilege-escalation"
INJECT_OUT=$(.venv/bin/python3 simulators/inject_logs.py privilege-escalation 2>&1)
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
key "Usuario comprometido: ${C_KEY}${VICTIM_USER}${C_NC}"
key "IP del atacante:      ${C_KEY}${ATTACKER_IP}${C_NC}"
say ""
say "El incidente está en SQS. El dispatcher lo procesará automáticamente."
pause

# ----------------------------------------------------------------------------
title "5. RESPUESTA AUTOMÁTICA — dispatcher enruta el incidente"
cat <<'EOF'
  El dispatcher recibe PRIVILEGE_ESCALATION desde SQS y aplica:

     PRIVILEGE_ESCALATION  →  [ notify-alert ,  revoke-credentials ]

  - notify-alert         : publica la alerta en SNS
  - revoke-credentials   : DESACTIVA las keys + aplica EmergencyDenyAll

  Sin intervención humana. Espero a que el playbook actúe...
EOF
for i in $(seq 1 20); do
  HIT=$($AWSL s3api head-object --bucket tesis-security-logs \
    --key "responses/revoked-credentials.json" 2>/dev/null || echo "")
  if [ -n "$HIT" ]; then
    say "${C_OK}Procesado automáticamente en ~$((i*2))s${C_NC}"
    break
  fi
  # También verificar por el estado de la key
  KEY_STATUS=$($AWSL iam list-access-keys --user-name "$VICTIM_USER" \
    --query 'AccessKeyMetadata[0].Status' --output text 2>/dev/null || echo "")
  if [ "$KEY_STATUS" = "Inactive" ]; then
    say "${C_OK}Keys revocadas automáticamente en ~$((i*2))s${C_NC}"
    break
  fi
  sleep 2
done
pause

# ----------------------------------------------------------------------------
title "6. ENFORCEMENT REAL — estado de las keys DESPUÉS"
key "awslocal iam list-access-keys --user-name ${VICTIM_USER}"
$AWSL iam list-access-keys --user-name "$VICTIM_USER" \
  --query 'AccessKeyMetadata[].[UserName,AccessKeyId,Status]' \
  --output table 2>/dev/null
say ""
say "Status cambió de ${C_WARN}Active${C_NC} → ${C_OK}Inactive${C_NC}."
say ""
say "CLAVE TÉCNICA: ${C_KEY}Status=Inactive${C_NC} en IAM significa que la key NO"
say "puede autenticar ninguna llamada API. Si el atacante intenta usar esas"
say "credenciales, recibe InvalidClientTokenId — acceso cortado."
pause

# ----------------------------------------------------------------------------
title "7. SEGUNDA CAPA DE BLOQUEO — política EmergencyDenyAll"
key "awslocal iam get-user-policy --user-name ${VICTIM_USER} --policy-name EmergencyDenyAll"
$AWSL iam get-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name EmergencyDenyAll \
  --query 'PolicyDocument' --output text 2>/dev/null | python3 -m json.tool || \
  say "(política no encontrada aún; puede tardar unos segundos)"
say ""
say "CLAVE TÉCNICA: aunque existan tokens STS activos o keys no listadas,"
say "la política inline ${C_KEY}Deny */*${C_NC} los bloquea a todos."
say "Es la segunda capa de contención — el atacante no puede hacer NADA."
pause

# ----------------------------------------------------------------------------
title "8. PISTA DE AUDITORÍA — evidencia en S3"
say "El playbook registra exactamente QUÉ revocó y CUÁNDO:"
key "awslocal s3 cp s3://${BUCKET}/responses/revoked-credentials.json -"
$AWSL s3 cp s3://$BUCKET/responses/revoked-credentials.json - 2>/dev/null \
  | python3 -m json.tool
say ""
say "El campo ${C_KEY}enforcement.key_ids${C_NC} lista cada AccessKeyId revocada."
pause

# ----------------------------------------------------------------------------
title "9. TRAZABILIDAD — log de ejecución en CloudWatch"
LG="/aws/lambda/tesis-revoke-credentials"
key "awslocal logs filter-log-events $LG"
$AWSL logs filter-log-events --log-group-name "$LG" \
  --query 'events[*].message' --output text 2>/dev/null \
  | tr '\t' '\n' | grep -i 'revoke-credentials\|Desactivada\|DenyAll' | tail -5
[ $? -ne 0 ] && say "(sin coincidencias; el log puede tardar unos segundos)"
pause

# ----------------------------------------------------------------------------
title "10. RESUMEN — Incidente 2: Escalada de Privilegios"
cat <<EOF
  ✔ Flujo AUTOMÁTICO: SQS → dispatcher → revoke-credentials (sin intervención)
  ✔ Enforcement REAL en IAM:
      iam.update_access_key(Status="Inactive")    → credentials revocadas
      iam.put_user_policy("EmergencyDenyAll")     → acceso total bloqueado
  ✔ Dos capas de contención:
      1. Keys Inactive: ninguna nueva auth posible con esas credenciales
      2. Deny-All policy: bloquea también tokens STS activos y futuras keys
  ✔ 3 evidencias: list-access-keys (Active→Inactive) · get-user-policy
    (EmergencyDenyAll) · responses/revoked-credentials.json en S3
  ✔ IAM de mínimo privilegio para el rol del playbook

  Enforcement point exacto:
    lambdas/revoke-credentials/handler.py
    → iam.update_access_key(UserName=username, AccessKeyId=kid, Status="Inactive")
EOF
echo ""
echo -e "${C_OK}  === FIN DEMO INCIDENTE 2 ===${C_NC}"
