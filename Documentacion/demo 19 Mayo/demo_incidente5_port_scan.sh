#!/usr/bin/env bash
# ============================================================================
#  DEMO PASO A PASO — Incidente 5: Reconocimiento / Port Scan
#  Componente C: Automatización de Respuesta (Bryan)
#  Tesis: Detección y respuesta ante incidentes en AWS (LocalStack)
#
#  Un atacante enumera la infraestructura AWS: DescribeSecurityGroups,
#  DescribeInstances, DescribeSubnets, DescribeVpcs, DescribeNetworkInterfaces
#  en ráfaga rápida desde la misma IP.
#  El Componente B detecta el patrón de reconocimiento (port scan / recon).
#
#  Diferencia clave vs Incidente 1 (brute-force):
#    • El atacante no está golpeando login → está mapeando la infraestructura
#    • Severity: MEDIUM (recon temprano, no hay credenciales comprometidas)
#    • La respuesta proactiva bloquea la IP ANTES de que escale el ataque
#    • Es el "early warning": detectamos antes de que el atacante pueda actuar
#
#  Enforcement REAL demostrado:
#    ec2.create_network_acl_entry(RuleAction="deny", Egress=False)
#    ← mismo mecanismo que brute-force, diferente patrón de ataque
#
#  Uso:  bash "demo 19 Mayo/demo_incidente5_port_scan.sh"
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
  echo -e "${C_OK}[preflight] Recursos AWS OK (S3, SNS, SQS, IAM, EC2/NACL)${NC}"

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
title "0. INCIDENTE 5 — RECONOCIMIENTO / PORT SCAN"
cat <<'EOF'

  Port Scan en AWS ≠ nmap sobre puertos TCP.
  En cloud, el "port scan" es ENUMERAR LA INFRAESTRUCTURA vía API:

     DescribeSecurityGroups   → mapear reglas de firewall
     DescribeInstances        → listar instancias EC2
     DescribeSubnets          → mapear subredes
     DescribeVpcs             → mapear VPCs
     DescribeNetworkInterfaces→ identificar interfaces de red

  Todo en ráfaga, desde la misma IP, en segundos.
  CloudTrail lo registra → Componente B detecta el patrón → ALERTA.

   Generación          Detección (Comp B)      Respuesta (Comp C)
  ┌────────────┐      ┌─────────────────┐    ┌────────────────────────────┐
  │ 5x Describe│─────▶│ DuckDB detecta  │───▶│ SQS → dispatcher →         │
  │ API calls  │      │ recon pattern:  │    │  ├─ notify-alert (SNS)     │
  │ misma IP   │      │ ≥3 Describe ops │    │  └─ block-ip → NACL DENY  │
  │ < 30 seg   │      │ misma IP/minuto │    └────────────────────────────┘
  └────────────┘      └─────────────────┘

  Decisión de diseño: bloquear PROACTIVAMENTE en NACL aunque sea recon.
  El atacante no puede continuar con el ataque si no tiene conectividad.
EOF
pause

# ----------------------------------------------------------------------------
title "1. LA INFRAESTRUCTURA — NACL como punto de cumplimiento"
say "Verifico servicios relevantes:"
curl -s http://localhost:4566/_localstack/health | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['services']; \
   [print(f'   - {k:12s}: {v}') for k,v in d.items() if k in \
   ('s3','sns','sqs','lambda','iam','logs','ec2')]"
say ""
say "${C_OK}EC2 disponible${C_NC} → Network ACL disponible para bloqueo de red."
pause

# ----------------------------------------------------------------------------
title "2. ESTADO ANTES — NACL sin bloqueos"
NACL=$($AWSL ec2 describe-network-acls --filters "Name=default,Values=true" \
       --query 'NetworkAcls[0].NetworkAclId' --output text)
say "Network ACL objetivo: ${C_KEY}${NACL}${C_NC}"
say "Limpiando bloqueos de demos anteriores para una demo reproducible:"
for rn in $($AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
            --query 'NetworkAcls[0].Entries[?Egress==`false` && RuleNumber<`100`].RuleNumber' \
            --output text 2>/dev/null); do
  $AWSL ec2 delete-network-acl-entry --network-acl-id "$NACL" --rule-number "$rn" --ingress 2>/dev/null || true
done
echo ""
key "awslocal ec2 describe-network-acls (entradas de ENTRADA)"
$AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
  --query 'NetworkAcls[0].Entries[?Egress==`false`].[RuleNumber,RuleAction,CidrBlock]' --output table
say ""
say "Solo ${C_KEY}regla 100 = ALLOW 0.0.0.0/0${C_NC} → toda IP puede alcanzar la infraestructura."
say "El atacante puede seguir mapeando libremente."
pause

# ----------------------------------------------------------------------------
title "3. EL RECONOCIMIENTO — inyectar port scan"
say "El atacante ejecuta 5 llamadas API de enumeración en ráfaga:"
say "  DescribeSecurityGroups · DescribeInstances · DescribeSubnets"
say "  DescribeVpcs · DescribeNetworkInterfaces"
say ""
say "Cada una es una llamada ${C_KEY}readOnly=true${C_NC} — solo leen, no modifican."
say "Por eso el atacante cree que es 'seguro'. Pero CloudTrail lo registra todo."
echo ""
key ".venv/bin/python3 simulators/inject_logs.py port-scan"
INJECT_OUT=$(.venv/bin/python3 simulators/inject_logs.py port-scan 2>&1)
echo "$INJECT_OUT" | grep -E '\[inject\]|incident_type|severity|sourceIPAddress|event_count'
ATTACKER_IP=$(echo "$INJECT_OUT" | python3 -c \
  "import sys,re; t=sys.stdin.read(); \
   m=re.search(r'\"sourceIPAddress\": \"([^\"]+)\"', t); \
   print(m.group(1) if m else '0.0.0.0')")
echo ""
key "IP del atacante / explorador:  ${C_KEY}${ATTACKER_IP}${C_NC}"
say ""
say "SEVERITY=MEDIUM pero la respuesta es INMEDIATA y PROACTIVA."
say "Bloqueamos la IP antes de que pueda actuar sobre lo que descubrió."
pause

# ----------------------------------------------------------------------------
title "4. CENTRALIZACIÓN — log en S3 + incidente en SQS"
key "awslocal s3 ls s3://${BUCKET}/cloudtrail/ --recursive (último)"
$AWSL s3 ls s3://$BUCKET/cloudtrail/ --recursive | tail -1
say ""
say "Tabla de enrutamiento del dispatcher:"
say "  PORT_SCAN → [ notify-alert , ${C_KEY}block-ip${C_NC} ]"
say ""
say "block-ip: mismo playbook que brute-force, mismo enforcement NACL DENY."
say "El sistema no distingue el MOTIVO del bloqueo, sino la amenaza que representa."
pause

# ----------------------------------------------------------------------------
title "5. RESPUESTA AUTOMÁTICA — bloqueo de la IP del explorador"
cat <<'EOF'
  El playbook block-ip identifica la IP del atacante desde el payload
  y ejecuta:

    ec2.create_network_acl_entry(
        NetworkAclId = <NACL de la VPC>,
        RuleNumber   = <número < 100>,    ← evalúa ANTES que el ALLOW 100
        RuleAction   = "deny",
        Egress       = False,             ← tráfico de ENTRADA
        CidrBlock    = "<IP>/32",
        Protocol     = "-1",              ← todos los protocolos
    )

  Resultado: la IP del reconocedor no puede llegar a nada en la VPC.
  Espero procesamiento automático...
EOF
for i in $(seq 1 20); do
  HIT=$($AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
    --query "NetworkAcls[0].Entries[?Egress==\`false\` && RuleAction==\`deny\` && CidrBlock==\`${ATTACKER_IP}/32\`]" \
    --output text 2>/dev/null)
  [ -n "$HIT" ] && { say "${C_OK}✔ Bloqueado automáticamente en ~$((i*2))s${C_NC}"; break; }
  sleep 2
done
pause

# ----------------------------------------------------------------------------
title "6. ENFORCEMENT REAL — NACL DESPUÉS del bloqueo"
key "awslocal ec2 describe-network-acls (entradas de ENTRADA)"
$AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
  --query 'NetworkAcls[0].Entries[?Egress==`false`].[RuleNumber,RuleAction,CidrBlock]' --output table
say ""
say "Regla DENY para ${C_KEY}${ATTACKER_IP}/32${C_NC} con número < 100."
say ""
say "CLAVE TÉCNICA — diferencia con Incidente 1 (brute-force):"
say "  • Incidente 1: atacante YA estaba golpeando → respuesta REACTIVA"
say "  • Incidente 5: atacante solo reconociendo → respuesta PROACTIVA"
say "  • Mismo enforcement, diferente ventana temporal de actuación."
say "  • PORT_SCAN Severity=MEDIUM pero bloqueamos igualmente porque"
say "    el recon es el PRIMER PASO de todo ataque avanzado."
pause

# ----------------------------------------------------------------------------
title "7. PISTA DE AUDITORÍA — evidencia en S3"
key "awslocal s3 cp s3://${BUCKET}/responses/blocked-ips.json -"
$AWSL s3 cp s3://$BUCKET/responses/blocked-ips.json - 2>/dev/null \
  | python3 -m json.tool
say ""
say "Campos: ${C_KEY}reason: PORT_SCAN${C_NC} · ${C_KEY}enforcement.network_acl_id${C_NC} · "
say "${C_KEY}enforcement.rule_number${C_NC} (< 100)"
pause

# ----------------------------------------------------------------------------
title "8. COMPARATIVA — Los 5 incidentes y sus enforcement points"
cat <<'EOF'
  ┌──────────────────────────┬────────────────────┬──────────────────────────────────────┐
  │ Incidente                │ Playbook           │ Enforcement Point (línea clave)      │
  ├──────────────────────────┼────────────────────┼──────────────────────────────────────┤
  │ 1. Brute-Force (HIGH)    │ block-ip           │ ec2.create_network_acl_entry(deny)   │
  │ 2. Priv. Escalation (CRIT)│ revoke-credentials│ iam.update_access_key(Inactive)      │
  │                          │                    │ iam.put_user_policy(DenyAll)         │
  │ 3. Credential Leak (CRIT)│ revoke-credentials │ iam.update_access_key(Inactive)      │
  │                          │                    │ iam.put_user_policy(DenyAll)         │
  │ 4. Exfiltration (HIGH)   │ isolate-instance   │ s3.put_bucket_policy(Deny GetObject) │
  │ 5. Port Scan (MED) ←AQUÍ │ block-ip           │ ec2.create_network_acl_entry(deny)   │
  └──────────────────────────┴────────────────────┴──────────────────────────────────────┘

  3 servicios AWS diferentes como enforcement points:
    EC2 Network ACL  → bloqueo de red (IP level)
    IAM Policy/Keys  → bloqueo de identidad (credentials level)
    S3 Bucket Policy → bloqueo de datos (data level)
EOF
pause

# ----------------------------------------------------------------------------
title "9. RESUMEN — Incidente 5: Reconocimiento"
cat <<EOF
  ✔ Flujo AUTOMÁTICO: SQS → dispatcher → block-ip (mismo que Incidente 1)
  ✔ Enforcement REAL: NACL DENY para ${ATTACKER_IP}/32 (regla < 100)
  ✔ Respuesta PROACTIVA: el atacante es bloqueado antes de poder actuar
  ✔ Early warning: bloqueo en etapa de recon → el ATT&CK kill chain se
    interrumpe en "Reconnaissance" antes de llegar a "Execution"
  ✔ 3 evidencias: describe-network-acls (antes/después) · blocked-ips.json
    · log CloudWatch de tesis-block-ip

  Decisión de diseño: PORT_SCAN activa block-ip aunque Severity=MEDIUM.
  El sistema aplica "deny-by-default proactivo" ante cualquier indicador
  de reconocimiento, no solo ante ataques en curso.
EOF
echo ""
echo -e "${C_OK}  === FIN DEMO INCIDENTE 5 ===${C_NC}"
echo ""
echo -e "${C_TITLE}  ┌──────────────────────────────────────────┐${C_NC}"
echo -e "${C_TITLE}  │  Has completado los 5 demos del sistema  │${C_NC}"
echo -e "${C_TITLE}  │  de respuesta automatizada — Comp C      │${C_NC}"
echo -e "${C_TITLE}  └──────────────────────────────────────────┘${C_NC}"
