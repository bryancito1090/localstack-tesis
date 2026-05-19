#!/usr/bin/env bash
# ============================================================================
#  DEMO PASO A PASO — Componente C: Automatización de Respuesta (Bryan)
#  Tesis: Detección y respuesta ante incidentes en AWS (LocalStack)
#
#  Esta demo recorre el stack completo y DEMUESTRA el bloqueo REAL de la IP
#  del atacante (regla DENY en una Network ACL), no solo una notificación.
#
#  Uso:   bash demo/demo_stack.sh
#  Cada paso espera ENTER para que puedas explicar mientras presentas.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.venv/bin:$PATH"

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
title "0. ARQUITECTURA DEL SISTEMA"
cat <<'EOF'

   Generación        Centralización      Detección         Respuesta (Componente C)
  ┌───────────┐      ┌────────────┐    ┌────────────┐    ┌──────────────────────────┐
  │ CloudTrail│─────▶│ S3 +       │───▶│ DuckDB /   │───▶│ SQS → dispatcher →       │
  │ (ataque)  │      │ CloudWatch │    │ Metric Flt │    │  ├─ notify-alert (SNS)   │
  └───────────┘      └────────────┘    └────────────┘    │  └─ block-ip → NACL DENY │
                                                          └──────────────────────────┘
   Componente A          Componente A      Componente B        Componente C  (Bryan)

  Lo que demostraré: el flujo es AUTOMÁTICO (sin intervención humana) y la
  acción de block-ip es un BLOQUEO REAL a nivel de red, verificable en
  infraestructura AWS — no una simple notificación.
EOF
pause

# ----------------------------------------------------------------------------
title "1. LA INFRAESTRUCTURA — LocalStack está corriendo"
say "Verifico que los servicios AWS emulados están disponibles:"
key "curl .../_localstack/health"
curl -s http://localhost:4566/_localstack/health | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['services']; \
   [print(f'   - {k:12s}: {v}') for k,v in d.items() if k in \
   ('s3','sns','sqs','lambda','iam','logs','ec2')]"
say ""
say "${C_OK}EC2 disponible${C_NC} → es lo que permite el bloqueo real vía Network ACL."
pause

# ----------------------------------------------------------------------------
title "2. ESQUEMA DE ALMACENAMIENTO — dónde vive la información"
say "Bucket único ${C_KEY}s3://${BUCKET}${C_NC}, organizado por fuente (alineado con Componente A):"
key "awslocal s3 ls s3://${BUCKET}/"
$AWSL s3 ls s3://$BUCKET/ || true
cat <<EOF

   cloudtrail/  → eventos de auditoría (el ataque entra aquí)
   vpc-flow/    → tráfico de red
   guardduty/   → hallazgos
   responses/   → EVIDENCIA DE MITIGACIÓN (lo que genera mi Componente C)

   Particionado por fecha: cloudtrail/AAAA/MM/DD/HHMMSS/<incidente>-<id>.json
EOF
pause

# ----------------------------------------------------------------------------
title "3. PUNTO DE CUMPLIMIENTO — estado de la Network ACL ANTES"
NACL=$($AWSL ec2 describe-network-acls --filters "Name=default,Values=true" \
       --query 'NetworkAcls[0].NetworkAclId' --output text)
say "La NACL ${C_KEY}${NACL}${C_NC} es el firewall de subred donde se aplicará el bloqueo."
say "Limpio reglas de bloqueos anteriores para una demo reproducible..."
for rn in $($AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
            --query 'NetworkAcls[0].Entries[?Egress==`false` && RuleNumber<`100`].RuleNumber' \
            --output text); do
  $AWSL ec2 delete-network-acl-entry --network-acl-id "$NACL" --rule-number "$rn" --ingress 2>/dev/null
done
key "awslocal ec2 describe-network-acls (entradas de ENTRADA)"
$AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
  --query 'NetworkAcls[0].Entries[?Egress==`false`].[RuleNumber,RuleAction,CidrBlock]' --output table
say ""
say "Solo está la ${C_KEY}regla 100 = ALLOW 0.0.0.0/0${C_NC} (permite todo). Sin bloqueos."
pause

# ----------------------------------------------------------------------------
title "4. EL ATAQUE — inyectar un incidente de fuerza bruta"
say "Genero 10 intentos fallidos de login desde una IP atacante y los publico"
say "en S3 (como lo haría CloudTrail real) + SQS (el bus de incidentes):"
key ".venv/bin/python3 simulators/inject_logs.py brute-force"
INJECT_OUT=$(.venv/bin/python3 simulators/inject_logs.py brute-force 2>&1)
echo "$INJECT_OUT" | grep -E '\[inject\]|sourceIPAddress|incident_type|severity'
ATTACKER_IP=$(echo "$INJECT_OUT" | python3 -c \
  "import sys,re,json; t=sys.stdin.read(); m=re.search(r'\"sourceIPAddress\": \"([^\"]+)\"',t); print(m.group(1) if m else '0.0.0.0')")
say ""
key "IP del atacante en este incidente: ${C_KEY}${ATTACKER_IP}${C_NC}"
pause

# ----------------------------------------------------------------------------
title "5. CENTRALIZACIÓN — el log llegó a S3 y el incidente a SQS"
key "awslocal s3 ls s3://${BUCKET}/cloudtrail/ --recursive (último)"
$AWSL s3 ls s3://$BUCKET/cloudtrail/ --recursive | tail -1
say ""
say "El mensaje fue encolado en SQS. Un ${C_KEY}event source mapping${C_NC} conecta"
say "esa cola con la Lambda dispatcher → de aquí en adelante TODO es automático."
key "awslocal lambda list-event-source-mappings --function-name tesis-dispatcher"
$AWSL lambda list-event-source-mappings --function-name tesis-dispatcher \
  --query 'EventSourceMappings[].[State,EventSourceArn]' --output table
pause

# ----------------------------------------------------------------------------
title "6. RESPUESTA AUTOMÁTICA — el dispatcher enruta el incidente"
cat <<'EOF'
  El dispatcher recibe el incidente desde SQS y aplica su tabla de enrutamiento:

     BRUTE_FORCE  →  [ notify-alert ,  block-ip ]

  - notify-alert : publica la alerta estructurada en SNS
  - block-ip     : APLICA EL BLOQUEO REAL en la Network ACL

  No invoco nada a mano: SQS dispara al dispatcher solo. Espero a que procese...
EOF
for i in $(seq 1 20); do
  HIT=$($AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
    --query "NetworkAcls[0].Entries[?Egress==\`false\` && RuleAction==\`deny\` && CidrBlock==\`${ATTACKER_IP}/32\`]" \
    --output text)
  [ -n "$HIT" ] && { say "${C_OK}Procesado automáticamente en ~$((i*2))s${C_NC}"; break; }
  sleep 2
done
pause

# ----------------------------------------------------------------------------
title "7. EL BLOQUEO REAL — estado de la Network ACL DESPUÉS"
key "awslocal ec2 describe-network-acls (entradas de ENTRADA)"
$AWSL ec2 describe-network-acls --network-acl-ids "$NACL" \
  --query 'NetworkAcls[0].Entries[?Egress==`false`].[RuleNumber,RuleAction,CidrBlock]' --output table
cat <<EOF

  ${ATTACKER_IP}/32 ahora tiene una regla DENY con número < 100.

  CLAVE TÉCNICA: una NACL evalúa por número, de menor a mayor, primera
  coincidencia gana. El DENY quedó por DEBAJO del ALLOW 100 → se evalúa
  primero → el tráfico del atacante se rechaza de verdad. Si estuviera por
  encima de 100, el ALLOW ganaría y el bloqueo sería cosmético.

  ▶ EL BLOQUEO REAL OCURRE EN:
    lambdas/block-ip/handler.py  →  _block_ip_on_network()
    →  ec2.create_network_acl_entry(RuleAction="deny", CidrBlock="${ATTACKER_IP}/32", ...)
EOF
pause

# ----------------------------------------------------------------------------
title "8. PISTA DE AUDITORÍA — evidencia de mitigación en S3"
say "El playbook registra QUÉ bloqueó y DÓNDE (prefijo responses/):"
key "awslocal s3 cp s3://${BUCKET}/responses/blocked-ips.json -"
$AWSL s3 cp s3://$BUCKET/responses/blocked-ips.json - 2>/dev/null | python3 -m json.tool
say ""
say "El campo ${C_KEY}enforcement${C_NC} prueba el punto exacto: network_acl_id + rule_number."
pause

# ----------------------------------------------------------------------------
title "9. TRAZABILIDAD — log de ejecución en CloudWatch"
LG="/aws/lambda/tesis-block-ip"
key "awslocal logs filter-log-events $LG --filter-pattern block-ip"
$AWSL logs filter-log-events --log-group-name "$LG" --filter-pattern "block-ip" \
  --query 'events[*].message' --output text 2>/dev/null | tr '\t' '\n' \
  | grep -i 'block-ip' | tail -3
[ $? -ne 0 ] && say "(sin coincidencias; el log puede tardar unos segundos en indexarse)"
pause

# ----------------------------------------------------------------------------
title "10. RESUMEN — qué demostré"
cat <<EOF
  ✔ El flujo es AUTOMÁTICO: SQS → dispatcher → playbooks (sin intervención)
  ✔ block-ip ejecuta CONTENCIÓN REAL: regla DENY en Network ACL (verificable)
  ✔ El punto de cumplimiento exacto: ec2.create_network_acl_entry() en
    lambdas/block-ip/handler.py
  ✔ 3 evidencias: describe-network-acls (antes/después) · responses/blocked-ips.json
    · log de CloudWatch
  ✔ Almacenamiento alineado con Componente A (prefijo responses/ = evidencia)
  ✔ IAM de mínimo privilegio para los permisos EC2 NACL

  Decisión de diseño a defender: añadí SQS + dispatcher + DLQ entre SNS y las
  Lambdas. Da durabilidad y reintentos (maxReceiveCount=3): si un playbook
  falla, el incidente no se pierde, va a la DLQ para análisis forense.
EOF
echo ""
echo -e "${C_OK}  === FIN DE LA DEMO ===${C_NC}"
