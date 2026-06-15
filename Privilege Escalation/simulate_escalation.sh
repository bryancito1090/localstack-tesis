#!/usr/bin/env bash
# ============================================================================
#  SIMULACIÓN DE ATAQUE — Incidente 3: Escalada de Privilegios IAM
#  Tesis: Detección y respuesta ante incidentes en AWS (LocalStack / Real AWS)
# ============================================================================
set -euo pipefail

# Colores para salida en consola
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'
C_NC='\033[0m'

echo -e "${C_CYAN}======================================================================${C_NC}"
echo -e "${C_CYAN}  Iniciando Simulación: Escalada de Privilegios (PRIVILEGE_ESCALATION) ${C_NC}"
echo -e "${C_CYAN}======================================================================${C_NC}"

# Detectar si usar LocalStack o AWS Real
AWS_CMD="aws"
REGION="ca-central-1"
ENDPOINT_FLAG=""

if curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1; then
    echo -e "${C_GREEN}[*] LocalStack detectado en localhost:4566.${C_NC}"
    if command -v awslocal >/dev/null 2>&1; then
        AWS_CMD="awslocal"
    else
        AWS_CMD="aws"
        ENDPOINT_FLAG="--endpoint-url http://localhost:4566"
    fi
else
    echo -e "${C_YELLOW}[!] LocalStack no detectado. Utilizando AWS CLI global (ca-central-1).${C_NC}"
fi

# Validar identidad
echo -e "\n${C_CYAN}[Paso 1] Validando identidad y conexión AWS...${C_NC}"
if ! $AWS_CMD sts get-caller-identity $ENDPOINT_FLAG >/dev/null 2>&1; then
    echo -e "${C_RED}[ERROR] No se pudo verificar la identidad. ¿Están cargadas tus credenciales?${C_NC}"
    echo -e "Ejecuta: export AWS_ACCESS_KEY_ID=tu_key && export AWS_SECRET_ACCESS_KEY=tu_secret"
    exit 1
fi
$AWS_CMD sts get-caller-identity $ENDPOINT_FLAG --output table

# Inventario de recursos desplegados
echo -e "\n${C_CYAN}[Paso 2] Mostrando recursos del sistema en AWS...${C_NC}"
echo -e "${C_GREEN}1. Tabla DynamoDB de Incidentes:${C_NC}"
DYNAMO_TABLE=$($AWS_CMD dynamodb list-tables $ENDPOINT_FLAG --query "TableNames[?contains(@, 'incidents')]" --output text || echo "tesis-ir_incidents")
echo -e "   -> Tabla detectada: $DYNAMO_TABLE"

echo -e "${C_GREEN}2. Buckets S3 de Evidencia/Logs:${C_NC}"
EVIDENCE_BUCKET=$($AWS_CMD s3 ls $ENDPOINT_FLAG | awk '{print $3}' | grep -E 'evidence|logs' | head -n1 || echo "tesis-ir-evidence")
echo -e "   -> Bucket detectado: $EVIDENCE_BUCKET"

echo -e "${C_GREEN}3. Colas SQS activas:${C_NC}"
QUEUE_URL=$($AWS_CMD sqs list-queues $ENDPOINT_FLAG --query "QueueUrls[?contains(@, 'incident')]" --output text 2>/dev/null | awk '{print $1}' || echo "http://localhost:4566/000000000000/tesis-ir-incident-queue")
echo -e "   -> Cola detectada: $QUEUE_URL"

# Simulación del ataque
USER_NAME="tesis-ir-temp-escalation-test"
POLICY_ARN="arn:aws:iam::aws:policy/ReadOnlyAccess"

echo -e "\n${C_CYAN}[Paso 3] Ejecutando simulación de ataque (IAM)...${C_NC}"
echo -e "Creando usuario temporal: ${C_YELLOW}$USER_NAME${C_NC}"
$AWS_CMD iam create-user --user-name "$USER_NAME" $ENDPOINT_FLAG --output json

# Crear una Access Key activa para este usuario para poder demostrar la revocación real
echo -e "Generando Access Key activa para el usuario (blanco de mitigación)..."
$AWS_CMD iam create-access-key --user-name "$USER_NAME" $ENDPOINT_FLAG --output json

echo -e "Adjuntando política: ${C_YELLOW}$POLICY_ARN${C_NC}"
$AWS_CMD iam attach-user-policy --user-name "$USER_NAME" --policy-arn "$POLICY_ARN" $ENDPOINT_FLAG

echo -e "${C_GREEN}[✓] Ataque simulado con éxito.${C_NC}"
echo -e "\n${C_YELLOW}Se han ejecutado los eventos 'CreateUser' y 'AttachUserPolicy' en IAM.${C_NC}"
echo -e "Estos eventos serán detectados por el CloudTrail y enviados al detector Lambda."
echo -e "El playbook de mitigación automática 'revoke-credentials' se disparará en breve."

# Esperar a que la Lambda procese el incidente y realice la revocación
echo -e "\n${C_CYAN}[Paso 4] Esperando 10 segundos para verificar la mitigación automática...${C_NC}"
sleep 10

echo -e "\n${C_CYAN}[Paso 5] Verificando la mitigación (Puntos de Cumplimiento / Enforcement):${C_NC}"

# 1. Verificar estado de las Access Keys del usuario
echo -e "${C_GREEN}1. Verificando estado de las Access Keys (deben pasar a INACTIVE):${C_NC}"
$AWS_CMD iam list-access-keys --user-name "$USER_NAME" $ENDPOINT_FLAG --output table || echo -e "${C_RED}Error al listar keys o el usuario no existe.${C_NC}"

# 2. Verificar si se aplicó EmergencyDenyAll
echo -e "${C_GREEN}2. Verificando política de contención inline 'EmergencyDenyAll':${C_NC}"
$AWS_CMD iam get-user-policy --user-name "$USER_NAME" --policy-name "EmergencyDenyAll" $ENDPOINT_FLAG --output json || echo -e "${C_RED}La política EmergencyDenyAll aún no ha sido aplicada.${C_NC}"

# 3. Mostrar log de auditoría del playbook en S3
echo -e "${C_GREEN}3. Log de auditoría de revocación registrado en S3:${C_NC}"
$AWS_CMD s3 cp "s3://$EVIDENCE_BUCKET/responses/revoke-credentials/revoked-credentials.json" - $ENDPOINT_FLAG 2>/dev/null || echo -e "${C_YELLOW}Log en S3 aún no escrito (o tarda en propagar). Consulta de nuevo en un minuto.${C_NC}"

# 4. Mostrar registro de incidentes en DynamoDB
echo -e "${C_GREEN}4. Registro del incidente en DynamoDB:${C_NC}"
$AWS_CMD dynamodb scan --table-name "$DYNAMO_TABLE" $ENDPOINT_FLAG --output table

# Preguntar para limpiar o salir
echo -e "\n${C_CYAN}======================================================================${C_NC}"
read -rp "Presiona [ENTER] para limpiar el usuario temporal y las políticas de la simulación..."
echo -e "${C_CYAN}======================================================================${C_NC}"

echo -e "\n${C_CYAN}[Paso 6] Limpiando el entorno...${C_NC}"
echo -e "Removiendo política EmergencyDenyAll..."
$AWS_CMD iam delete-user-policy --user-name "$USER_NAME" --policy-name "EmergencyDenyAll" $ENDPOINT_FLAG || true

echo -e "Removiendo política ReadOnlyAccess..."
$AWS_CMD iam detach-user-policy --user-name "$USER_NAME" --policy-arn "$POLICY_ARN" $ENDPOINT_FLAG || true

echo -e "Eliminando Access Keys del usuario de prueba..."
KEYS=$($AWS_CMD iam list-access-keys --user-name "$USER_NAME" $ENDPOINT_FLAG --query "AccessKeyMetadata[].AccessKeyId" --output text 2>/dev/null || echo "")
for kid in $KEYS; do
    $AWS_CMD iam delete-access-key --user-name "$USER_NAME" --access-key-id "$kid" $ENDPOINT_FLAG || true
done

echo -e "Eliminando usuario temporal..."
$AWS_CMD iam delete-user --user-name "$USER_NAME" $ENDPOINT_FLAG || true

echo -e "${C_GREEN}[✓] Limpieza completada. El entorno está restaurado.${C_NC}"
