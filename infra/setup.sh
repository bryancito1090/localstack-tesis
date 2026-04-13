#!/usr/bin/env bash
# Bootstrap de recursos AWS locales para el Componente C — Automatización de Respuesta
# Requiere: LocalStack corriendo en localhost:4566 y awslocal instalado
set -euo pipefail

ENDPOINT="http://localhost:4566"
REGION="us-east-1"
ACCOUNT_ID="000000000000"  # LocalStack usa este account ID ficticio

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[--]${NC} $1"; }
fail() { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

echo "========================================"
echo "  Bootstrap Componente C — Tesis"
echo "  LocalStack: $ENDPOINT"
echo "========================================"

# Verificar que LocalStack está corriendo
curl -sf "$ENDPOINT/_localstack/health" > /dev/null || fail "LocalStack no está corriendo. Ejecuta: docker compose up -d"

# ── S3 ────────────────────────────────────────────────────────────────────────
warn "Creando bucket S3..."
awslocal s3 mb s3://tesis-security-logs --region $REGION 2>/dev/null || warn "Bucket ya existe"
# Crear prefijos vacíos (objetos vacíos actúan como carpetas)
for prefix in cloudtrail vpc-flow guardduty responses; do
    awslocal s3api put-object --bucket tesis-security-logs --key "$prefix/" > /dev/null
done
log "S3: s3://tesis-security-logs [cloudtrail/, vpc-flow/, guardduty/, responses/]"

# ── SNS ───────────────────────────────────────────────────────────────────────
warn "Creando tópicos SNS..."
ALERTS_ARN=$(awslocal sns create-topic --name tesis-security-alerts --query 'TopicArn' --output text)
TRIGGERS_ARN=$(awslocal sns create-topic --name tesis-lambda-triggers --query 'TopicArn' --output text)
log "SNS alerts:   $ALERTS_ARN"
log "SNS triggers: $TRIGGERS_ARN"

# ── SQS ───────────────────────────────────────────────────────────────────────
warn "Creando colas SQS..."
DLQ_URL=$(awslocal sqs create-queue --queue-name tesis-incident-queue-dlq --query 'QueueUrl' --output text)
DLQ_ARN="arn:aws:sqs:$REGION:$ACCOUNT_ID:tesis-incident-queue-dlq"

# Cola principal con DLQ configurada
QUEUE_URL=$(awslocal sqs create-queue \
    --queue-name tesis-incident-queue \
    --attributes "{\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"$DLQ_ARN\\\",\\\"maxReceiveCount\\\":\\\"3\\\"}\"}" \
    --query 'QueueUrl' --output text)
log "SQS queue: $QUEUE_URL"
log "SQS DLQ:   $DLQ_URL"

# ── CloudWatch Logs ───────────────────────────────────────────────────────────
warn "Creando grupos de logs CloudWatch..."
awslocal logs create-log-group --log-group-name /tesis/security-events 2>/dev/null || warn "Log group ya existe"
awslocal logs create-log-group --log-group-name /tesis/lambda-responses 2>/dev/null || warn "Log group ya existe"
log "CloudWatch: /tesis/security-events"
log "CloudWatch: /tesis/lambda-responses"

# ── IAM ───────────────────────────────────────────────────────────────────────
warn "Creando rol IAM para Lambdas de respuesta..."
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'
ROLE_ARN=$(awslocal iam create-role \
    --role-name tesis-lambda-response-role \
    --assume-role-policy-document "$TRUST_POLICY" \
    --query 'Role.Arn' --output text 2>/dev/null) || {
    ROLE_ARN=$(awslocal iam get-role --role-name tesis-lambda-response-role --query 'Role.Arn' --output text)
    warn "Rol ya existe"
}

# Adjuntar política de acceso a los recursos del proyecto
awslocal iam put-role-policy \
    --role-name tesis-lambda-response-role \
    --policy-name tesis-lambda-base-policy \
    --policy-document file://$(dirname "$0")/lambda-policies/base-policy.json 2>/dev/null || true
log "IAM Role: $ROLE_ARN"

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  Recursos creados exitosamente"
echo "========================================"
echo ""
awslocal s3 ls
echo ""
awslocal sns list-topics --query 'Topics[].TopicArn' --output table
echo ""
awslocal sqs list-queues --output table
