"""
Playbook: notify-alert
Recibe un evento de incidente desde SQS y publica una notificación
estructurada al tópico SNS de alertas.
"""
import json
import os
import boto3
from datetime import datetime, timezone

# LOCALSTACK_HOSTNAME es inyectada por LocalStack en contenedores Lambda (Docker executor)
# Permite que la Lambda alcance LocalStack sin hardcodear IPs que cambian entre reinicios
_ls_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", f"http://{_ls_host}:4566")
REGION   = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
SNS_ARN  = os.environ.get("SNS_ALERTS_ARN", "arn:aws:sns:us-east-1:000000000000:tesis-security-alerts")

sns = boto3.client("sns", endpoint_url=ENDPOINT, region_name=REGION)


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        # Parsear mensaje SQS
        try:
            body = json.loads(record["body"])
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "error", "detail": f"Payload inválido: {e}"}

        incident_type = body.get("incident_type", "UNKNOWN")
        severity      = body.get("severity", "MEDIUM")
        source_ip     = body.get("sourceIPAddress", "0.0.0.0")
        resource      = body.get("affectedResource", "unknown")
        timestamp     = body.get("timestamp", datetime.now(timezone.utc).isoformat())

        # Construir mensaje de alerta
        alert = {
            "alert_type":         "SECURITY_INCIDENT",
            "incident_type":      incident_type,
            "severity":           severity,
            "sourceIPAddress":    source_ip,
            "affectedResource":   resource,
            "detectedAt":         timestamp,
            "respondedAt":        datetime.now(timezone.utc).isoformat(),
            "playbook":           "notify-alert",
            "status":             "NOTIFIED"
        }

        subject = f"[{severity}] Incidente detectado: {incident_type}"
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=subject[:100],  # SNS limita el subject a 100 chars
            Message=json.dumps(alert, indent=2)
        )

        print(f"[notify-alert] Alerta publicada: {incident_type} desde {source_ip}")
        results.append({"status": "success", "action": "sns_published", "details": alert})

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
