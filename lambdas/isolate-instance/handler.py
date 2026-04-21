"""
Playbook: isolate-instance
Registra la instancia comprometida en S3 (quarantine list) y notifica via SNS.
En producción real: desasociaría Security Groups y aplicaría política de cuarentena EC2.
En LocalStack Community (sin EC2 habilitado): persiste estado en S3.
"""
import json
import os
import boto3
from datetime import datetime, timezone

_ls_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", f"http://{_ls_host}:4566")
REGION   = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
BUCKET   = os.environ.get("S3_BUCKET", "tesis-security-logs")
SNS_ARN  = os.environ.get("SNS_ALERTS_ARN", "arn:aws:sns:us-east-1:000000000000:tesis-security-alerts")

s3  = boto3.client("s3",  endpoint_url=ENDPOINT, region_name=REGION)
sns = boto3.client("sns", endpoint_url=ENDPOINT, region_name=REGION)


def _load_quarantine() -> list:
    try:
        obj = s3.get_object(Bucket=BUCKET, Key="responses/quarantine-instances.json")
        return json.loads(obj["Body"].read())
    except Exception:
        return []


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "error", "detail": f"Payload inválido: {e}"}

        resource      = body.get("affectedResource", "ec2:instance/unknown")
        incident_type = body.get("incident_type", "UNKNOWN")
        severity      = body.get("severity", "HIGH")
        source_ip     = body.get("sourceIPAddress", "0.0.0.0")
        timestamp     = datetime.now(timezone.utc).isoformat()

        # 1. Registrar en lista de cuarentena en S3
        quarantine = _load_quarantine()
        entry = {
            "resource":       resource,
            "isolated_at":    timestamp,
            "reason":         incident_type,
            "severity":       severity,
            "sourceIPAddress": source_ip,
            "actions_applied": [
                "security_group_removed",   # simulado
                "deny_all_policy_applied",  # simulado
                "snapshot_triggered",       # simulado
            ],
        }
        quarantine.append(entry)
        s3.put_object(
            Bucket=BUCKET,
            Key="responses/quarantine-instances.json",
            Body=json.dumps(quarantine, indent=2).encode(),
            ContentType="application/json",
        )
        print(f"[isolate-instance] Recurso {resource} en cuarentena")

        # 2. Notificar al equipo
        result = {
            "playbook":  "isolate-instance",
            "action":    "instance_isolated",
            "resource":  resource,
            "status":    "QUARANTINED",
            "timestamp": timestamp,
        }
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"[{severity}] Instancia aislada: {resource}",
            Message=json.dumps(result, indent=2),
        )

        results.append({"status": "success", "action": "instance_isolated", "details": result})

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
