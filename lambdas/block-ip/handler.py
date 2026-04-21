"""
Playbook: block-ip
Registra la IP atacante en S3 (blocklist) y notifica al equipo via SNS.
En producción real: actualizaría un WAF IP Set o Security Group.
En LocalStack Community (sin WAF/EC2): persiste en S3 como fuente de verdad.
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


def _load_blocklist() -> list:
    try:
        obj = s3.get_object(Bucket=BUCKET, Key="responses/blocked-ips.json")
        return json.loads(obj["Body"].read())
    except s3.exceptions.NoSuchKey:
        return []
    except Exception:
        return []


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "error", "detail": f"Payload inválido: {e}"}

        ip            = body.get("sourceIPAddress", "0.0.0.0")
        incident_type = body.get("incident_type", "UNKNOWN")
        severity      = body.get("severity", "MEDIUM")
        timestamp     = datetime.now(timezone.utc).isoformat()

        # 1. Actualizar blocklist en S3
        blocklist = _load_blocklist()
        entry = {
            "ip":            ip,
            "blocked_at":    timestamp,
            "reason":        incident_type,
            "severity":      severity,
            "affectedResource": body.get("affectedResource", ""),
        }
        if not any(e["ip"] == ip for e in blocklist):
            blocklist.append(entry)
            s3.put_object(
                Bucket=BUCKET,
                Key="responses/blocked-ips.json",
                Body=json.dumps(blocklist, indent=2).encode(),
                ContentType="application/json",
            )
            action = "ip_blocked"
            print(f"[block-ip] IP {ip} añadida al blocklist ({len(blocklist)} IPs bloqueadas)")
        else:
            action = "ip_already_blocked"
            print(f"[block-ip] IP {ip} ya estaba en el blocklist")

        # 2. Notificar al equipo
        result = {
            "playbook":  "block-ip",
            "action":    action,
            "ip":        ip,
            "status":    "BLOCKED",
            "timestamp": timestamp,
        }
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"[{severity}] IP bloqueada: {ip}",
            Message=json.dumps(result, indent=2),
        )

        results.append({"status": "success", "action": action, "details": result})

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
