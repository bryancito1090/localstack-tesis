"""
Inyector de logs simulados hacia LocalStack.
Genera eventos con cloudtrail_gen.py y los sube a S3 + SQS para
activar el flujo completo del Componente C.
"""
import json
import sys
import os
import uuid
from datetime import datetime, timezone

import boto3
from cloudtrail_gen import GENERATORS

ENDPOINT  = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
REGION    = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
BUCKET    = os.environ.get("S3_BUCKET", "tesis-security-logs")
QUEUE     = os.environ.get("SQS_QUEUE", "tesis-incident-queue")
QUEUE_URL = f"{ENDPOINT}/000000000000/{QUEUE}"

s3  = boto3.client("s3",  endpoint_url=ENDPOINT, region_name=REGION)
sqs = boto3.client("sqs", endpoint_url=ENDPOINT, region_name=REGION)

SEVERITY_MAP = {
    "brute-force":          "HIGH",
    "privilege-escalation": "CRITICAL",
    "credential-leak":      "CRITICAL",
    "exfiltration":         "HIGH",
    "port-scan":            "MEDIUM",
}


def inject(incident_type: str):
    gen = GENERATORS.get(incident_type)
    if not gen:
        print(f"Tipo desconocido: {incident_type}. Disponibles: {', '.join(GENERATORS)}")
        sys.exit(1)

    events = gen()
    print(f"[inject] Generados {len(events)} eventos de tipo '{incident_type}'")

    # 1. Subir a S3 como archivo JSON (simula CloudTrail → S3)
    timestamp = datetime.now(timezone.utc).strftime("%Y/%m/%d/%H%M%S")
    s3_key = f"cloudtrail/{timestamp}/{incident_type}-{uuid.uuid4().hex[:8]}.json"
    s3.put_object(
        Bucket=BUCKET,
        Key=s3_key,
        Body=json.dumps({"Records": events}, indent=2).encode(),
        ContentType="application/json"
    )
    print(f"[inject] Subido a s3://{BUCKET}/{s3_key}")

    # 2. Detectar el evento más relevante para el payload de respuesta
    first = events[0]
    payload = {
        "incident_type":    incident_type.replace("-", "_").upper(),
        "severity":         SEVERITY_MAP.get(incident_type, "MEDIUM"),
        "sourceIPAddress":  first.get("sourceIPAddress", "0.0.0.0"),
        "affectedResource": f"iam:user/{first['userIdentity']['userName']}",
        "s3_log_key":       s3_key,
        "event_count":      len(events),
        "timestamp":        first.get("eventTime", datetime.now(timezone.utc).isoformat()),
    }

    # 3. Publicar en SQS para triggear Lambda de respuesta
    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(payload),
        MessageAttributes={
            "incident_type": {
                "StringValue": incident_type,
                "DataType":    "String"
            }
        }
    )
    print(f"[inject] Mensaje SQS enviado a {QUEUE}")
    print(f"[inject] Payload:\n{json.dumps(payload, indent=2)}")
    return payload


if __name__ == "__main__":
    incident = sys.argv[1] if len(sys.argv) > 1 else "brute-force"
    inject(incident)
