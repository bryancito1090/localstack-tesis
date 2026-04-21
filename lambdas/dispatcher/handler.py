"""
Playbook: dispatcher
Lambda central de enrutamiento. Recibe eventos de SQS y decide qué
playbooks ejecutar según el tipo de incidente.

Tabla de enrutamiento:
  BRUTE_FORCE          → notify-alert + block-ip
  CREDENTIAL_LEAK      → notify-alert + revoke-credentials
  PRIVILEGE_ESCALATION → notify-alert + revoke-credentials
  EXFILTRATION         → notify-alert + isolate-instance
  PORT_SCAN            → notify-alert + block-ip
"""
import json
import os
import boto3
from datetime import datetime, timezone

_ls_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", f"http://{_ls_host}:4566")
REGION   = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

lmb = boto3.client("lambda", endpoint_url=ENDPOINT, region_name=REGION)

ROUTING_TABLE = {
    "BRUTE_FORCE":          ["tesis-notify-alert", "tesis-block-ip"],
    "CREDENTIAL_LEAK":      ["tesis-notify-alert", "tesis-revoke-credentials"],
    "PRIVILEGE_ESCALATION": ["tesis-notify-alert", "tesis-revoke-credentials"],
    "EXFILTRATION":         ["tesis-notify-alert", "tesis-isolate-instance"],
    "PORT_SCAN":            ["tesis-notify-alert", "tesis-block-ip"],
}


def _invoke_playbook(function_name: str, payload: dict) -> dict:
    """Invoca un playbook Lambda con el mismo formato de evento SQS."""
    sqs_event = {
        "Records": [{
            "messageId":      "dispatcher-fwd",
            "receiptHandle":  "dispatcher-fwd",
            "body":           json.dumps(payload),
            "eventSource":    "aws:sqs",
            "eventSourceARN": "arn:aws:sqs:us-east-1:000000000000:tesis-incident-queue",
            "awsRegion":      REGION,
        }]
    }
    response = lmb.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(sqs_event).encode(),
    )
    result_payload = json.loads(response["Payload"].read())
    status = "success" if response.get("FunctionError") is None else "error"
    print(f"[dispatcher] {function_name} → {status}")
    return {"function": function_name, "status": status, "response": result_payload}


def lambda_handler(event, context):
    dispatch_results = []

    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "error", "detail": f"Payload inválido: {e}"}

        incident_type = body.get("incident_type", "UNKNOWN")
        severity      = body.get("severity", "MEDIUM")
        playbooks     = ROUTING_TABLE.get(incident_type, ["tesis-notify-alert"])

        print(f"[dispatcher] Incidente: {incident_type} ({severity}) → playbooks: {playbooks}")

        invocations = []
        for fn in playbooks:
            result = _invoke_playbook(fn, body)
            invocations.append(result)

        dispatch_results.append({
            "incident_type": incident_type,
            "severity":      severity,
            "playbooks_run": playbooks,
            "invocations":   invocations,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        })

    return {
        "status":    "success",
        "processed": len(dispatch_results),
        "results":   dispatch_results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
