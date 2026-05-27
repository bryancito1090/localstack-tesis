"""
Playbook: isolate-instance
Contención ante acceso masivo no autorizado a datos (exfiltración u otro).

Punto de cumplimiento (enforcement point) según tipo de recurso:

  ▶ Recurso S3  (prefijo "s3:bucket/<nombre>")  — EXFILTRACIÓN
      s3.put_bucket_policy() con Deny GetObject+ListBucket para la IP atacante.
      Esa es la línea donde la exfiltración queda bloqueada a nivel de datos:
      cualquier intento de GetObject desde esa IP recibirá AccessDenied.

  ▶ Recurso EC2 (prefijo "ec2:instance/<id>")  — otro incidente
      Registra la instancia en la lista de cuarentena en S3 y simula las
      acciones de aislamiento de red (security group removal, policy, snapshot).
      En producción real reemplazaría el SG de la instancia por uno vacío.

El registro en S3 (responses/quarantine-instances.json) actúa como
PISTA DE AUDITORÍA / evidencia de mitigación, alineado con el prefijo
`responses/` del esquema del Componente A.
"""
import json
import os
import boto3
from datetime import datetime, timezone

_ls_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", f"http://{_ls_host}:4566")
REGION   = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
BUCKET   = os.environ.get("S3_BUCKET", "tesis-security-logs")
SNS_ARN  = os.environ.get("SNS_ALERTS_ARN",
           "arn:aws:sns:us-east-1:000000000000:tesis-security-alerts")

s3  = boto3.client("s3",  endpoint_url=ENDPOINT, region_name=REGION)
sns = boto3.client("sns", endpoint_url=ENDPOINT, region_name=REGION)


def _load_quarantine() -> list:
    try:
        obj = s3.get_object(Bucket=BUCKET, Key="responses/quarantine-instances.json")
        return json.loads(obj["Body"].read())
    except Exception:
        return []


def _block_s3_exfiltration(bucket_name: str, source_ip: str) -> dict:
    """
    PUNTO DE CUMPLIMIENTO REAL para exfiltración de datos S3.
    Aplica una política de bucket que deniega GetObject y ListBucket
    desde la IP atacante — la exfiltración queda cortada a nivel de datos.
    """
    cidr     = f"{source_ip}/32"
    stmt_id  = f"DenyExfiltrationIP-{source_ip.replace('.', '-')}"

    # Cargar política existente o inicializar con estructura vacía
    try:
        existing   = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
        statements = existing.get("Statement", [])
    except Exception:
        statements = []

    # Idempotencia: ¿ya existe el Deny para este CIDR?
    for stmt in statements:
        condition_ips = (stmt.get("Condition", {})
                             .get("IpAddress", {})
                             .get("aws:SourceIp", []))
        if stmt.get("Effect") == "Deny" and cidr in condition_ips:
            return {
                "enforced":       True,
                "already_present": True,
                "bucket":         bucket_name,
                "denied_ip":      cidr,
            }

    # ← ENFORCEMENT POINT: línea donde la exfiltración queda bloqueada
    statements.append({
        "Sid":       stmt_id,
        "Effect":    "Deny",
        "Principal": "*",
        "Action":    ["s3:GetObject", "s3:ListBucket"],
        "Resource":  [
            f"arn:aws:s3:::{bucket_name}",
            f"arn:aws:s3:::{bucket_name}/*",
        ],
        "Condition": {
            "IpAddress": {
                "aws:SourceIp": [cidr]
            }
        }
    })
    new_policy = {"Version": "2012-10-17", "Statement": statements}
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(new_policy))

    print(f"[isolate-instance] S3 bucket {bucket_name}: "
          f"Deny GetObject/ListBucket para {cidr} → exfiltración bloqueada")
    return {
        "enforced":        True,
        "already_present": False,
        "bucket":          bucket_name,
        "denied_ip":       cidr,
        "blocked_actions": ["s3:GetObject", "s3:ListBucket"],
    }


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

        actions_applied = []
        enforcement     = {}

        # ── Enforcement real según tipo de recurso ────────────────────────────
        if resource.startswith("s3:bucket/"):
            bucket_name = resource.replace("s3:bucket/", "")
            try:
                enforcement = _block_s3_exfiltration(bucket_name, source_ip)
                action      = "s3_exfiltration_blocked"
                actions_applied.extend([
                    f"s3_deny_policy_applied:{bucket_name}",
                    f"attacker_ip_blocked:{source_ip}/32",
                    "s3:GetObject_denied",
                    "s3:ListBucket_denied",
                ])
            except Exception as e:
                enforcement = {"enforced": False, "error": str(e)}
                action      = "s3_block_failed"
                print(f"[isolate-instance] ERROR bloqueando bucket {bucket_name}: {e}")

        else:
            # EC2 u otro recurso: registro en cuarentena + acciones simuladas
            action          = "instance_isolated"
            actions_applied = [
                "security_group_removed",   # En prod: reemplazar por SG vacío
                "deny_all_policy_applied",  # En prod: IAM policy de cuarentena
                "snapshot_triggered",       # En prod: EBS snapshot forense
            ]
            enforcement = {"enforced": True, "mode": "simulated"}

        # ── Auditoría: lista de cuarentena en S3 (prefijo responses/) ─────────
        quarantine = _load_quarantine()
        entry = {
            "resource":        resource,
            "isolated_at":     timestamp,
            "reason":          incident_type,
            "severity":        severity,
            "sourceIPAddress": source_ip,
            "actions_applied": actions_applied,
            "enforcement":     enforcement,
        }
        quarantine.append(entry)
        s3.put_object(
            Bucket=BUCKET,
            Key="responses/quarantine-instances.json",
            Body=json.dumps(quarantine, indent=2).encode(),
            ContentType="application/json",
        )
        print(f"[isolate-instance] Recurso {resource} registrado en cuarentena")

        # ── Notificar al equipo vía SNS ────────────────────────────────────────
        status = "QUARANTINED" if enforcement.get("enforced") else "QUARANTINE_FAILED"
        result = {
            "playbook":    "isolate-instance",
            "action":      action,
            "resource":    resource,
            "status":      status,
            "enforcement": enforcement,
            "timestamp":   timestamp,
        }
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"[{severity}] Recurso aislado: {resource}"[:100],
            Message=json.dumps(result, indent=2),
        )

        results.append({"status": "success", "action": action, "details": result})

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
