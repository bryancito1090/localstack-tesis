"""
Playbook: revoke-credentials
Revoca (desactiva) las access keys de un usuario IAM comprometido
y adjunta una política de denegación explícita para bloqueo inmediato.

Punto de cumplimiento (enforcement point):
  1. iam.update_access_key(Status="Inactive")  ← línea exacta donde las
     credenciales del atacante quedan invalidadas. Cada key existente
     del usuario pasa de Active → Inactive en IAM.
  2. iam.put_user_policy("EmergencyDenyAll")   ← capa extra: aunque haya
     keys no listadas o futuros tokens STS, la política Deny-All las bloquea.

El registro en S3 (responses/revoked-credentials.json) actúa como
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

iam = boto3.client("iam", endpoint_url=ENDPOINT, region_name=REGION)
s3  = boto3.client("s3",  endpoint_url=ENDPOINT, region_name=REGION)
sns = boto3.client("sns", endpoint_url=ENDPOINT, region_name=REGION)

DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect":   "Deny",
        "Action":   "*",
        "Resource": "*"
    }]
})


def _load_revoke_log() -> list:
    try:
        obj = s3.get_object(Bucket=BUCKET, Key="responses/revoked-credentials.json")
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

        username      = body.get("affectedResource", "").replace("iam:user/", "")
        incident_type = body.get("incident_type", "UNKNOWN")
        severity      = body.get("severity", "CRITICAL")
        source_ip     = body.get("sourceIPAddress", "0.0.0.0")
        timestamp     = datetime.now(timezone.utc).isoformat()

        if not username:
            return {"status": "error", "detail": "affectedResource no contiene usuario IAM"}

        actions_taken = []
        keys_revoked  = []
        enforcement   = {}

        # ── 1. CUMPLIMIENTO REAL: desactivar todas las access keys ───────────
        #       ENFORCEMENT POINT: update_access_key(Status="Inactive")
        try:
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                kid = key["AccessKeyId"]
                if key.get("Status") == "Active":
                    # ← línea exacta donde la credencial queda revocada
                    iam.update_access_key(
                        UserName=username,
                        AccessKeyId=kid,
                        Status="Inactive"
                    )
                    keys_revoked.append(kid)
                    actions_taken.append(f"AccessKey desactivada: {kid}")
                    print(f"[revoke-credentials] Desactivada key {kid} de {username}")
                else:
                    actions_taken.append(f"AccessKey ya inactiva: {kid}")
            enforcement["keys_found"]       = len(keys)
            enforcement["keys_deactivated"] = len(keys_revoked)
            enforcement["key_ids"]          = keys_revoked
        except Exception as e:
            enforcement["keys_error"] = str(e)
            print(f"[revoke-credentials] No se pudieron listar/desactivar keys de "
                  f"{username}: {e}")

        # ── 2. CUMPLIMIENTO ADICIONAL: política DenyAll (bloqueo total) ──────
        try:
            iam.put_user_policy(
                UserName=username,
                PolicyName="EmergencyDenyAll",
                PolicyDocument=DENY_ALL_POLICY
            )
            actions_taken.append("Política EmergencyDenyAll adjuntada")
            enforcement["deny_all_applied"] = True
            print(f"[revoke-credentials] EmergencyDenyAll aplicado a {username}")
        except Exception as e:
            enforcement["deny_all_error"] = str(e)
            enforcement["deny_all_applied"] = False
            print(f"[revoke-credentials] Error aplicando DenyAll a {username}: {e}")

        # ── 3. AUDITORÍA: evidencia de mitigación en S3 (prefijo responses/) ─
        revoke_log = _load_revoke_log()
        log_entry  = {
            "username":        username,
            "revoked_at":      timestamp,
            "reason":          incident_type,
            "severity":        severity,
            "sourceIPAddress": source_ip,
            "enforcement":     enforcement,
            "actions_taken":   actions_taken,
        }
        if not any(e["username"] == username for e in revoke_log):
            revoke_log.append(log_entry)
        s3.put_object(
            Bucket=BUCKET,
            Key="responses/revoked-credentials.json",
            Body=json.dumps(revoke_log, indent=2).encode(),
            ContentType="application/json",
        )

        # ── 4. Notificar al equipo vía SNS ───────────────────────────────────
        result = {
            "playbook":    "revoke-credentials",
            "username":    username,
            "actions":     actions_taken,
            "status":      "CONTAINED",
            "enforcement": enforcement,
            "timestamp":   timestamp,
        }
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"[{severity}] Credenciales revocadas: {username}"[:100],
            Message=json.dumps(result, indent=2),
        )

        results.append({
            "status": "success",
            "action": "credentials_revoked",
            "details": result,
        })

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
