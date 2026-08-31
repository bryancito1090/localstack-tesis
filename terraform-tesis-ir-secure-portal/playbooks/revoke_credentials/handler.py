"""
Playbook: revoke-credentials
Revoca (desactiva) las access keys de un usuario IAM comprometido
y adjunta una política de denegación explícita para bloqueo inmediato.

Punto de cumplimiento (enforcement point):
  1. iam.update_access_key(Status="Inactive")  ← key del atacante revocada
  2. iam.put_user_policy("EmergencyDenyAll")   ← bloqueo total DenyAll
"""
import json
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import boto3

s3  = boto3.client("s3")
sns = boto3.client("sns")
iam = boto3.client("iam")

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
SNS_ARN         = os.environ["SNS_ALERTS_ARN"]
RESPONSE_PREFIX = os.environ.get("RESPONSE_PREFIX", "responses/revoke-credentials")
EC_TZ           = ZoneInfo("America/Guayaquil")

DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect":   "Deny",
        "Action":   "*",
        "Resource": "*"
    }]
})

def now_ecuador() -> str:
    return datetime.now(EC_TZ).isoformat()

def load_revoke_log() -> list:
    try:
        obj = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=f"{RESPONSE_PREFIX}/revoked-credentials.json")
        return json.loads(obj["Body"].read())
    except Exception:
        return []

def save_revoke_log(revoke_log: list) -> None:
    s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=f"{RESPONSE_PREFIX}/revoked-credentials.json",
        Body=json.dumps(revoke_log, indent=2, ensure_ascii=False).encode("utf-8"),
        ContentType="application/json",
    )

def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        try:
            body = json.loads(record.get("body", "{}"))
        except json.JSONDecodeError as exc:
            results.append({"status": "skipped", "reason": f"invalid_json: {exc}"})
            continue

        incident_type = body.get("incident_type", "UNKNOWN")
        # Procesar incidentes de escalada o leak de credenciales
        if incident_type not in {"PRIVILEGE_ESCALATION", "CREDENTIAL_LEAK"}:
            print(f"[revoke-credentials] Tipo {incident_type} no requiere revocacion. Omitiendo.")
            results.append({"status": "skipped", "reason": f"not_in_revoke_list:{incident_type}"})
            continue

        affected_resource = body.get("affectedResource", "")
        # Extraer el usuario del formato "iam:user/nombre"
        username = affected_resource.replace("iam:user/", "") if affected_resource.startswith("iam:user/") else affected_resource
        source_ip = body.get("sourceIPAddress", "0.0.0.0")
        timestamp = now_ecuador()
        incident_id = body.get("incident_id", "")

        if not username or username == "unknown":
            print(f"[revoke-credentials] affectedResource invalido: {affected_resource}. Omitiendo.")
            results.append({"status": "skipped", "reason": f"invalid_affected_resource:{affected_resource}"})
            continue

        actions_taken = []
        keys_revoked  = []
        enforcement   = {}

        # ── 1. CUMPLIMIENTO REAL: desactivar todas las access keys ───────────
        try:
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                kid = key["AccessKeyId"]
                if key.get("Status") == "Active":
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
            print(f"[revoke-credentials] Error desactivando keys de {username}: {e}")

        # ── 2. CUMPLIMIENTO ADICIONAL: política DenyAll (bloqueo total) ──────
        try:
            iam.put_user_policy(
                UserName=username,
                PolicyName="EmergencyDenyAll",
                PolicyDocument=DENY_ALL_POLICY
            )
            actions_taken.append("Politica EmergencyDenyAll adjuntada")
            enforcement["deny_all_applied"] = True
            print(f"[revoke-credentials] EmergencyDenyAll aplicado a {username}")
        except Exception as e:
            enforcement["deny_all_error"] = str(e)
            enforcement["deny_all_applied"] = False
            print(f"[revoke-credentials] Error aplicando DenyAll a {username}: {e}")

        # Status final
        status = "CONTAINED" if (len(keys_revoked) > 0 or enforcement.get("deny_all_applied")) else "NO_ACTION_TAKEN"

        # ── 3. Construir registro de evidencia ───────────────────────────────
        entry = {
            "playbook":        "revoke-credentials",
            "incident_type":   incident_type,
            "severity":        body.get("severity", "CRITICAL"),
            "sourceIPAddress": source_ip,
            "affectedResource": affected_resource,
            "status":          status,
            "enforcement":     enforcement,
            "actions_taken":   actions_taken,
            "timestamp":       timestamp,
            "timezone":        "America/Guayaquil",
            "incident_id":     incident_id,
        }

        # ── 4. Actualizar lista acumulativa ───────────────────────────────────
        revoke_log = load_revoke_log()
        if not any(item.get("username") == username for item in revoke_log):
            revoke_log.append({
                "username":        username,
                "revoked_at":      timestamp,
                "reason":          incident_type,
                "severity":        body.get("severity", "CRITICAL"),
                "sourceIPAddress": source_ip,
                "enforcement":     enforcement,
                "actions_taken":   actions_taken,
            })
            save_revoke_log(revoke_log)

        # ── 5. Guardar evidencia individual por incidente ─────────────────────
        key = f"{RESPONSE_PREFIX}/{incident_id or uuid.uuid4().hex}.json"
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=key,
            Body=json.dumps(entry, indent=2, ensure_ascii=False).encode("utf-8"),
            ContentType="application/json",
        )

        # ── 6. Notificar al equipo vía SNS ───────────────────────────────────
        subject = f"[{entry['severity']}] Mitigacion: Credenciales {username} {status}"
        mitigation_report = f"""
[MITIGACION DE SEGURIDAD AWS] - ACCION: {status}
==================================================
Playbook          : revoke-credentials
Tipo de Incidente : {incident_type}
ID de Incidente   : {incident_id}
Estado            : {status}
--------------------------------------------------
Usuario IAM       : {username}
Acciones Tomadas  : {', '.join(actions_taken)}
DenyAll Aplicado  : {'SI' if enforcement.get('deny_all_applied') else 'NO'}
--------------------------------------------------
Hora Mitigacion   : {timestamp}
Evidencia S3      : {key}
==================================================
""".strip()
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=subject[:100],
            Message=mitigation_report,
        )

        print(f"[revoke-credentials] {incident_type} → {status} para {username}. evidence={key}")
        results.append({
            "status":       "success",
            "action":       status,
            "evidence_key": key,
            "details":      enforcement,
        })

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": now_ecuador(),
    }
