"""
Playbook: revoke-credentials
Revoca (desactiva) las access keys de un usuario IAM comprometido,
adjunta una politica de denegacion explicita (DenyAll) para bloqueo inmediato,
registra evidencia en S3 y notifica via HTML Card (SES) y SNS (Telegram).
"""
import html
import json
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import boto3

s3  = boto3.client("s3")
sns = boto3.client("sns")
iam = boto3.client("iam")
ses = boto3.client("ses")

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
SNS_ARN         = os.environ["SNS_ALERTS_ARN"]
RESPONSE_PREFIX = os.environ.get("RESPONSE_PREFIX", "responses/revoke-credentials")
ALERT_EMAIL      = os.environ.get("ALERT_EMAIL", "")
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL") or ALERT_EMAIL
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


def format_dt(dt_str: str) -> str:
    if not dt_str or dt_str == "N/A":
        return "N/A"
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=EC_TZ)
        else:
            dt = dt.astimezone(EC_TZ)
        return dt.strftime("%Y-%m-%d %H:%M:%S (America/Guayaquil)")
    except Exception:
        return dt_str


def generate_html_card(title: str, subtitle: str, badge_text: str, badge_type: str, sections: dict, callout_label: str, callout_text: str, footer_text: str) -> str:
    color_map = {
        "CRITICAL":  {"header": "#B71C1C", "badge_bg": "#FFEBEE", "badge_text": "#B71C1C", "border": "#EF5350"},
        "HIGH":      {"header": "#E65100", "badge_bg": "#FFF3E0", "badge_text": "#E65100", "border": "#FF9800"},
        "MEDIUM":    {"header": "#F57F17", "badge_bg": "#FFFDE7", "badge_text": "#F57F17", "border": "#FFEE58"},
        "LOW":       {"header": "#0277BD", "badge_bg": "#E1F5FE", "badge_text": "#0277BD", "border": "#29B6F6"},
        "BLOCKED":   {"header": "#B71C1C", "badge_bg": "#FFEBEE", "badge_text": "#B71C1C", "border": "#EF5350"},
        "CONTAINED": {"header": "#0D47A1", "badge_bg": "#E3F2FD", "badge_text": "#0D47A1", "border": "#42A5F5"},
    }
    c = color_map.get(badge_type.upper(), {"header": "#1E293B", "badge_bg": "#F1F5F9", "badge_text": "#1E293B", "border": "#94A3B8"})

    sections_html = ""
    for sec_title, kvs in sections.items():
        rows = ""
        for k, v in kvs:
            rows += f"""
            <tr>
              <td style="padding: 7px 12px; color: #64748B; font-size: 13px; font-weight: 600; border-bottom: 1px solid #F1F5F9; width: 36%;">{html.escape(str(k))}</td>
              <td style="padding: 7px 12px; color: #0F172A; font-size: 13px; font-family: SFMono-Regular, Consolas, monospace; border-bottom: 1px solid #F1F5F9; word-break: break-all;">{html.escape(str(v))}</td>
            </tr>"""
        sections_html += f"""
        <div style="margin-top: 16px;">
          <div style="color: #334155; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #E2E8F0; padding-bottom: 4px; margin-bottom: 8px;">{html.escape(sec_title)}</div>
          <table style="width: 100%; border-collapse: collapse;">
            {rows}
          </table>
        </div>"""

    callout_html = ""
    if callout_text:
        callout_html = f"""
        <div style="margin-top: 16px;">
          <div style="color: #334155; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #E2E8F0; padding-bottom: 4px; margin-bottom: 8px;">{html.escape(callout_label)}</div>
          <div style="background-color: #F8FAFC; border-left: 4px solid {c['border']}; padding: 12px 16px; border-radius: 0 4px 4px 0; color: #1E293B; font-size: 13px; line-height: 1.5;">
            {html.escape(callout_text)}
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin: 0; padding: 20px; background-color: #F4F6F8; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <div style="max-width: 620px; margin: 0 auto; background-color: #FFFFFF; border-radius: 8px; overflow: hidden; border: 1px solid #E2E8F0; box-shadow: 0 2px 8px rgba(0,0,0,0.06);">
    <div style="background-color: {c['header']}; padding: 18px 24px; color: #FFFFFF;">
      <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.85; margin-bottom: 4px;">{html.escape(subtitle)}</div>
      <div style="font-size: 18px; font-weight: 700; letter-spacing: 0.2px;">{html.escape(title)}</div>
    </div>
    <div style="padding: 20px 24px;">
      <div style="display: inline-block; padding: 4px 12px; border-radius: 4px; background-color: {c['badge_bg']}; color: {c['badge_text']}; font-weight: 700; font-size: 12px; border: 1px solid {c['border']}; text-transform: uppercase; margin-bottom: 8px;">
        {html.escape(badge_text)}
      </div>
      {sections_html}
      {callout_html}
    </div>
    <div style="background-color: #F1F5F9; padding: 12px 24px; border-top: 1px solid #E2E8F0; color: #64748B; font-size: 11px; text-align: center;">
      {html.escape(footer_text)}
    </div>
  </div>
</body>
</html>"""


def format_mitigation_html(entry: dict, username: str, actions_taken: list, enforcement: dict, key: str) -> str:
    status = entry.get("status", "CONTAINED")
    incident_type = entry.get("incident_type", "INCIDENT")
    timestamp = format_dt(entry.get("timestamp", ""))
    actions_str = ", ".join(actions_taken) if actions_taken else "Ninguna acción registrada"
    deny_status = "EmergencyDenyAll adjuntada (Bloqueo Total)" if enforcement.get("deny_all_applied") else "No aplicada"

    return generate_html_card(
        title="[MITIGACION DE SEGURIDAD AWS]",
        subtitle="IAM Automated Credential Revocation",
        badge_text=f"ACCION: {status}",
        badge_type="CONTAINED" if status == "CONTAINED" else "CRITICAL",
        sections={
            "INFORMACION GENERAL": [
                ("Estado", status),
                ("Playbook", "revoke-credentials"),
                ("Tipo de Incidente", incident_type),
                ("ID de Incidente", entry.get("incident_id", "N/A")),
            ],
            "CONTENCION APLICADA": [
                ("Usuario IAM", username),
                ("Acciones Tomadas", actions_str),
                ("Politica DenyAll", deny_status),
                ("Enforcement", "Desactivacion inmediata de credenciales y revocacion de permisos"),
            ],
            "TRAZABILIDAD": [
                ("Hora Mitigacion", timestamp),
                ("Evidencia S3", key),
            ]
        },
        callout_label="DETALLES DE MITIGACION",
        callout_text=f"Credenciales de acceso para el usuario IAM '{username}' revocadas. Llaves desactivadas ({enforcement.get('keys_deactivated', 0)}) y politica inline EmergencyDenyAll adjuntada.",
        footer_text="AWS Automated Incident Response System | Tesis IR"
    )


def send_ses_email(subject: str, html_body: str, plain_body: str) -> None:
    if not ALERT_EMAIL:
        return
    sender = SES_SENDER_EMAIL or ALERT_EMAIL
    try:
        ses.send_email(
            Source=f"AWS Security SOC <{sender}>",
            Destination={"ToAddresses": [ALERT_EMAIL]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Html": {"Data": html_body, "Charset": "UTF-8"},
                    "Text": {"Data": plain_body, "Charset": "UTF-8"},
                }
            }
        )
        print(f"[SES] Correo HTML de mitigacion enviado a {ALERT_EMAIL} desde {sender}")
    except Exception as exc:
        print(f"[SES] Envio SES no disponible ({exc}). Se mantiene envio via SNS.")


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
        if incident_type not in {"PRIVILEGE_ESCALATION", "CREDENTIAL_LEAK"}:
            print(f"[revoke-credentials] Tipo {incident_type} no requiere revocacion. Omitiendo.")
            results.append({"status": "skipped", "reason": f"not_in_revoke_list:{incident_type}"})
            continue

        affected_resource = body.get("affectedResource", "")
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

        # ── 6. Generar reportes ──────────────────────────────────────────────
        subject = f"[{entry['severity']}] Mitigacion: Credenciales {username} {status}"
        formatted_time = format_dt(timestamp)
        actions_str = ", ".join(actions_taken) if actions_taken else "Ninguna acción registrada"
        deny_status = "EmergencyDenyAll adjuntada (Bloqueo Total)" if enforcement.get('deny_all_applied') else "No aplicada"

        mitigation_plain = "\n".join([
            "=" * 60,
            f"[MITIGACION DE SEGURIDAD AWS] - ACCION: {status}",
            "=" * 60,
            "INFORMACION GENERAL:",
            f"  Estado             : {status}",
            f"  Playbook           : revoke-credentials",
            f"  Tipo de Incidente  : {incident_type}",
            f"  ID de Incidente    : {incident_id}",
            "",
            "CONTENCION APLICADA:",
            f"  Usuario IAM        : {username}",
            f"  Acciones Tomadas   : {actions_str}",
            f"  Politica DenyAll   : {deny_status}",
            "  Enforcement        : Desactivacion inmediata de credenciales y revocacion de permisos",
            "",
            "TRAZABILIDAD:",
            f"  Hora Mitigacion    : {formatted_time}",
            f"  Evidencia S3       : {key}",
            "=" * 60,
        ])
        mitigation_html = format_mitigation_html(entry, username, actions_taken, enforcement, key)

        # ── Envio directo de correo HTML via SES ───────────────────────────
        send_ses_email(subject, mitigation_html, mitigation_plain)

        # ── Publicar reporte en SNS ────────────────────────────────────────
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=subject[:100],
            Message=mitigation_plain,
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
