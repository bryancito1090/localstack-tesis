"""
Playbook: block-ip
Mitigacion de contención real para incidentes de red.
Bloquea la IP origen creando una regla DENY inbound en la Network ACL
objetivo, registra evidencia de respuesta en S3 y notifica via HTML Card (SES) y SNS (Telegram).
"""
import html
import ipaddress
import json
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import boto3

s3  = boto3.client("s3")
sns = boto3.client("sns")
ec2 = boto3.client("ec2")
ses = boto3.client("ses")

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
SNS_ARN         = os.environ["SNS_ALERTS_ARN"]
TARGET_NACL_ID  = os.environ["TARGET_NACL_ID"]
RESPONSE_PREFIX = os.environ.get("RESPONSE_PREFIX", "responses/block-ip")
RULE_MIN        = int(os.environ.get("RULE_MIN", "1"))
RULE_MAX        = int(os.environ.get("RULE_MAX", "99"))
ALERT_EMAIL      = os.environ.get("ALERT_EMAIL", "")
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL") or ALERT_EMAIL
EC_TZ           = ZoneInfo("America/Guayaquil")

BLOCK_INCIDENT_TYPES = {"BRUTE_FORCE", "PORT_SCAN"}


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


def format_mitigation_html(entry: dict, enforcement: dict, key: str) -> str:
    status = entry.get("status", "BLOCKED")
    incident_type = entry.get("incident_type", "INCIDENT")
    ip_value = entry.get("sourceIPAddress", "N/A")
    timestamp = format_dt(entry.get("timestamp", ""))
    nacl_id = enforcement.get("network_acl_id", "N/A")
    rule_num = enforcement.get("rule_number", "N/A")

    return generate_html_card(
        title="[MITIGACION DE SEGURIDAD AWS]",
        subtitle="Network ACL Automated Containment",
        badge_text=f"ACCION: {status}",
        badge_type="BLOCKED" if status == "BLOCKED" else "HIGH",
        sections={
            "INFORMACION GENERAL": [
                ("Estado", status),
                ("Playbook", "block-ip"),
                ("Tipo de Incidente", incident_type),
                ("ID de Incidente", entry.get("incident_id", "N/A")),
            ],
            "CONTENCION APLICADA": [
                ("IP Bloqueada", f"{ip_value}/32"),
                ("Network ACL", nacl_id),
                ("Regla Inbound", f"#{rule_num} (DENY All Traffic)"),
                ("Enforcement", "Bloqueo perimetral a nivel de subred en VPC"),
            ],
            "TRAZABILIDAD": [
                ("Hora Mitigacion", timestamp),
                ("Evidencia S3", key),
            ]
        },
        callout_label="DETALLES DE MITIGACION",
        callout_text=f"Trafico de entrada proveniente de la IP atacante {ip_value} bloqueado permanentemente mediante regla DENY #{rule_num} en la Network ACL {nacl_id}.",
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


def valid_public_ip(ip_value: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_multicast
        or ip.is_unspecified or ip.is_reserved
    )


def next_rule_number(nacl_id: str) -> int:
    response = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    used = set()
    for entry in response.get("NetworkAcls", [{}])[0].get("Entries", []):
        if not entry.get("Egress", False):
            used.add(entry.get("RuleNumber"))
    for number in range(RULE_MIN, RULE_MAX + 1):
        if number not in used:
            return number
    raise RuntimeError("No quedan numeros de regla libres para reglas DENY de mitigacion.")


def block_ip(ip_value: str) -> dict:
    cidr = f"{ip_value}/32"
    response = ec2.describe_network_acls(NetworkAclIds=[TARGET_NACL_ID])
    entries  = response.get("NetworkAcls", [{}])[0].get("Entries", [])

    for entry in entries:
        if (not entry.get("Egress", False)
                and entry.get("CidrBlock") == cidr
                and entry.get("RuleAction") == "deny"):
            return {
                "enforced":        True,
                "already_present": True,
                "network_acl_id":  TARGET_NACL_ID,
                "rule_number":     entry.get("RuleNumber"),
                "cidr":            cidr,
            }

    rule_number = next_rule_number(TARGET_NACL_ID)
    ec2.create_network_acl_entry(
        NetworkAclId=TARGET_NACL_ID,
        RuleNumber=rule_number,
        Protocol="-1",
        RuleAction="deny",
        Egress=False,
        CidrBlock=cidr,
    )
    print(f"[block-ip] NACL {TARGET_NACL_ID}: regla DENY #{rule_number} creada para {cidr}")
    return {
        "enforced":        True,
        "already_present": False,
        "network_acl_id":  TARGET_NACL_ID,
        "rule_number":     rule_number,
        "cidr":            cidr,
    }


def load_blocklist() -> list:
    try:
        obj = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=f"{RESPONSE_PREFIX}/blocked-ips.json")
        return json.loads(obj["Body"].read())
    except Exception:
        return []


def save_blocklist(blocklist: list) -> None:
    s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=f"{RESPONSE_PREFIX}/blocked-ips.json",
        Body=json.dumps(blocklist, indent=2, ensure_ascii=False).encode("utf-8"),
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

        if incident_type not in BLOCK_INCIDENT_TYPES:
            print(f"[block-ip] Tipo {incident_type} no requiere bloqueo de IP. Omitiendo.")
            results.append({"status": "skipped", "reason": f"not_in_block_list:{incident_type}"})
            continue

        ip_value  = body.get("sourceIPAddress", "")
        timestamp = now_ecuador()

        # ── Aplicar bloqueo real en NACL ──────────────────────────────────
        if not valid_public_ip(ip_value):
            enforcement = {
                "enforced": False,
                "reason":   "invalid_or_non_public_ip",
                "ip":       ip_value,
            }
            status = "SKIPPED"
            print(f"[block-ip] IP invalida o privada: {ip_value}. Omitiendo bloqueo.")
        else:
            try:
                enforcement = block_ip(ip_value)
                status = "BLOCKED" if enforcement.get("enforced") else "BLOCK_FAILED"
            except Exception as exc:
                enforcement = {"enforced": False, "error": str(exc), "ip": ip_value}
                status = "BLOCK_FAILED"
                print(f"[block-ip] ERROR aplicando bloqueo para {ip_value}: {exc}")

        # ── Construir registro de evidencia ────────────────────────────────
        entry = {
            "playbook":        "block-ip",
            "incident_type":   incident_type,
            "severity":        body.get("severity", "MEDIUM"),
            "sourceIPAddress": ip_value,
            "affectedResource": body.get("affectedResource", "unknown"),
            "affected_service": body.get("affected_service",
                                          body.get("affectedService", "unknown")),
            "asset_name":      body.get("asset_name", body.get("assetName", "unknown")),
            "severity_basis":  body.get("severity_basis",
                                         f"Umbral de {incident_type} alcanzado."),
            "status":          status,
            "enforcement":     enforcement,
            "timestamp":       timestamp,
            "timezone":        "America/Guayaquil",
            "incident_id":     body.get("incident_id", ""),
        }

        if incident_type == "PORT_SCAN":
            entry["scanned_ports_count"]  = body.get("scanned_ports_count",
                                                       body.get("event_count", 0))
            entry["rejected_connections"] = body.get("rejected_connections", 0)
        elif incident_type == "BRUTE_FORCE":
            entry["failed_attempts"]      = body.get("failed_attempts",
                                                       body.get("event_count", 0))

        # ── Actualizar lista de IPs bloqueadas ────────────────────────────
        blocklist = load_blocklist()
        if not any(item.get("sourceIPAddress") == ip_value for item in blocklist):
            blocklist.append(entry)
            save_blocklist(blocklist)

        # ── Guardar evidencia individual por incidente ─────────────────────
        key = f"{RESPONSE_PREFIX}/{body.get('incident_id') or uuid.uuid4().hex}.json"
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=key,
            Body=json.dumps(entry, indent=2, ensure_ascii=False).encode("utf-8"),
            ContentType="application/json",
        )

        # ── Generar reportes ───────────────────────────────────────────────
        subject = f"[{entry['severity']}] Mitigacion: IP {ip_value} {status} en NACL"
        formatted_time = format_dt(timestamp)
        nacl_id = enforcement.get('network_acl_id', 'N/A')
        rule_num = enforcement.get('rule_number', 'N/A')

        mitigation_plain = "\n".join([
            "=" * 60,
            f"[MITIGACION DE SEGURIDAD AWS] - ACCION: {status}",
            "=" * 60,
            "INFORMACION GENERAL:",
            f"  Estado             : {status}",
            f"  Playbook           : block-ip",
            f"  Tipo de Incidente  : {incident_type}",
            f"  ID de Incidente    : {entry['incident_id']}",
            "",
            "CONTENCION APLICADA:",
            f"  IP Bloqueada       : {ip_value}/32",
            f"  Network ACL        : {nacl_id}",
            f"  Regla Inbound      : #{rule_num} (DENY All Traffic)",
            "  Enforcement        : Bloqueo perimetral a nivel de subred en VPC",
            "",
            "TRAZABILIDAD:",
            f"  Hora Mitigacion    : {formatted_time}",
            f"  Evidencia S3       : {key}",
            "=" * 60,
        ])
        mitigation_html = format_mitigation_html(entry, enforcement, key)

        # ── Envio directo de correo HTML via SES ───────────────────────────
        send_ses_email(subject, mitigation_html, mitigation_plain)

        # ── Publicar reporte en SNS ────────────────────────────────────────
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=subject[:100],
            Message=mitigation_plain,
        )

        print(f"[block-ip] {incident_type} → {status} para {ip_value}. "
              f"NACL rule={enforcement.get('rule_number')}. evidence={key}")
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
