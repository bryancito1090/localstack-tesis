"""
Playbook: notify-alert
Recibe incidentes desde una cola SQS dedicada, genera un reporte profesional
de seguridad para el SOC (formato tarjeta HTML con colores diferenciados y texto plano normalizado)
y lo entrega via SES a Gmail y via SNS a Telegram. Tambien registra evidencia en S3.
"""
import html
import json
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import boto3

sns = boto3.client("sns")
s3  = boto3.client("s3")
ses = boto3.client("ses")

SNS_ARN         = os.environ["SNS_ALERTS_ARN"]
EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
RESPONSE_PREFIX = os.environ.get("RESPONSE_PREFIX", "responses/notify-alert")
ALERT_EMAIL      = os.environ.get("ALERT_EMAIL", "")
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL") or ALERT_EMAIL
EC_TZ           = ZoneInfo("America/Guayaquil")

SUPPORTED_INCIDENT_TYPES = {
    "BRUTE_FORCE",
    "PORT_SCAN",
    "PRIVILEGE_ESCALATION",
    "CREDENTIAL_LEAK",
    "EXFILTRATION",
}


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


def format_incident_report(alert: dict) -> str:
    """Genera un reporte profesional de seguridad (SOC) estructurado y normalizado en texto plano."""
    incident_type = alert.get("incident_type", "NO_ESPECIFICADO")
    severity      = alert.get("severity", "MEDIUM")
    status        = alert.get("status", "NOTIFICADO")
    incident_id   = alert.get("incident_id", "N/A")
    source_ip     = alert.get("sourceIPAddress", "N/A")
    resource      = alert.get("affectedResource", "N/A")
    service       = alert.get("affected_service", "N/A")
    asset         = alert.get("asset_name", "N/A")
    basis         = alert.get("severity_basis", "N/A")
    detected_at   = format_dt(alert.get("detectedAt", "N/A"))
    responded_at  = format_dt(alert.get("respondedAt", "N/A"))
    s3_key        = alert.get("s3_log_key", "N/A")

    lines = [
        "=" * 60,
        "[ALERTA DE SEGURIDAD AWS] - SOC INCIDENT RESPONSE",
        "=" * 60,
        "INFORMACION GENERAL:",
        f"  Severidad          : {severity}",
        f"  Tipo de Incidente  : {incident_type}",
        f"  ID de Incidente    : {incident_id}",
        f"  Estado             : {status}",
        f"  Playbook           : notify-alert",
        "",
        "RECURSO Y ORIGEN:",
        f"  IP Origen          : {source_ip}",
        f"  Recurso Afectado   : {resource}",
        f"  Servicio Afectado  : {service}",
        f"  Activo Objetivo    : {asset}",
        "",
        "CRITERIO Y DIAGNOSTICO:",
        f"  Criterio / Motivo  : {basis}",
        f"  Hora Deteccion     : {detected_at}",
        f"  Hora Respuesta     : {responded_at}",
        f"  Evidencia S3       : {s3_key}",
        "=" * 60,
    ]
    return "\n".join(lines)


def format_incident_html(alert: dict) -> str:
    """Genera la tarjeta visual HTML con colores diferenciados según la severidad."""
    incident_type = alert.get("incident_type", "NO_ESPECIFICADO")
    severity      = alert.get("severity", "MEDIUM")
    status        = alert.get("status", "NOTIFICADO")
    incident_id   = alert.get("incident_id", "N/A")
    source_ip     = alert.get("sourceIPAddress", "N/A")
    resource      = alert.get("affectedResource", "N/A")
    service       = alert.get("affected_service", "N/A")
    asset         = alert.get("asset_name", "N/A")
    basis         = alert.get("severity_basis", "N/A")
    detected_at   = format_dt(alert.get("detectedAt", "N/A"))
    responded_at  = format_dt(alert.get("respondedAt", "N/A"))
    s3_key        = alert.get("s3_log_key", "N/A")

    return generate_html_card(
        title="[ALERTA DE SEGURIDAD AWS]",
        subtitle="SOC Automated Incident Response",
        badge_text=f"SEVERIDAD: {severity}",
        badge_type=severity,
        sections={
            "INFORMACION GENERAL": [
                ("Tipo de Incidente", incident_type),
                ("ID de Incidente", incident_id),
                ("Estado", status),
                ("Playbook", "notify-alert"),
            ],
            "RECURSO Y ORIGEN": [
                ("IP Origen", source_ip),
                ("Recurso Afectado", resource),
                ("Servicio Afectado", service),
                ("Activo Objetivo", asset),
            ],
            "TRAZABILIDAD": [
                ("Hora Deteccion", detected_at),
                ("Hora Respuesta", responded_at),
                ("Evidencia S3", s3_key),
            ]
        },
        callout_label="CRITERIO Y DIAGNOSTICO",
        callout_text=basis,
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
        print(f"[SES] Correo HTML enviado a {ALERT_EMAIL} desde {sender}")
    except Exception as exc:
        print(f"[SES] Envio SES no disponible ({exc}). Se mantiene envio via SNS.")


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        try:
            body = json.loads(record.get("body", "{}"))
        except json.JSONDecodeError as exc:
            results.append({"status": "skipped", "reason": f"invalid_json: {exc}"})
            continue

        incident_type = body.get("incident_type", "UNKNOWN")
        if incident_type not in SUPPORTED_INCIDENT_TYPES:
            results.append({"status": "skipped", "reason": f"unsupported_type:{incident_type}"})
            continue

        # ── Construir alerta estructurada ──────────────────────────────────
        alert = {
            "alert_type":       "SECURITY_INCIDENT",
            "incident_type":    incident_type,
            "severity":         body.get("severity", "MEDIUM"),
            "sourceIPAddress":  body.get("sourceIPAddress", "unknown"),
            "affectedResource": body.get("affectedResource", "unknown"),
            "affected_service": body.get("affected_service",
                                         body.get("affectedService", "unknown")),
            "asset_name":       body.get("asset_name",
                                         body.get("assetName", "unknown")),
            "severity_basis":   body.get("severity_basis",
                                         f"Umbral de {incident_type} alcanzado."),
            "detectedAt":       body.get("timestamp", now_ecuador()),
            "respondedAt":      now_ecuador(),
            "timezone":         "America/Guayaquil",
            "playbook":         "notify-alert",
            "status":           "NOTIFIED",
            "s3_log_key":       body.get("s3_log_key", ""),
            "incident_id":      body.get("incident_id", ""),
        }

        # ── Guardar evidencia JSON en S3 ───────────────────────────────────
        key = f"{RESPONSE_PREFIX}/{body.get('incident_id') or uuid.uuid4().hex}.json"
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=key,
            Body=json.dumps(alert, indent=2, ensure_ascii=False).encode("utf-8"),
            ContentType="application/json",
        )

        # ── Generar reportes ───────────────────────────────────────────────
        subject = f"[{alert['severity']}] Incidente: {incident_type} ({alert['affectedResource']})"
        report_text = format_incident_report(alert)
        report_html = format_incident_html(alert)

        # ── Envio directo de correo HTML via SES (si esta disponible) ──────
        send_ses_email(subject, report_html, report_text)

        # ── Publicar reporte en SNS (para Telegram y subscriptores SNS) ────
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=subject[:100],
            Message=report_text,
        )

        print(f"[notify-alert] {incident_type} notificado profesionalmente. evidence_key={key}")
        results.append({"status": "success", "action": "sns_published", "evidence_key": key})

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": now_ecuador(),
    }
