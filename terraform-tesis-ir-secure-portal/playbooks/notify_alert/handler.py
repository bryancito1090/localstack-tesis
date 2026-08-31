"""
Playbook: notify-alert
Recibe incidentes desde una cola SQS dedicada, genera un reporte profesional
de seguridad para el SOC y lo publica al topico SNS (para entrega simultanea
y formateada en Gmail y Telegram). Tambien registra evidencia en S3.
"""
import json
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import boto3

sns = boto3.client("sns")
s3  = boto3.client("s3")

SNS_ARN         = os.environ["SNS_ALERTS_ARN"]
EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
RESPONSE_PREFIX = os.environ.get("RESPONSE_PREFIX", "responses/notify-alert")
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


def format_incident_report(alert: dict) -> str:
    """Genera un reporte profesional de seguridad (SOC) en texto plano para correo y Telegram."""
    incident_type = alert.get("incident_type", "NO_ESPECIFICADO")
    severity      = alert.get("severity", "MEDIUM")
    status        = alert.get("status", "NOTIFICADO")
    incident_id   = alert.get("incident_id", "N/A")
    source_ip     = alert.get("sourceIPAddress", "N/A")
    resource      = alert.get("affectedResource", "N/A")
    service       = alert.get("affected_service", "N/A")
    asset         = alert.get("asset_name", "N/A")
    basis         = alert.get("severity_basis", "N/A")
    detected_at   = alert.get("detectedAt", "N/A")
    responded_at  = alert.get("respondedAt", "N/A")
    s3_key        = alert.get("s3_log_key", "N/A")

    lines = [
        f"[ALERTA DE SEGURIDAD AWS] - SEVERIDAD: {severity}",
        "=" * 50,
        f"Tipo de Incidente : {incident_type}",
        f"ID de Incidente   : {incident_id}",
        f"Estado            : {status}",
        f"Playbook          : notify-alert",
        "-" * 50,
        f"IP Origen         : {source_ip}",
        f"Recurso Afectado  : {resource}",
        f"Servicio Afectado : {service}",
        f"Activo Objetivo   : {asset}",
        "-" * 50,
        f"Criterio / Motivo : {basis}",
        f"Hora Deteccion    : {detected_at}",
        f"Hora Respuesta    : {responded_at}",
        f"Evidencia S3      : {s3_key}",
        "=" * 50,
    ]
    return "\n".join(lines)


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

        # ── Publicar reporte legible en SNS (llega formateado a Gmail y Telegram)
        subject = f"[{alert['severity']}] Incidente: {incident_type} ({alert['affectedResource']})"
        report_text = format_incident_report(alert)

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
