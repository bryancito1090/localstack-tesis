"""
Lambda: telegram-notifier
Suscrito a Amazon SNS (Topic de alertas de seguridad).
Recibe las notificaciones de incidentes y mitigaciones de seguridad publicadas
en el tópico SNS, genera una tarjeta visual en formato de imagen PNG de alta resolución
(con cabeceras de color según severidad/acción, tablas e insignias) y la entrega
directamente al chat de Telegram mediante la API sendPhoto.
"""
import html
import json
import os
import urllib.parse
import urllib.request
import uuid

try:
    import card_image
except ImportError:
    from . import card_image

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")


def parse_key_values(raw_text: str) -> dict:
    """Extrae pares clave-valor de reportes en texto estructurado."""
    data = {}
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("-") or line.startswith("━"):
            continue
        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip().lstrip("•").strip()
            v = parts[1].strip()
            data[k] = v
    return data


def create_incident_card_image(data: dict) -> bytes:
    sev      = str(data.get("severity") or data.get("Severidad") or "HIGH")
    inc_type = str(data.get("incident_type") or data.get("Tipo de Incidente") or data.get("Tipo Incidente") or "INCIDENT")
    inc_id   = str(data.get("incident_id") or data.get("ID de Incidente") or data.get("ID Incidente") or "N/A")
    status   = str(data.get("status") or data.get("Estado") or "NOTIFICADO")
    playbook = str(data.get("playbook") or data.get("Playbook") or "notify-alert")
    ip       = str(data.get("sourceIPAddress") or data.get("IP Origen") or "N/A")
    resource = str(data.get("affectedResource") or data.get("Recurso Afectado") or data.get("Recurso") or "N/A")
    service  = str(data.get("affected_service") or data.get("Servicio Afectado") or data.get("Servicio") or "N/A")
    asset    = str(data.get("asset_name") or data.get("Activo Objetivo") or data.get("Activo") or "N/A")
    basis    = str(data.get("severity_basis") or data.get("Criterio / Motivo") or data.get("Motivo") or "N/A")
    det_time = str(data.get("detectedAt") or data.get("Hora Deteccion") or data.get("Hora Detección") or data.get("timestamp_ecuador") or data.get("timestamp") or "N/A")
    s3_key   = str(data.get("s3_log_key") or data.get("Evidencia S3") or "N/A")

    sections = {
        "INFORMACION GENERAL": [
            ("Tipo de Incidente", inc_type),
            ("ID de Incidente", inc_id),
            ("Estado", status),
            ("Playbook", playbook),
        ],
        "RECURSO Y ORIGEN": [
            ("IP Origen", ip),
            ("Recurso Afectado", resource),
            ("Servicio Afectado", service),
            ("Activo Objetivo", asset),
        ],
        "TRAZABILIDAD": [
            ("Hora Deteccion", det_time),
            ("Evidencia S3", s3_key),
        ]
    }

    return card_image.generate_security_card_png(
        title="[ALERTA DE SEGURIDAD AWS]",
        subtitle="SOC Automated Incident Response",
        badge_text=f"SEVERIDAD: {sev}",
        badge_type=sev,
        sections=sections,
        callout_label="CRITERIO Y DIAGNOSTICO",
        callout_text=basis,
        footer_text="AWS Automated Incident Response System | Tesis IR"
    )


def create_mitigation_card_image(raw_text: str, kv: dict) -> bytes:
    is_block  = "block-ip" in raw_text or "IP Bloqueada" in kv or "Network ACL" in kv
    status    = str(kv.get("Estado", "CONTAINED"))
    playbook  = str(kv.get("Playbook", "mitigation-playbook"))
    inc_type  = str(kv.get("Tipo de Incidente") or kv.get("Tipo Incidente") or "INCIDENT")
    inc_id    = str(kv.get("ID de Incidente") or kv.get("ID Incidente") or "N/A")
    exec_time = str(kv.get("Hora Mitigacion") or kv.get("Hora Ejecución") or "N/A")
    s3_key    = str(kv.get("Evidencia S3", "N/A"))

    if is_block:
        ip      = str(kv.get("IP Bloqueada") or kv.get("IP Objetivo") or "N/A")
        nacl    = str(kv.get("Network ACL", "N/A"))
        regla   = str(kv.get("Regla Inbound") or kv.get("Regla Creada") or "N/A")
        enforce = str(kv.get("Enforcement", "Bloqueo perimetral a nivel de subred en VPC"))

        sections = {
            "INFORMACION GENERAL": [
                ("Estado", status),
                ("Playbook", playbook),
                ("Tipo de Incidente", inc_type),
                ("ID de Incidente", inc_id),
            ],
            "CONTENCION APLICADA": [
                ("IP Bloqueada", ip),
                ("Network ACL", nacl),
                ("Regla Inbound", regla),
                ("Enforcement", enforce),
            ],
            "TRAZABILIDAD": [
                ("Hora Mitigacion", exec_time),
                ("Evidencia S3", s3_key),
            ]
        }
        return card_image.generate_security_card_png(
            title="[MITIGACION DE SEGURIDAD AWS]",
            subtitle="Network ACL Automated Containment",
            badge_text=f"ACCION: {status}",
            badge_type="BLOCKED" if status == "BLOCKED" else "HIGH",
            sections=sections,
            callout_label="DETALLES DE MITIGACION",
            callout_text=f"Trafico de entrada desde {ip} bloqueado permanentemente mediante regla DENY en {nacl}.",
            footer_text="AWS Automated Incident Response System | Tesis IR"
        )
    else:
        user    = str(kv.get("Usuario IAM", "N/A"))
        actions = str(kv.get("Acciones Tomadas") or kv.get("Acciones") or "N/A")
        deny    = str(kv.get("Politica DenyAll") or kv.get("DenyAll Policy") or "N/A")
        enforce = str(kv.get("Enforcement", "Desactivacion inmediata de credenciales y revocacion de permisos"))

        sections = {
            "INFORMACION GENERAL": [
                ("Estado", status),
                ("Playbook", playbook),
                ("Tipo de Incidente", inc_type),
                ("ID de Incidente", inc_id),
            ],
            "CONTENCION APLICADA": [
                ("Usuario IAM", user),
                ("Acciones Tomadas", actions),
                ("Politica DenyAll", deny),
                ("Enforcement", enforce),
            ],
            "TRAZABILIDAD": [
                ("Hora Mitigacion", exec_time),
                ("Evidencia S3", s3_key),
            ]
        }
        return card_image.generate_security_card_png(
            title="[MITIGACION DE SEGURIDAD AWS]",
            subtitle="IAM Automated Credential Revocation",
            badge_text=f"ACCION: {status}",
            badge_type="CONTAINED" if status == "CONTAINED" else "CRITICAL",
            sections=sections,
            callout_label="DETALLES DE MITIGACION",
            callout_text=f"Credenciales de {user} revocadas y politica inline EmergencyDenyAll adjuntada.",
            footer_text="AWS Automated Incident Response System | Tesis IR"
        )


def send_telegram_photo(png_bytes: bytes, caption: str = "") -> dict:
    """Envía la tarjeta de imagen PNG a Telegram usando multipart/form-data."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[telegram-notifier] Variables TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no configuradas.")
        return {"status": "skipped", "reason": "missing_credentials"}

    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
    body = bytearray()

    # Campo: chat_id
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(b'Content-Disposition: form-data; name="chat_id"\r\n\r\n')
    body.extend(f"{TELEGRAM_CHAT_ID}\r\n".encode("utf-8"))

    # Campo opcional: caption
    if caption:
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(b'Content-Disposition: form-data; name="caption"\r\n\r\n')
        body.extend(caption.encode("utf-8"))
        body.extend(b"\r\n")

    # Campo: photo (archivo PNG en memoria)
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(b'Content-Disposition: form-data; name="photo"; filename="security_card.png"\r\n')
    body.extend(b"Content-Type: image/png\r\n\r\n")
    body.extend(png_bytes)
    body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto"
    req = urllib.request.Request(
        api_url,
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            resp_body = response.read().decode("utf-8")
            print(f"[telegram-notifier] Tarjeta de imagen enviada a Telegram. HTTP {response.status}")
            return {"status": "success", "response": json.loads(resp_body)}
    except Exception as exc:
        print(f"[telegram-notifier] Error enviando imagen a Telegram: {exc}")
        return {"status": "error", "error": str(exc)}


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        sns_record = record.get("Sns", {})
        raw_message = sns_record.get("Message", "").strip()

        if not raw_message:
            continue

        png_bytes = None
        caption = ""

        try:
            if raw_message.startswith("{"):
                data = json.loads(raw_message)
                if "incident_payload" in data:
                    data = data["incident_payload"]
                png_bytes = create_incident_card_image(data)
                caption = f"Incidente: {data.get('incident_type', 'INCIDENT')} ({data.get('severity', 'HIGH')})"
            elif "ALERTA DE SEGURIDAD AWS" in raw_message:
                kv = parse_key_values(raw_message)
                png_bytes = create_incident_card_image(kv)
                caption = f"Alerta: {kv.get('Tipo de Incidente', 'INCIDENT')} [{kv.get('Severidad', 'HIGH')}]"
            elif "MITIGACION DE SEGURIDAD AWS" in raw_message or "MITIGACIÓN DE SEGURIDAD AWS" in raw_message:
                kv = parse_key_values(raw_message)
                png_bytes = create_mitigation_card_image(raw_message, kv)
                caption = f"Mitigacion: {kv.get('Playbook', 'block-ip')} [{kv.get('Estado', 'BLOCKED')}]"
            else:
                # Si es un mensaje generico, crear tarjeta generica
                kv = parse_key_values(raw_message)
                png_bytes = create_incident_card_image(kv)
                caption = "Notificacion de Seguridad AWS"
        except Exception as exc:
            print(f"[telegram-notifier] Error construyendo tarjeta grafica: {exc}")

        if png_bytes:
            send_res = send_telegram_photo(png_bytes, caption)
            results.append(send_res)
        else:
            print("[telegram-notifier] No se pudo generar la tarjeta grafica PNG.")

    return {
        "status": "success",
        "processed": len(results),
        "results": results
    }
