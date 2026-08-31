"""
Lambda: telegram-notifier
Suscrito a Amazon SNS (Topic de alertas de seguridad).
Recibe la notificacion estructurada del topico SNS y la envia directamente
a Telegram en formato monoespaciado (<pre>) usando la biblioteca estandar de Python.
"""
import json
import os
import urllib.parse
import urllib.request

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")


def send_telegram_message(text: str) -> dict:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[telegram-notifier] Variables TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no configuradas.")
        return {"status": "skipped", "reason": "missing_credentials"}

    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"<pre>{text}</pre>",
        "parse_mode": "HTML"
    }

    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=data_bytes,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_body = response.read().decode("utf-8")
            print(f"[telegram-notifier] Mensaje entregado a Telegram. HTTP {response.status}")
            return {"status": "success", "response": json.loads(resp_body)}
    except Exception as exc:
        print(f"[telegram-notifier] Error enviando mensaje a Telegram: {exc}")
        return {"status": "error", "error": str(exc)}


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        sns_record = record.get("Sns", {})
        raw_message = sns_record.get("Message", "")
        
        # Si el mensaje ya es texto plano formateado por notify-alert, enviarlo directo
        if not raw_message.strip().startswith("{"):
            send_result = send_telegram_message(raw_message.strip())
            results.append(send_result)
            continue

        # Si por alguna razon llega un JSON crudo, parsearlo y formatearlo
        try:
            message_data = json.loads(raw_message)
            if "incident_payload" in message_data:
                message_data = message_data["incident_payload"]
            
            lines = [
                f"[ALERTA DE SEGURIDAD AWS] - SEVERIDAD: {message_data.get('severity', 'HIGH')}",
                "=" * 50,
                f"Tipo de Incidente : {message_data.get('incident_type', 'NO_ESPECIFICADO')}",
                f"ID de Incidente   : {message_data.get('incident_id', 'N/A')}",
                f"Estado            : {message_data.get('status', 'NOTIFICADO')}",
                "-" * 50,
                f"IP Origen         : {message_data.get('sourceIPAddress', 'N/A')}",
                f"Recurso Afectado  : {message_data.get('affectedResource', 'N/A')}",
                f"Criterio / Motivo : {message_data.get('severity_basis', 'N/A')}",
                "=" * 50,
            ]
            formatted_text = "\n".join(lines)
            send_result = send_telegram_message(formatted_text)
            results.append(send_result)
        except Exception:
            send_result = send_telegram_message(str(raw_message))
            results.append(send_result)

    return {
        "status": "success",
        "processed": len(results),
        "results": results
    }
