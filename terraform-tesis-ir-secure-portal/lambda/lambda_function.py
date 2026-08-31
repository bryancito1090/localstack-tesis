import base64
import gzip
import ipaddress
import json
import os
import time
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
sns = boto3.client("sns")
sqs = boto3.client("sqs")
cloudwatch = boto3.client("cloudwatch")

INCIDENTS_TABLE = os.environ["INCIDENTS_TABLE"]
STATE_TABLE = os.environ["STATE_TABLE"]
EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
CONFIG_KEY = os.environ["CONFIG_KEY"]
INCIDENT_QUEUE_URL = os.environ.get("INCIDENT_QUEUE_URL", "")
VPC_ID = os.environ.get("VPC_ID", "unknown-vpc")
PORTAL_INSTANCE_ID = os.environ.get("PORTAL_INSTANCE_ID", "unknown-instance")
PLAYBOOK_NOTIFY_QUEUE_URL = os.environ.get("PLAYBOOK_NOTIFY_QUEUE_URL", "")
PLAYBOOK_BLOCK_IP_QUEUE_URL = os.environ.get("PLAYBOOK_BLOCK_IP_QUEUE_URL", "")
PLAYBOOK_REVOKE_CREDENTIALS_QUEUE_URL = os.environ.get("PLAYBOOK_REVOKE_CREDENTIALS_QUEUE_URL", "")
ECUADOR_TZ = ZoneInfo("America/Guayaquil")

incidents_table = dynamodb.Table(INCIDENTS_TABLE)
state_table = dynamodb.Table(STATE_TABLE)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ecuador_now() -> str:
    return datetime.now(ECUADOR_TZ).isoformat()


def epoch_now() -> int:
    return int(time.time())


def current_window(minutes: int) -> int:
    return epoch_now() // (minutes * 60)


def decimal_default(obj):
    if isinstance(obj, Decimal):
        return int(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def load_config() -> dict:
    obj = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=CONFIG_KEY)
    return json.loads(obj["Body"].read().decode("utf-8"))


def decode_cloudwatch_event(event: dict) -> dict:
    if "awslogs" not in event:
        return {
            "logGroup": "direct-test",
            "logStream": "manual",
            "logEvents": [
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": int(time.time() * 1000),
                    "message": json.dumps(event),
                }
            ],
        }

    payload = base64.b64decode(event["awslogs"]["data"])
    uncompressed = gzip.decompress(payload)
    return json.loads(uncompressed)


def safe_json_loads(value: str):
    try:
        return json.loads(value)
    except Exception:
        return None


def ip_in_cidrs(ip_value: str, cidrs: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_value)
    except Exception:
        return False

    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except Exception:
            continue
    return False


def username_from_identity(event_json: dict) -> str:
    identity = event_json.get("userIdentity", {}) or {}
    username = identity.get("userName")
    if username:
        return username

    arn = identity.get("arn", "")
    if ":user/" in arn:
        return arn.split(":user/", 1)[1]
    if ":assumed-role/" in arn:
        return arn.rsplit("/", 1)[-1]
    if identity.get("principalId"):
        return str(identity.get("principalId"))
    return "unknown"


def affected_iam_user(event_json: dict, fallback_username: str | None = None) -> str:
    username = fallback_username or username_from_identity(event_json)
    if not username:
        username = "unknown"
    return f"iam:user/{username}"


def increment_counter(pk: str, sk: str = "counter", ttl_seconds: int = 900) -> int:
    response = state_table.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET #ttl = :ttl, updated_at = :updated_at ADD #count :one",
        ExpressionAttributeNames={
            "#ttl": "ttl",
            "#count": "count",
        },
        ExpressionAttributeValues={
            ":ttl": epoch_now() + ttl_seconds,
            ":updated_at": utc_now(),
            ":one": 1,
        },
        ReturnValues="UPDATED_NEW",
    )
    return int(response["Attributes"]["count"])


def mark_alert_once(alert_key: str, ttl_seconds: int = 900) -> bool:
    try:
        state_table.put_item(
            Item={
                "pk": f"alert#{alert_key}",
                "sk": "sent",
                "ttl": epoch_now() + ttl_seconds,
                "created_at": utc_now(),
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def put_distinct_port_and_count(srcaddr: str, dstport: str, ttl_seconds: int = 900) -> int:
    pk = f"portscan#{srcaddr}#window#{current_window(5)}"
    sk = f"port#{dstport}"
    state_table.put_item(
        Item={
            "pk": pk,
            "sk": sk,
            "ttl": epoch_now() + ttl_seconds,
            "updated_at": utc_now(),
        }
    )
    response = state_table.query(KeyConditionExpression=Key("pk").eq(pk), Select="COUNT")
    return int(response.get("Count", 0))


def evidence_folder(incident_type: str) -> str:
    mapping = {
        "BRUTE_FORCE": "incident-01-bruteforce",
        "PORT_SCAN": "incident-02-port-scan",
        "PRIVILEGE_ESCALATION": "incident-03-privilege-escalation",
        "CREDENTIAL_LEAK": "incident-04-credential-leak",
        "EXFILTRATION": "incident-05-exfiltration",
    }
    return mapping.get(incident_type, incident_type.lower())


def build_evidence_key(incident_type: str, incident_id: str) -> str:
    return f"{evidence_folder(incident_type)}/{incident_id}.json"


def send_sqs_message(queue_url: str, payload: dict) -> None:
    if not queue_url:
        return
    try:
        sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload, default=decimal_default))
    except Exception as e:
        print(f"[ERROR] Failed to send message to SQS queue {queue_url}: {e}")


def publish_incident_queue(payload: dict) -> None:
    # Cola principal exigida por Variables_Incidentes.docx.
    send_sqs_message(INCIDENT_QUEUE_URL, payload)

    # Fan-out controlado a playbooks de respuesta automatica.
    # Se usan colas dedicadas para que notify-alert y block-ip reciban ambos
    # el mismo evento sin competir por el mensaje SQS.
    #
    # Incidentes con respuesta automatica activa:
    #   BRUTE_FORCE → notify-alert + block-ip  (Incidente 1)
    #   PORT_SCAN   → notify-alert + block-ip  (Incidente 2)
    #   PRIVILEGE_ESCALATION → notify-alert + revoke-credentials (Incidente 3)
    #   CREDENTIAL_LEAK      → notify-alert + revoke-credentials (Incidente 4)
    PLAYBOOK_INCIDENTS = {"BRUTE_FORCE", "PORT_SCAN"}
    if payload.get("incident_type") in PLAYBOOK_INCIDENTS:
        send_sqs_message(PLAYBOOK_NOTIFY_QUEUE_URL, payload)
        send_sqs_message(PLAYBOOK_BLOCK_IP_QUEUE_URL, payload)

    REVOKE_INCIDENTS = {"PRIVILEGE_ESCALATION", "CREDENTIAL_LEAK"}
    if payload.get("incident_type") in REVOKE_INCIDENTS:
        send_sqs_message(PLAYBOOK_NOTIFY_QUEUE_URL, payload)
        send_sqs_message(PLAYBOOK_REVOKE_CREDENTIALS_QUEUE_URL, payload)


def save_incident(payload: dict, source: str, raw_event: dict, summary: str) -> str:
    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}"
    created_at = utc_now()
    created_at_ecuador = ecuador_now()
    evidence_key = build_evidence_key(payload["incident_type"], incident_id)

    final_payload = dict(payload)
    final_payload["incident_id"] = incident_id
    final_payload["timestamp"] = final_payload.get("timestamp") or created_at_ecuador
    final_payload["timestamp_utc"] = final_payload.get("timestamp_utc") or created_at
    final_payload["timestamp_ecuador"] = final_payload.get("timestamp_ecuador") or created_at_ecuador
    final_payload["timezone"] = final_payload.get("timezone") or "America/Guayaquil"
    final_payload["s3_log_key"] = evidence_key
    # Registrar qué playbooks se activan para este incidente
    if final_payload.get("incident_type") in {"BRUTE_FORCE", "PORT_SCAN"}:
        final_payload["playbooks_requested"] = ["notify-alert", "block-ip"]
    elif final_payload.get("incident_type") in {"PRIVILEGE_ESCALATION", "CREDENTIAL_LEAK"}:
        final_payload["playbooks_requested"] = ["notify-alert", "revoke-credentials"]

    evidence_doc = {
        "incident_id": incident_id,
        "incident_payload": final_payload,
        "source": source,
        "summary": summary,
        "created_at": created_at,
        "created_at_ecuador": created_at_ecuador,
        "timezone": "America/Guayaquil",
        "raw_event": raw_event,
    }

    s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=evidence_key,
        Body=json.dumps(evidence_doc, indent=2, default=decimal_default).encode("utf-8"),
        ContentType="application/json",
    )

    incidents_table.put_item(
        Item={
            "incident_id": incident_id,
            "type": final_payload["incident_type"],
            "severity": final_payload["severity"],
            "status": "DETECTED",
            "sourceIPAddress": final_payload.get("sourceIPAddress", "unknown"),
            "affectedResource": final_payload.get("affectedResource", "unknown"),
            "event_count": int(final_payload.get("event_count", 1)),
            "source": source,
            "summary": summary,
            "s3_log_key": evidence_key,
            "evidence_s3_uri": f"s3://{EVIDENCE_BUCKET}/{evidence_key}",
            "created_at": created_at,
            "created_at_ecuador": created_at_ecuador,
            "affected_service": final_payload.get("affected_service", final_payload.get("affectedService", "unknown")),
            "asset_name": final_payload.get("asset_name", final_payload.get("assetName", "unknown")),
            "severity_basis": final_payload.get("severity_basis", "not_specified"),
        }
    )

    publish_incident_queue(final_payload)

    cloudwatch.put_metric_data(
        Namespace="TesisIR",
        MetricData=[
            {
                "MetricName": final_payload["incident_type"],
                "Value": 1,
                "Unit": "Count",
            }
        ],
    )
    return incident_id


def analyze_app_event(event_json: dict, config: dict):
    if event_json.get("event_type") != "login_failed":
        return None

    thresholds = config.get("thresholds", {})
    source_ip = event_json.get("source_ip") or event_json.get("sourceIPAddress") or "unknown"
    username = event_json.get("username", "unknown")
    threshold = int(thresholds.get("app_login_failures_same_ip_5m", 5))
    window = current_window(5)
    count = increment_counter(f"app_bruteforce#{source_ip}#window#{window}", ttl_seconds=900)

    if count >= threshold and mark_alert_once(f"BRUTE_FORCE#APP#{source_ip}#{window}"):
        severity_basis = (
            f"HIGH porque la IP {source_ip} alcanzo {count} intentos fallidos "
            f"en 5 minutos; el umbral configurado para BRUTE_FORCE es {threshold}."
        )
        payload = {
            "incident_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "sourceIPAddress": source_ip,
            "affectedResource": event_json.get("affectedResource") or f"iam:user/{username}",
            "s3_log_key": "pending",
            "timestamp": event_json.get("timestamp") or ecuador_now(),
            "timestamp_utc": event_json.get("timestamp_utc") or utc_now(),
            "timezone": "America/Guayaquil",
            "event_count": count,
            "failed_attempts": count,
            "detection_window": "5 minutes",
            "affected_service": event_json.get("affected_service", "Portal de autenticacion corporativo"),
            "asset_name": event_json.get("asset_name", f"{PORTAL_INSTANCE_ID}"),
            "asset_type": event_json.get("asset_type", "EC2 web application"),
            "severity_basis": severity_basis,
            "mitigation_playbooks": ["notify-alert", "block-ip"],
        }
        return payload, f"{count} intentos fallidos de login del portal desde {source_ip} en 5 minutos."
    return None


def analyze_cloudtrail(event_json: dict, config: dict):
    event_name = event_json.get("eventName")
    event_source = event_json.get("eventSource")
    source_ip = event_json.get("sourceIPAddress", "unknown")
    aws_region = event_json.get("awsRegion", "unknown")
    username = username_from_identity(event_json)
    thresholds = config.get("thresholds", {})
    allowed_ips = config.get("authorized_ips", [])

    # Incidente 1: fuerza bruta por ConsoleLogin fallido.
    if event_name == "ConsoleLogin":
        response = event_json.get("responseElements", {}) or {}
        if response.get("ConsoleLogin") == "Failure":
            threshold_ip = int(thresholds.get("console_login_failures_same_ip_5m", 10))
            threshold_user = int(thresholds.get("console_login_failures_same_user_5m", 5))
            window = current_window(5)
            count_ip = increment_counter(f"console_bruteforce_ip#{source_ip}#window#{window}", ttl_seconds=900)
            count_user = increment_counter(f"console_bruteforce_user#{username}#window#{window}", ttl_seconds=900)
            if count_user >= threshold_user and mark_alert_once(f"BRUTE_FORCE#USER#{username}#{window}"):
                payload = {
                    "incident_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "sourceIPAddress": source_ip,
                    "affectedResource": affected_iam_user(event_json, username),
                    "s3_log_key": "pending",
                    "timestamp": event_json.get("eventTime", utc_now()),
                    "event_count": count_user,
                    "failed_attempts": count_user,
                    "detection_window": "5 minutes",
                    "affected_service": "AWS Sign-In / IAM",
                    "asset_name": "AWS Console",
                    "asset_type": "AWS control plane",
                    "severity_basis": f"HIGH porque se alcanzaron {count_user} fallos de ConsoleLogin para el mismo usuario en 5 minutos.",
                    "mitigation_playbooks": ["notify-alert", "block-ip"],
                }
                return payload, f"{count_user} fallos de ConsoleLogin para {username} en 5 minutos."
            if count_ip >= threshold_ip and mark_alert_once(f"BRUTE_FORCE#IP#{source_ip}#{window}"):
                payload = {
                    "incident_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "sourceIPAddress": source_ip,
                    "affectedResource": affected_iam_user(event_json, username),
                    "s3_log_key": "pending",
                    "timestamp": event_json.get("eventTime", utc_now()),
                    "event_count": count_ip,
                    "failed_attempts": count_ip,
                    "detection_window": "5 minutes",
                    "affected_service": "AWS Sign-In / IAM",
                    "asset_name": "AWS Console",
                    "asset_type": "AWS control plane",
                    "severity_basis": f"HIGH porque se alcanzaron {count_ip} fallos de ConsoleLogin desde la misma IP en 5 minutos.",
                    "mitigation_playbooks": ["notify-alert", "block-ip"],
                }
                return payload, f"{count_ip} fallos de ConsoleLogin desde {source_ip} en 5 minutos."

    # Incidente 3: escalada de privilegios.
    iam_critical_events = {
        "CreateUser",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "AddUserToGroup",
        "CreatePolicyVersion",
        "UpdateAssumeRolePolicy",
    }
    if event_source == "iam.amazonaws.com" and event_name in iam_critical_events:
        request_params = event_json.get("requestParameters", {}) or {}
        target_policy_arn = request_params.get("policyArn") or request_params.get("policyDocument", "")
        window = current_window(5)
        count = increment_counter(f"privilege_escalation#{username}#window#{window}", ttl_seconds=900)
        payload = {
            "incident_type": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "sourceIPAddress": source_ip,
            "affectedResource": affected_iam_user(event_json, username),
            "s3_log_key": "pending",
            "timestamp": event_json.get("eventTime", utc_now()),
            "event_count": count,
            "suspicious_actions": [event_name],
        }
        if target_policy_arn:
            payload["target_policy_arn"] = str(target_policy_arn)[:500]
        return payload, f"Accion IAM critica {event_name} ejecutada por {username} desde {source_ip}."

    # Incidente 4: fuga de credenciales por uso desde IP no autorizada.
    # Se restringe a eventos de identidad/API claramente representativos para reducir falsos positivos.
    credential_leak_events = {"GetCallerIdentity", "GetUser", "ListAccessKeys"}
    identity_type = (event_json.get("userIdentity", {}) or {}).get("type", "")
    if event_name in credential_leak_events and identity_type in {"IAMUser", "AssumedRole"}:
        if source_ip != "unknown" and not ip_in_cidrs(source_ip, allowed_ips):
            if mark_alert_once(f"CREDENTIAL_LEAK#{username}#{source_ip}#{current_window(5)}", ttl_seconds=900):
                payload = {
                    "incident_type": "CREDENTIAL_LEAK",
                    "severity": "CRITICAL",
                    "sourceIPAddress": source_ip,
                    "affectedResource": affected_iam_user(event_json, username),
                    "s3_log_key": "pending",
                    "timestamp": event_json.get("eventTime", utc_now()),
                    "event_count": 1,
                    "service_accessed": event_source,
                    "unusual_region": aws_region,
                }
                return payload, f"Credenciales de {username} usadas desde IP no autorizada {source_ip}."

    # Incidente 5: exfiltracion por muchas descargas GetObject desde una IP en 1 hora.
    if event_source == "s3.amazonaws.com" and event_name == "GetObject":
        request_params = event_json.get("requestParameters", {}) or {}
        bucket = request_params.get("bucketName") or extract_bucket_from_resources(event_json)
        window = current_window(60)
        count = increment_counter(f"exfiltration#{source_ip}#{bucket}#window#{window}", ttl_seconds=7200)
        threshold = int(thresholds.get("s3_getobject_exfiltration_count_1h", 50))
        if count >= threshold and mark_alert_once(f"EXFILTRATION#{source_ip}#{bucket}#{window}", ttl_seconds=7200):
            payload = {
                "incident_type": "EXFILTRATION",
                "severity": "HIGH",
                "sourceIPAddress": source_ip,
                "affectedResource": f"s3:::{bucket}" if bucket else f"ec2:instance/{PORTAL_INSTANCE_ID}",
                "s3_log_key": "pending",
                "timestamp": event_json.get("eventTime", utc_now()),
                "event_count": count,
                "total_downloads": count,
                "affected_bucket": bucket or "unknown",
                "first_access": "tracked_in_detection_window",
                "last_access": event_json.get("eventTime", utc_now()),
            }
            return payload, f"{count} operaciones GetObject desde {source_ip} sobre bucket {bucket} en 1 hora."

    return None


def extract_bucket_from_resources(event_json: dict) -> str:
    resources = event_json.get("resources", []) or []
    for resource in resources:
        arn = resource.get("ARN") or resource.get("arn") or ""
        if arn.startswith("arn:aws:s3:::"):
            value = arn.replace("arn:aws:s3:::", "", 1)
            return value.split("/", 1)[0]
    return "unknown"


def parse_flow_log(message: str):
    parts = message.strip().split()
    if len(parts) < 14:
        return None
    return {
        "version": parts[0],
        "account_id": parts[1],
        "interface_id": parts[2],
        "srcaddr": parts[3],
        "dstaddr": parts[4],
        "srcport": parts[5],
        "dstport": parts[6],
        "protocol": parts[7],
        "packets": parts[8],
        "bytes": parts[9],
        "start": parts[10],
        "end": parts[11],
        "action": parts[12],
        "log_status": parts[13],
        "raw_message": message,
    }


def analyze_flow_log(message: str, config: dict):
    flow = parse_flow_log(message)
    if not flow or flow.get("action") != "REJECT":
        return None

    thresholds = config.get("thresholds", {})
    threshold = int(thresholds.get("port_scan_distinct_ports_5m", 10))
    srcaddr = flow.get("srcaddr", "unknown")
    dstport = flow.get("dstport", "unknown")
    window = current_window(5)
    distinct_count = put_distinct_port_and_count(srcaddr, dstport)
    rejected_count = increment_counter(f"portscan_rejects#{srcaddr}#window#{window}", ttl_seconds=900)

    if distinct_count >= threshold and mark_alert_once(f"PORT_SCAN#{srcaddr}#{window}"):
        payload = {
            "incident_type": "PORT_SCAN",
            "severity": "MEDIUM",
            "sourceIPAddress": srcaddr,
            "affectedResource": f"vpc/{VPC_ID}",
            "s3_log_key": "pending",
            "timestamp": utc_now(),
            "event_count": rejected_count,
            "rejected_connections": rejected_count,
            "scanned_ports_count": distinct_count,
        }
        return payload, f"Posible escaneo: {distinct_count} puertos distintos rechazados desde {srcaddr} en 5 minutos.", flow
    return None


def lambda_handler(event, context):
    config = load_config()
    decoded = decode_cloudwatch_event(event)
    log_group = decoded.get("logGroup", "unknown")
    results = []

    for log_event in decoded.get("logEvents", []):
        raw_message = log_event.get("message", "")
        message_json = safe_json_loads(raw_message)
        analysis = None
        raw_for_evidence = message_json if isinstance(message_json, dict) else {"raw_message": raw_message}

        if isinstance(message_json, dict):
            if "eventSource" in message_json or "eventName" in message_json:
                analysis = analyze_cloudtrail(message_json, config)
            else:
                analysis = analyze_app_event(message_json, config)
        else:
            flow_analysis = analyze_flow_log(raw_message, config)
            if flow_analysis:
                payload, summary, flow = flow_analysis
                analysis = (payload, summary)
                raw_for_evidence = flow

        if analysis:
            payload, summary = analysis
            incident_id = save_incident(
                payload=payload,
                source=log_group,
                raw_event=raw_for_evidence,
                summary=summary,
            )
            results.append(incident_id)

    return {"statusCode": 200, "detected_incidents": results}
