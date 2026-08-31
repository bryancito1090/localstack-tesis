"""
Playbook: block-ip
Mitigacion de contención real para incidentes de red.
Bloquea la IP origen creando una regla DENY inbound en la Network ACL
objetivo y registra evidencia de respuesta en S3.

Incidentes soportados:
  - BRUTE_FORCE  (severity HIGH)   → Incidente 1
  - PORT_SCAN    (severity MEDIUM) → Incidente 2

Punto de cumplimiento (enforcement point):
  ec2.create_network_acl_entry(RuleAction="deny", Egress=False, CidrBlock=IP/32)
  Esa es la linea exacta donde el trafico de la IP atacante queda bloqueado
  a nivel de red en la VPC.

  Las NACLs evaluan reglas de menor a mayor numero; el DENY se inserta con
  numero < 100, por debajo del ALLOW por defecto (nro 100), por eso el bloqueo
  es efectivo y no cosmetico.
"""
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

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
SNS_ARN         = os.environ["SNS_ALERTS_ARN"]
TARGET_NACL_ID  = os.environ["TARGET_NACL_ID"]
RESPONSE_PREFIX = os.environ.get("RESPONSE_PREFIX", "responses/block-ip")
RULE_MIN        = int(os.environ.get("RULE_MIN", "1"))
RULE_MAX        = int(os.environ.get("RULE_MAX", "99"))
EC_TZ           = ZoneInfo("America/Guayaquil")

# Incidentes que activan el bloqueo de IP en NACL.
BLOCK_INCIDENT_TYPES = {"BRUTE_FORCE", "PORT_SCAN"}


def now_ecuador() -> str:
    return datetime.now(EC_TZ).isoformat()


def valid_public_ip(ip_value: str) -> bool:
    """Verifica que la IP sea publica y valida antes de aplicar el bloqueo."""
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_multicast
        or ip.is_unspecified or ip.is_reserved
    )


def next_rule_number(nacl_id: str) -> int:
    """Calcula el siguiente numero de regla libre en el rango DENY (1-99)."""
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
    """
    ENFORCEMENT POINT: crea la regla DENY en la NACL.
    Es idempotente: si el DENY ya existe devuelve already_present=True.
    """
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
    # ← línea exacta del bloqueo real a nivel de red
    ec2.create_network_acl_entry(
        NetworkAclId=TARGET_NACL_ID,
        RuleNumber=rule_number,
        Protocol="-1",       # todos los protocolos
        RuleAction="deny",
        Egress=False,        # tráfico de entrada (desde el atacante)
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

        # Solo procesar incidentes de red que requieren bloqueo de IP
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

        # Campos extra según el tipo de incidente
        if incident_type == "PORT_SCAN":
            entry["scanned_ports_count"]  = body.get("scanned_ports_count",
                                                       body.get("event_count", 0))
            entry["rejected_connections"] = body.get("rejected_connections", 0)
        elif incident_type == "BRUTE_FORCE":
            entry["failed_attempts"]      = body.get("failed_attempts",
                                                       body.get("event_count", 0))

        # ── Actualizar lista de IPs bloqueadas (blocklist acumulativo) ─────
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

        # ── Notificar al equipo via SNS ────────────────────────────────────
        subject = f"[{entry['severity']}] Mitigacion: IP {ip_value} {status} en NACL"
        mitigation_report = f"""
[MITIGACION DE SEGURIDAD AWS] - ACCION: {status}
==================================================
Playbook          : block-ip
Tipo de Incidente : {incident_type}
ID de Incidente   : {entry['incident_id']}
Estado            : {status}
--------------------------------------------------
IP Objetivo       : {ip_value}
Network ACL       : {enforcement.get('network_acl_id', 'N/A')}
Regla Creada      : #{enforcement.get('rule_number', 'N/A')}
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
