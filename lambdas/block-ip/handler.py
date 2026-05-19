"""
Playbook: block-ip
Acción de contención REAL ante una IP atacante.

Punto de cumplimiento (enforcement point):
  Se añade una regla DENY a la Network ACL de la VPC mediante
  ec2.create_network_acl_entry(). Esa es la línea donde el tráfico
  de la IP del atacante queda efectivamente denegado a nivel de red.

Detalle AWS clave: una NACL evalúa reglas por número, de menor a mayor,
y la primera coincidencia gana. La NACL por defecto trae una regla
ALLOW (nº 100). Por eso la regla DENY debe llevar un número MENOR a 100
(rango 1-99); si fuera mayor, el ALLOW 100 ganaría y el bloqueo no surtiría
efecto. Esto es lo que demuestra que el bloqueo es real y no cosmético.

El registro en S3 (responses/blocked-ips.json) se mantiene como PISTA DE
AUDITORÍA / evidencia de mitigación, alineado con el prefijo `responses/`
del esquema de almacenamiento del Componente A.
"""
import json
import os
import boto3
from datetime import datetime, timezone

_ls_host = os.environ.get("LOCALSTACK_HOSTNAME", "localhost")
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", f"http://{_ls_host}:4566")
REGION   = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
BUCKET   = os.environ.get("S3_BUCKET", "tesis-security-logs")
SNS_ARN  = os.environ.get("SNS_ALERTS_ARN", "arn:aws:sns:us-east-1:000000000000:tesis-security-alerts")
# Permite forzar una NACL concreta; si no, se usa la NACL por defecto de la VPC por defecto.
TARGET_NACL_ID = os.environ.get("TARGET_NACL_ID", "")

# Rango de números de regla reservado para los bloqueos de este playbook.
# Debe quedar por DEBAJO de la regla ALLOW por defecto (nº 100) para que el
# DENY se evalúe primero y el bloqueo sea efectivo.
RULE_MIN = 1
RULE_MAX = 99

s3  = boto3.client("s3",  endpoint_url=ENDPOINT, region_name=REGION)
sns = boto3.client("sns", endpoint_url=ENDPOINT, region_name=REGION)
ec2 = boto3.client("ec2", endpoint_url=ENDPOINT, region_name=REGION)


def _load_blocklist() -> list:
    try:
        obj = s3.get_object(Bucket=BUCKET, Key="responses/blocked-ips.json")
        return json.loads(obj["Body"].read())
    except s3.exceptions.NoSuchKey:
        return []
    except Exception:
        return []


def _resolve_target_nacl() -> str:
    """Devuelve el Network ACL ID donde se aplicará el bloqueo."""
    if TARGET_NACL_ID:
        return TARGET_NACL_ID
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])
    if not vpcs:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
    if not vpcs:
        raise RuntimeError("No hay ninguna VPC disponible para aplicar la NACL")
    vpc_id = vpcs[0]["VpcId"]
    acls = ec2.describe_network_acls(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "default", "Values": ["true"]}]
    ).get("NetworkAcls", [])
    if not acls:
        acls = ec2.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("NetworkAcls", [])
    if not acls:
        raise RuntimeError(f"La VPC {vpc_id} no tiene Network ACLs")
    return acls[0]["NetworkAclId"]


def _next_rule_number(nacl_id: str) -> int:
    """Calcula el siguiente número de regla libre en el rango DENY (1-99)."""
    acls = ec2.describe_network_acls(NetworkAclIds=[nacl_id]).get("NetworkAcls", [])
    used = set()
    if acls:
        for entry in acls[0].get("Entries", []):
            if not entry["Egress"]:
                used.add(entry["RuleNumber"])
    for n in range(RULE_MIN, RULE_MAX + 1):
        if n not in used:
            return n
    raise RuntimeError("No quedan números de regla libres en el rango DENY (1-99)")


def _block_ip_on_network(ip: str) -> dict:
    """
    PUNTO DE CUMPLIMIENTO REAL.
    Añade una regla DENY de entrada para la IP del atacante en la NACL.
    """
    cidr = f"{ip}/32"
    nacl_id = _resolve_target_nacl()

    # Idempotencia: ¿ya existe el DENY para este CIDR?
    acls = ec2.describe_network_acls(NetworkAclIds=[nacl_id]).get("NetworkAcls", [])
    for entry in (acls[0].get("Entries", []) if acls else []):
        if (not entry["Egress"]
                and entry.get("CidrBlock") == cidr
                and entry.get("RuleAction") == "deny"):
            return {
                "enforced": True,
                "already_present": True,
                "network_acl_id": nacl_id,
                "rule_number": entry["RuleNumber"],
                "cidr": cidr,
            }

    rule_number = _next_rule_number(nacl_id)
    # ── Línea exacta donde la IP del atacante queda bloqueada a nivel de red ──
    ec2.create_network_acl_entry(
        NetworkAclId=nacl_id,
        RuleNumber=rule_number,
        Protocol="-1",            # -1 = todos los protocolos
        RuleAction="deny",
        Egress=False,             # tráfico de ENTRADA (desde el atacante)
        CidrBlock=cidr,
    )
    print(f"[block-ip] NACL {nacl_id}: regla DENY #{rule_number} creada para {cidr}")
    return {
        "enforced": True,
        "already_present": False,
        "network_acl_id": nacl_id,
        "rule_number": rule_number,
        "cidr": cidr,
    }


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "error", "detail": f"Payload inválido: {e}"}

        ip            = body.get("sourceIPAddress", "0.0.0.0")
        incident_type = body.get("incident_type", "UNKNOWN")
        severity      = body.get("severity", "MEDIUM")
        timestamp     = datetime.now(timezone.utc).isoformat()

        # 1. CUMPLIMIENTO REAL: bloquear la IP en la red (Network ACL DENY)
        try:
            enforcement = _block_ip_on_network(ip)
        except Exception as e:
            enforcement = {"enforced": False, "error": str(e)}
            print(f"[block-ip] ERROR aplicando bloqueo de red para {ip}: {e}")

        # 2. AUDITORÍA: registrar la evidencia de mitigación en S3 (prefijo responses/)
        blocklist = _load_blocklist()
        entry = {
            "ip":               ip,
            "blocked_at":       timestamp,
            "reason":           incident_type,
            "severity":         severity,
            "affectedResource": body.get("affectedResource", ""),
            "enforcement":      enforcement,
        }
        if not any(e["ip"] == ip for e in blocklist):
            blocklist.append(entry)
            action = "ip_blocked" if enforcement.get("enforced") else "ip_block_failed"
        else:
            action = "ip_already_blocked"
            print(f"[block-ip] IP {ip} ya estaba en el blocklist de auditoría")
        s3.put_object(
            Bucket=BUCKET,
            Key="responses/blocked-ips.json",
            Body=json.dumps(blocklist, indent=2).encode(),
            ContentType="application/json",
        )

        # 3. Notificar al equipo
        status = "BLOCKED" if enforcement.get("enforced") else "BLOCK_FAILED"
        result = {
            "playbook":     "block-ip",
            "action":       action,
            "ip":           ip,
            "status":       status,
            "enforcement":  enforcement,
            "timestamp":    timestamp,
        }
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"[{severity}] IP bloqueada: {ip}"[:100],
            Message=json.dumps(result, indent=2),
        )

        results.append({"status": "success", "action": action, "details": result})

    return {
        "status":    "success",
        "processed": len(results),
        "results":   results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
