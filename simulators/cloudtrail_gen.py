"""
Generador de eventos CloudTrail simulados.
Produce logs JSON con la estructura real de CloudTrail para probar
los componentes de Detección (B) y Respuesta (C) sin depender de AWS real.
"""
import json
import random
import uuid
from datetime import datetime, timezone, timedelta


USERS = ["admin", "dev-operator", "ci-runner", "readonly-audit", "external-contractor"]
REGIONS = ["us-east-1", "us-west-2"]
IPS_LEGIT  = ["10.0.1.15", "10.0.2.30", "192.168.1.100"]
IPS_ATTACK = ["203.0.113.42", "198.51.100.77", "185.220.101.5", "45.33.32.156"]


def _base_event(username: str, source_ip: str, event_name: str, event_source: str) -> dict:
    return {
        "eventVersion":  "1.08",
        "eventTime":     datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "eventSource":   event_source,
        "eventName":     event_name,
        "awsRegion":     random.choice(REGIONS),
        "sourceIPAddress": source_ip,
        "userAgent":     "aws-cli/2.x Python/3.11",
        "requestID":     str(uuid.uuid4()),
        "eventID":       str(uuid.uuid4()),
        "readOnly":      False,
        "userIdentity": {
            "type":     "IAMUser",
            "userName": username,
            "arn":      f"arn:aws:iam::123456789012:user/{username}",
            "accountId": "123456789012"
        }
    }


def brute_force(attempts: int = 10, target_user: str = None) -> list[dict]:
    """Genera múltiples intentos fallidos de login (simula fuerza bruta)."""
    user   = target_user or random.choice(USERS)
    ip     = random.choice(IPS_ATTACK)
    events = []
    base_time = datetime.now(timezone.utc)

    for i in range(attempts):
        e = _base_event(user, ip, "ConsoleLogin", "signin.amazonaws.com")
        e["eventTime"] = (base_time + timedelta(seconds=i * 15)).isoformat().replace("+00:00", "Z")
        e["responseElements"] = {"ConsoleLogin": "Failure"}
        e["errorCode"]    = "AccessDenied"
        e["errorMessage"] = "Failed authentication"
        events.append(e)

    return events


def privilege_escalation(username: str = None) -> list[dict]:
    """Genera eventos de escalada de privilegios: un usuario adjunta políticas de admin."""
    user   = username or random.choice(USERS)
    ip     = random.choice(IPS_ATTACK)
    events = []

    # Intento de listar roles (reconocimiento)
    e = _base_event(user, ip, "ListRoles", "iam.amazonaws.com")
    e["readOnly"] = True
    events.append(e)

    # Adjuntar política AdministratorAccess a sí mismo
    e = _base_event(user, ip, "AttachUserPolicy", "iam.amazonaws.com")
    e["requestParameters"] = {
        "userName":  user,
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
    events.append(e)

    # Crear nueva access key para persistencia
    e = _base_event(user, ip, "CreateAccessKey", "iam.amazonaws.com")
    e["requestParameters"] = {"userName": user}
    e["responseElements"]  = {
        "accessKey": {
            "accessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
            "status": "Active",
            "userName": user
        }
    }
    events.append(e)

    return events


def credential_leak(username: str = None) -> list[dict]:
    """Simula uso de credenciales desde IP externa inusual (posible filtración)."""
    user = username or random.choice(USERS)
    ip   = random.choice(IPS_ATTACK)

    e = _base_event(user, ip, "GetCallerIdentity", "sts.amazonaws.com")
    e["readOnly"] = True
    e["requestParameters"] = None
    e["responseElements"]  = {
        "userId":  f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
        "account": "123456789012",
        "arn":     f"arn:aws:iam::123456789012:user/{user}"
    }
    return [e]


def exfiltration(bucket: str = "prod-data-bucket", files: int = 50) -> list[dict]:
    """Genera muchos GetObject consecutivos desde la misma IP (exfiltración de datos)."""
    user   = random.choice(USERS)
    ip     = random.choice(IPS_ATTACK)
    events = []

    for i in range(files):
        e = _base_event(user, ip, "GetObject", "s3.amazonaws.com")
        e["readOnly"] = True
        e["resources"] = [{
            "ARN":       f"arn:aws:s3:::{bucket}/data/record_{i:04d}.json",
            "accountId": "123456789012",
            "type":      "AWS::S3::Object"
        }]
        events.append(e)

    return events


def port_scan(source_ip: str = None) -> list[dict]:
    """Simula un evento de reconocimiento (DescribeSecurityGroups masivo)."""
    user = random.choice(USERS)
    ip   = source_ip or random.choice(IPS_ATTACK)
    events = []

    for action in ["DescribeSecurityGroups", "DescribeInstances", "DescribeSubnets",
                   "DescribeVpcs", "DescribeNetworkInterfaces"]:
        e = _base_event(user, ip, action, "ec2.amazonaws.com")
        e["readOnly"] = True
        events.append(e)

    return events


GENERATORS = {
    "brute-force":          brute_force,
    "privilege-escalation": privilege_escalation,
    "credential-leak":      credential_leak,
    "exfiltration":         exfiltration,
    "port-scan":            port_scan,
}


if __name__ == "__main__":
    import sys
    incident = sys.argv[1] if len(sys.argv) > 1 else "brute-force"
    gen = GENERATORS.get(incident)
    if not gen:
        print(f"Tipos disponibles: {', '.join(GENERATORS)}", file=sys.stderr)
        sys.exit(1)

    events = gen()
    print(json.dumps(events, indent=2))
