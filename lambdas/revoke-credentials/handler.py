"""
Playbook: revoke-credentials
Revoca (desactiva) las access keys de un usuario IAM comprometido
y adjunta una política de denegación explícita para bloqueo inmediato.
"""
import json
import os
import boto3
from datetime import datetime, timezone

ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
REGION   = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

iam = boto3.client("iam", endpoint_url=ENDPOINT, region_name=REGION)
sns = boto3.client("sns", endpoint_url=ENDPOINT, region_name=REGION)
SNS_ARN = os.environ.get("SNS_ALERTS_ARN", "arn:aws:sns:us-east-1:000000000000:tesis-security-alerts")

DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
    }]
})


def lambda_handler(event, context):
    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
        except (KeyError, json.JSONDecodeError) as e:
            return {"status": "error", "detail": f"Payload inválido: {e}"}

        username = body.get("affectedResource", "").replace("iam:user/", "")
        if not username:
            return {"status": "error", "detail": "affectedResource no contiene usuario IAM"}

        actions_taken = []

        # 1. Listar y desactivar todas las access keys del usuario
        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        for key in keys:
            kid = key["AccessKeyId"]
            iam.update_access_key(UserName=username, AccessKeyId=kid, Status="Inactive")
            actions_taken.append(f"AccessKey desactivada: {kid}")
            print(f"[revoke-credentials] Desactivada key {kid} de usuario {username}")

        # 2. Adjuntar política de Deny-All como medida de contención
        iam.put_user_policy(
            UserName=username,
            PolicyName="EmergencyDenyAll",
            PolicyDocument=DENY_ALL_POLICY
        )
        actions_taken.append("Política EmergencyDenyAll adjuntada")
        print(f"[revoke-credentials] DenyAll aplicado al usuario {username}")

        # 3. Notificar al equipo
        result = {
            "playbook":  "revoke-credentials",
            "username":  username,
            "actions":   actions_taken,
            "status":    "CONTAINED",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"[RESPUESTA] Credenciales revocadas: {username}",
            Message=json.dumps(result, indent=2)
        )

        return {"status": "success", "action": "credentials_revoked", "details": result,
                "timestamp": datetime.now(timezone.utc).isoformat()}
