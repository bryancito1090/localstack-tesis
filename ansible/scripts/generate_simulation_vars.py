"""Genera ansible/playbooks/simulations/vars.yml desde outputs de Terraform."""

import json
from pathlib import Path
import subprocess
import sys
import yaml


def main():
    root = Path(__file__).resolve().parents[2]
    tf_dir = root / "terraform-tesis-ir-secure-portal"
    out_file = root / "ansible/playbooks/simulations/vars.yml"
    try:
        raw = subprocess.run(
            ["terraform", f"-chdir={tf_dir}", "output", "-json"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(raw.stdout)
        vars_content = {
            "portal_public_ip": data["portal_public_ip"]["value"],
            "portal_url": data["portal_url"]["value"],
            "aws_region": data["region"]["value"],
            "vpc_id": data["vpc_id"]["value"],
            "nacl_id": data["mitigation_network_acl_id"]["value"],
            "sensitive_bucket": data["sensitive_bucket"]["value"],
            "evidence_bucket": data["evidence_bucket"]["value"],
            "logs_bucket": data["logs_bucket"]["value"],
            "dynamodb_incidents_table": data["dynamodb_incidents_table"]["value"],
            "dynamodb_state_table": data["dynamodb_state_table"]["value"],
            "portal_instance_id": data["portal_instance_id"]["value"],
            "test_iam_username": "tesis-ir-temp-escalation-test",
            "test_escalation_policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "emergency_deny_policy_name": "EmergencyDenyAll",
        }
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("---\n# Variables de simulacion actualizadas automaticamente desde Terraform\n\n")
            yaml.dump(vars_content, f, default_flow_style=False, sort_keys=False)
        print(f"Variables de simulacion actualizadas: {out_file}")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error generando vars.yml: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
