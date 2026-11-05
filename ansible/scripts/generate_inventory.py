"""Genera un inventario YAML (JSON compatible) desde un unico output de Terraform."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def build_inventory(values, connection="ssm", private_key=None):
    required = ["instance_id", "region", "asset_name", "log_group"]
    required += ["ssm_bucket"] if connection == "ssm" else ["public_ip", "ssh_key"]
    for key in required:
        if not isinstance(values.get(key), str) or not values[key].strip():
            raise ValueError(f"Output ansible_portal sin {key}; aplica Terraform y revisa la conexion elegida.")
    host = {"ansible_python_interpreter": "/usr/bin/python3"}
    if connection == "ssm":
        host.update(
            ansible_host=values["instance_id"],
            ansible_connection="amazon.aws.aws_ssm",
            ansible_aws_ssm_region=values["region"],
            ansible_aws_ssm_bucket_name=values["ssm_bucket"],
            ansible_aws_ssm_bucket_sse_mode="AES256",
            ansible_aws_ssm_s3_addressing_style="virtual",
        )
    else:
        host.update(ansible_host=values["public_ip"], ansible_connection="ssh", ansible_user="ec2-user")
        if private_key:
            host["ansible_ssh_private_key_file"] = str(Path(private_key).expanduser().resolve())
    return {
        "all": {
            "children": {
                "portal": {
                    "hosts": {"portal_ec2": host},
                    "vars": {
                        "portal_app_asset_name": values["asset_name"],
                        "cloudwatch_agent_region": values["region"],
                        "cloudwatch_agent_log_group": values["log_group"],
                    },
                }
            }
        }
    }


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform-dir", type=Path, default=root / "terraform-tesis-ir-secure-portal")
    parser.add_argument("--connection", choices=["ssm", "ssh"], default="ssm")
    parser.add_argument("--private-key")
    parser.add_argument("--output", type=Path, default=root / "ansible/inventory/hosts.yml")
    args = parser.parse_args()
    try:
        result = subprocess.run(
            ["terraform", f"-chdir={args.terraform_dir.resolve()}", "output", "-json", "ansible_portal"],
            check=True, capture_output=True, text=True,
        )
        inventory = build_inventory(json.loads(result.stdout), args.connection, args.private_key)
        # La validacion termina antes de tocar un inventario existente.
        args.output.write_text(json.dumps(inventory, indent=2) + "\n")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"No se genero el inventario: {exc}", file=sys.stderr)
        return 1
    print(f"Inventario {args.connection}: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
