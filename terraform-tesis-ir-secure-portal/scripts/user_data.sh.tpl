#!/bin/bash
set -euo pipefail

# Solo bootstrap: la configuracion del portal pertenece a Ansible.
dnf install -y python3 curl amazon-ssm-agent
systemctl enable --now amazon-ssm-agent
