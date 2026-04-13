#!/usr/bin/env bash
# Activa el entorno de desarrollo local de la tesis
# Uso: source activate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/.venv/bin/activate"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566

echo "Entorno de tesis activado."
echo "  awslocal → $(which awslocal)"
echo "  python3  → $(which python3)"
echo "  endpoint → $AWS_ENDPOINT_URL"
