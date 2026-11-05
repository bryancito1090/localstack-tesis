# Configuracion del portal EC2

Terraform crea AWS; Ansible instala y mantiene el software en Amazon Linux 2023. Los roles `common`, `portal_app`, `nginx` y `cloudwatch_agent` conservan los eventos que consume el detector. Python escucha en `127.0.0.1:8080`; Nginx atiende el puerto 80 y sobrescribe la IP reenviada para impedir suplantaciones.

## Preparacion

Desde la raiz, con Python 3.12 o 3.13, Terraform y AWS CLI disponibles:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r ansible/requirements.txt
ansible-galaxy collection install -r ansible/requirements.yml
aws sts get-caller-identity
```

Para SSM instala [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html). Las credenciales provienen del perfil AWS local (`AWS_PROFILE` si usas uno con nombre); no se copian al inventario ni al portal.

## Despliegue

```bash
terraform -chdir=terraform-tesis-ir-secure-portal init
terraform -chdir=terraform-tesis-ir-secure-portal plan -out=tfplan
terraform -chdir=terraform-tesis-ir-secure-portal apply tfplan
python ansible/scripts/generate_inventory.py
cd ansible
ansible-inventory --graph
ansible-playbook playbook.yml
# Verificar idempotencia: sin deriva, la segunda ejecucion debe dar changed=0.
ansible-playbook playbook.yml
```

El generador lee exclusivamente `terraform output -json ansible_portal`; no exporta el estado ni salidas sensibles. El inventario local se excluye de Git. Regeneralo tras reemplazar EC2 o cambiar region/proyecto. La IP publica puede cambiar al detener/iniciar la instancia.

El playbook espera la conexion y cloud-init, comprueba Amazon Linux 2023, instala los servicios y verifica `/health` a traves de Nginx. Los cambios posteriores se aplican repitiendo Ansible, sin reemplazar EC2. El secreto de sesion se crea solo una vez; el codigo pertenece a root y el servicio solo escribe en su directorio de logs.

### SSM (predeterminado)

No requiere llave SSH. EC2 debe aparecer `Online` en Systems Manager y tener salida HTTPS a SSM, `ssmmessages` y S3. El bootstrap inicia `amazon-ssm-agent`; Terraform ya asocia `AmazonSSMManagedInstanceCore`. Elegir SSM no modifica la regla SSH existente del Security Group.

El plugin [amazon.aws.aws_ssm](https://docs.ansible.com/projects/ansible/latest/collections/amazon/aws/aws_ssm_connection.html) transfiere modulos por S3 con URLs prefirmadas. Terraform crea `${project_name}-ansible-${account_id}-${region}`, separado de evidencia, con bloqueo publico, ACL desactivadas, SSE-S3 y expiracion de un dia como respaldo a la eliminacion del plugin. No habilites versionado: los modulos pueden contener datos sensibles. Almacenamiento y solicitudes generan cargos segun uso ([precios S3](https://aws.amazon.com/s3/pricing/)).

El operador necesita permisos de sesiones SSM sobre la instancia (`ssm:StartSession`, `ssm:ResumeSession`, `ssm:TerminateSession` y el documento de sesion usado), y `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`, `s3:GetBucketLocation` limitados al bucket de transferencias. EC2 usa las URLs prefirmadas y no necesita permisos S3 adicionales. El rol del portal no se amplia.

```bash
aws ssm describe-instance-information --region us-east-2
aws ssm start-session --target INSTANCE_ID --region us-east-2
```

### SSH alternativo

Define `key_name` en Terraform con una key pair existente y `ssh_allowed_cidr` con la IP del controlador `/32`. Conserva la llave privada fuera del repositorio. Verifica la huella del host por un canal confiable, por ejemplo SSM, y registrala en `~/.ssh/known_hosts`; la comprobacion de claves de host permanece activa.

```bash
python ansible/scripts/generate_inventory.py --connection ssh --private-key ~/.ssh/tesis.pem
cd ansible
ansible-playbook playbook.yml
```

Puedes omitir `--private-key` si usas `ssh-agent`. Para inventario manual usa `inventory/hosts.example.yml` como referencia y seleccionalo con `-i`.

## Migracion desde user_data

El script anterior instalaba todo; ahora solo prepara Python, curl y SSM. Con `user_data_replace_on_change=true`, **el primer plan de esta migracion propone reemplazar EC2**: revisa el plan, programa la interrupcion y conserva los logs locales necesarios. La instancia nueva no tendra portal hasta ejecutar Ansible. Los logs ya enviados a CloudWatch permanecen en su grupo administrado por Terraform.

Puedes configurar primero una EC2 existente usando un inventario manual por SSH, o SSM con un bucket de transferencias ya preparado. Ansible conserva el `session_secret` existente. No cambies la politica de reemplazo para ocultar el efecto de la migracion sin revisar el ciclo de vida de la instancia.

## Operacion y evidencia

```bash
# Desde ansible/, sobre una instancia ya configurada:
ansible-playbook playbook.yml --check --diff
ansible portal -b -m ansible.builtin.command -a 'systemctl status tesis-portal nginx amazon-cloudwatch-agent --no-pager'
ansible portal -b -m ansible.builtin.command -a 'journalctl -u tesis-portal -n 30 --no-pager'
ansible portal -b -m ansible.builtin.command -a 'tail -n 10 /var/log/tesis-portal/app.log'
```

`--check` revisa deriva en hosts existentes; no sustituye el primer despliegue donde faltan usuarios, archivos y servicios. La actualizacion global de paquetes es optativa: `ansible-playbook playbook.yml -e common_upgrade_packages=true`; revisa si despues se requiere reiniciar EC2.

La rotacion local es diaria, conserva siete archivos y evalua el limite de 10 MB al ejecutarse logrotate. CloudWatch envia `{instance_id}/app`, `/nginx-access` y `/nginx-error` al grupo exportado por Terraform. La [configuracion del agente](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html) contiene solo logs; la retencion del grupo sigue en Terraform.

```bash
# Desde la raiz; ajustar --region al output region.
PORTAL_IP=$(terraform -chdir=terraform-tesis-ir-secure-portal output -raw portal_public_ip)
curl --fail "http://$PORTAL_IP/health"
LOG_GROUP=$(terraform -chdir=terraform-tesis-ir-secure-portal output -raw ec2_app_log_group)
aws logs tail "$LOG_GROUP" --since 10m --follow --region us-east-2
```

Para verificar la cadena completa sigue [las pruebas de incidentes](../terraform-tesis-ir-secure-portal/GUIA_PRUEBAS_INCIDENTES.md) y conserva evidencia de CloudWatch, Lambda, SQS y mitigacion. La fuerza bruta puede bloquear la IP de prueba en la NACL.

## Validacion sin AWS

```bash
cd ansible
ansible-playbook -i inventory/hosts.example.yml playbook.yml --syntax-check
ansible-lint playbook.yml
cd ..
python -m unittest discover -s tests -v
terraform -chdir=terraform-tesis-ir-secure-portal fmt -check
terraform -chdir=terraform-tesis-ir-secure-portal init -backend=false -input=false
terraform -chdir=terraform-tesis-ir-secure-portal validate
```

CI comprueba sintaxis, lint, contrato HTTP/eventos, inventario, reglas de PR, Terraform y secretos. La idempotencia remota y la entrega real a CloudWatch se verifican con las ejecuciones operativas anteriores.
