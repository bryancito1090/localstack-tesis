# Suite de Simulaciones Red Team y Rollback Automatizado (Ansible)

Esta suite automatiza la generación de ataques controlados para validar de forma integral el pipeline de **Detección y Respuesta Automatizada ante Incidentes en AWS** (TIC Tesis), permitiendo simular los 5 incidentes soportados y restaurar el laboratorio a su estado base (*Zero-State*) con un solo comando.

---

## 1. Inventario de Playbooks de Simulación

| Playbook | Incidente Validado | Severidad | Mitigación Automatizada Probada | Canales |
|---|---|---|---|---|
| `01_brute_force.yml` | `BRUTE_FORCE` | `HIGH` | Bloqueo IP en Network ACL (Ingress DENY) + Lockout 403 en Portal | SES (Gmail) + Telegram |
| `02_port_scan.yml` | `PORT_SCAN` | `MEDIUM` | Detección de `REJECT` en VPC Flow Logs + Bloqueo IP en Network ACL | SES (Gmail) + Telegram |
| `03_privilege_escalation.yml` | `PRIVILEGE_ESCALATION` | `CRITICAL` | Desactivación de claves IAM + Adjunta `EmergencyDenyAll` | SES (Gmail) + Telegram |
| `04_credential_leak.yml` | `CREDENTIAL_LEAK` | `CRITICAL` | Validación de IP autorizada + Inactivación de credenciales | SES (Gmail) + Telegram |
| `05_s3_exfiltration.yml` | `EXFILTRATION` | `HIGH` | Detección de tasa de `GetObject` (>50/h) en CloudTrail Data Events | SES (Gmail) + Telegram |
| `rollback_cleanup.yml` | **Restauración** | — | Limpia reglas DENY en NACL, retira `EmergencyDenyAll` y reinicia memoria del portal | Consola / Logs |
| `run_all.yml` | **Suite Completa** | — | Orquestador maestro para correr las 5 simulaciones y el rollback con tags | Todos |

---

## 2. Requisitos Previos

1. Contar con credenciales de AWS configuradas en la terminal (ejecutar `aws sts get-caller-identity`).
2. Entorno virtual activo con Ansible y colecciones de AWS:
   ```bash
   source .venv/bin/activate
   ```

---

## 3. Modo de Uso

### A. Simular Fuerza Bruta (`BRUTE_FORCE`)
Dispara 5 intentos con contraseñas inválidas contra `/login`, comprueba la respuesta defensiva `403 Bloqueado` y verifica la regla de bloqueo en la Network ACL:
```bash
ansible-playbook ansible/playbooks/simulations/01_brute_force.yml
```

### B. Simular Escaneo de Puertos (`PORT_SCAN`)
Envía paquetes TCP hacia puertos cerrados (81 a 92) forzando registros `REJECT` en VPC Flow Logs:
```bash
ansible-playbook ansible/playbooks/simulations/02_port_scan.yml
```

### C. Simular Escalada de Privilegios (`PRIVILEGE_ESCALATION`)
Crea el usuario temporal `tesis-ir-temp-escalation-test` y adjunta una política administrativa para gatillar la revocación automática:
```bash
ansible-playbook ansible/playbooks/simulations/03_privilege_escalation.yml
```

### D. Simular Fuga de Credenciales (`CREDENTIAL_LEAK`)
Ejecuta la verificación de llamadas API desde origen no autorizado:
```bash
ansible-playbook ansible/playbooks/simulations/04_credential_leak.yml
```

### E. Simular Exfiltración en S3 (`EXFILTRATION`)
Ejecuta una ráfaga de 55 descargas sobre el bucket confidencial:
```bash
ansible-playbook ansible/playbooks/simulations/05_s3_exfiltration.yml
```

### F. Restauración y Limpieza del Laboratorio (*Rollback Zero-State*)
Elimina las reglas de bloqueo en Network ACL, remueve usuarios y políticas temporales de contención en IAM, y reinicia la memoria del portal web para dejar el entorno 100% limpio y listo para una nueva demostración:
```bash
ansible-playbook ansible/playbooks/simulations/rollback_cleanup.yml
```
