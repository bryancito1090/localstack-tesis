variable "aws_region" {
  description = "Region AWS. Use ca-central-1 si quieres mantener la region que venias usando, o us-east-1 si seguiras exactamente el documento base."
  type        = string
  default     = "ca-central-1"
}

variable "project_name" {
  description = "Prefijo de nombres para todos los recursos. Usa solo minusculas, numeros y guiones."
  type        = string
  default     = "tesis-ir"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "project_name solo puede tener minusculas, numeros y guiones."
  }
}

variable "ssh_allowed_cidr" {
  description = "Tu IP publica en formato CIDR para SSH. Ejemplo: 181.39.10.20/32. No uses 0.0.0.0/0."
  type        = string

  validation {
    condition     = can(cidrhost(var.ssh_allowed_cidr, 0)) && var.ssh_allowed_cidr != "0.0.0.0/0"
    error_message = "ssh_allowed_cidr debe ser un CIDR valido y no debe ser 0.0.0.0/0."
  }
}

variable "http_allowed_cidrs" {
  description = "CIDRs permitidos para HTTP del portal. Si queda vacio, se usa ssh_allowed_cidr. Para demo publica podrias usar 0.0.0.0/0, pero no es lo recomendado."
  type        = list(string)
  default     = []
}

variable "authorized_ip_cidrs" {
  description = "IPs autorizadas para la logica del detector. Si queda vacio, se usa ssh_allowed_cidr."
  type        = list(string)
  default     = []
}

variable "authorized_admin_users" {
  description = "Usuarios autorizados usados en config/authorized_ips.json."
  type        = list(string)
  default     = ["tesis-admin", "estudiante-b"]
}

variable "alert_email" {
  description = "Correo para SNS y presupuesto. Si lo dejas vacio, no se crea suscripcion email ni budget."
  type        = string
  default     = ""
}

variable "create_budget" {
  description = "Crear un presupuesto mensual con alertas si alert_email no esta vacio."
  type        = bool
  default     = true
}

variable "monthly_budget_limit_usd" {
  description = "Monto del budget mensual."
  type        = number
  default     = 5
}

variable "vpc_cidr" {
  description = "CIDR de la VPC."
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_a_cidr" {
  description = "CIDR subred publica A."
  type        = string
  default     = "10.10.1.0/24"
}

variable "public_subnet_b_cidr" {
  description = "CIDR subred publica B."
  type        = string
  default     = "10.10.2.0/24"
}

variable "private_subnet_a_cidr" {
  description = "CIDR subred privada A reservada."
  type        = string
  default     = "10.10.11.0/24"
}

variable "private_subnet_b_cidr" {
  description = "CIDR subred privada B reservada."
  type        = string
  default     = "10.10.12.0/24"
}

variable "portal_private_ip" {
  description = "IP privada fija para la EC2 dentro de la subred publica A."
  type        = string
  default     = "10.10.1.10"
}

variable "ec2_instance_type" {
  description = "Tipo de instancia. En ca-central-1 muchas cuentas usan t3.micro como elegible Free Tier; valida con aws ec2 describe-instance-types."
  type        = string
  default     = "t3.micro"
}

variable "ec2_volume_size_gb" {
  description = "Tamaño EBS gp3 de la EC2."
  type        = number
  default     = 8
}

variable "key_name" {
  description = "Nombre de una key pair existente para SSH. Si queda vacio, usa Session Manager en lugar de SSH tradicional."
  type        = string
  default     = ""
}

variable "cloudwatch_retention_days" {
  description = "Retencion de logs en CloudWatch para reducir costos."
  type        = number
  default     = 14
}

variable "normalized_log_retention_days" {
  description = "Retencion del log group normalizado de incidentes."
  type        = number
  default     = 30
}

variable "force_destroy_buckets" {
  description = "Permite destruir buckets con objetos al ejecutar terraform destroy. Para laboratorio es practico; para evidencia real usa false."
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Activa VPC Flow Logs sobre la ENI de la EC2."
  type        = bool
  default     = true
}

variable "cloudtrail_multi_region" {
  description = "Trail multi-region. Para bajo costo/logs reducidos se deja false."
  type        = bool
  default     = false
}

variable "enable_s3_data_events" {
  description = "Activa CloudTrail Data Events sobre el prefijo sensible del bucket demo. Puede generar cargos; activalo solo para la prueba del incidente 5."
  type        = bool
  default     = false
}

variable "enable_aws_config" {
  description = "Activa AWS Config y una regla administrada. Puede generar cargos; activalo solo cuando pruebes cambios de configuracion."
  type        = bool
  default     = false
}

variable "config_resource_types" {
  description = "Tipos de recursos monitoreados por AWS Config cuando enable_aws_config=true."
  type        = list(string)
  default = [
    "AWS::IAM::User",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::NetworkAcl",
    "AWS::EC2::Instance",
    "AWS::S3::Bucket"
  ]
}

variable "create_test_iam_user" {
  description = "Crea un usuario IAM de laboratorio sin claves ni password de consola."
  type        = bool
  default     = true
}

variable "threshold_console_login_failures_same_user_5m" {
  description = "Umbral de fallos ConsoleLogin por usuario en 5 minutos."
  type        = number
  default     = 5
}

variable "threshold_console_login_failures_same_ip_5m" {
  description = "Umbral de fallos ConsoleLogin por IP en 5 minutos."
  type        = number
  default     = 10
}

variable "threshold_app_login_failures_same_ip_5m" {
  description = "Umbral de login_failed del portal por IP en 5 minutos."
  type        = number
  default     = 5
}

variable "threshold_port_scan_distinct_ports_5m" {
  description = "Puertos distintos rechazados desde una misma IP en 5 minutos."
  type        = number
  default     = 10
}

variable "threshold_s3_getobject_unusual_count_5m" {
  description = "Umbral de accesos S3 GetObject/ListBucket inusuales en 5 minutos."
  type        = number
  default     = 10
}

variable "threshold_s3_getobject_exfiltration_count_1h" {
  description = "Umbral de GetObject desde la misma IP en 1 hora para EXFILTRATION, segun Variables_Incidentes.docx."
  type        = number
  default     = 50
}
