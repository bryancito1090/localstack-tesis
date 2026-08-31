terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "lab"
      ManagedBy   = "terraform"
      Owner       = "estudiante-b"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  account_id = data.aws_caller_identity.current.account_id

  name_prefix = var.project_name

  az_1 = data.aws_availability_zones.available.names[0]
  az_2 = data.aws_availability_zones.available.names[1]

  logs_bucket_name      = "${var.project_name}-logs-${local.account_id}-${var.aws_region}"
  evidence_bucket_name  = "${var.project_name}-evidence-${local.account_id}-${var.aws_region}"
  sensitive_bucket_name = "${var.project_name}-sensitive-data-${local.account_id}-${var.aws_region}"

  authorized_ip_cidrs = length(var.authorized_ip_cidrs) > 0 ? var.authorized_ip_cidrs : [var.ssh_allowed_cidr]
  portal_http_cidrs  = length(var.http_allowed_cidrs) > 0 ? var.http_allowed_cidrs : [var.ssh_allowed_cidr]

  common_log_groups = {
    cloudtrail = "/aws/cloudtrail/${var.project_name}-management"
    flowlogs   = "/aws/vpc/${var.project_name}-flowlogs"
    config     = "/aws/config/${var.project_name}-changes"
    app        = "/aws/ec2/${var.project_name}-portal-app"
    normalized = "/aws/${var.project_name}/incidents-normalized"
    lambda     = "/aws/lambda/lambda-${var.project_name}-detector-b"
  }

  evidence_prefixes = [
    "incident-01-bruteforce/",
    "incident-02-port-scan/",
    "incident-03-privilege-escalation/",
    "incident-04-credential-leak/",
    "incident-05-exfiltration/",
    "config/"
  ]

  logs_prefixes = [
    "cloudtrail/",
    "vpc-flow-logs/",
    "config/",
    "athena-results/"
  ]

  sensitive_prefixes = [
    "sensible/",
    "public/"
  ]
}

# -----------------------------------------------------------------------------
# Presupuesto básico. Se crea solo si defines alert_email y create_budget=true.
# -----------------------------------------------------------------------------

resource "aws_budgets_budget" "monthly_cost" {
  count = var.create_budget && var.alert_email != "" ? 1 : 0

  name         = "${var.project_name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

# -----------------------------------------------------------------------------
# Red: VPC, subredes públicas/privadas reservadas, IGW y rutas públicas.
# No se crea NAT Gateway, ALB, RDS ni VPC Endpoints para reducir costos.
# -----------------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_a_cidr
  availability_zone       = local.az_1
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-subnet-public1-${local.az_1}"
    Tier = "public"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_b_cidr
  availability_zone       = local.az_2
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-subnet-public2-${local.az_2}"
    Tier = "public"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_a_cidr
  availability_zone = local.az_1

  tags = {
    Name = "${var.project_name}-subnet-private1-${local.az_1}"
    Tier = "private-reserved"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_b_cidr
  availability_zone = local.az_2

  tags = {
    Name = "${var.project_name}-subnet-private2-${local.az_2}"
    Tier = "private-reserved"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project_name}-rtb-public"
  }
}

resource "aws_route" "public_default_ipv4" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project_name}-rtb-private-local-only"
  }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# -----------------------------------------------------------------------------
# Security Group del portal.
# SSH queda limitado a tu IP pública /32.
# -----------------------------------------------------------------------------

resource "aws_security_group" "portal" {
  name        = "${var.project_name}-portal-sg"
  description = "Security group para portal web de laboratorio IR"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTP del portal limitado a CIDRs autorizados"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = local.portal_http_cidrs
  }

  ingress {
    description = "SSH solo desde la IP autorizada"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_allowed_cidr]
  }

  egress {
    description = "Salida necesaria para instalar paquetes y enviar logs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-portal-sg"
  }
}

# -----------------------------------------------------------------------------
# Buckets S3: logs, evidencia y datos sensibles ficticios.
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket        = local.logs_bucket_name
  force_destroy = var.force_destroy_buckets

  tags = {
    Name = local.logs_bucket_name
    Role = "logs"
  }
}

resource "aws_s3_bucket" "evidence" {
  bucket        = local.evidence_bucket_name
  force_destroy = var.force_destroy_buckets

  tags = {
    Name = local.evidence_bucket_name
    Role = "incident-evidence"
  }
}

resource "aws_s3_bucket" "sensitive" {
  bucket        = local.sensitive_bucket_name
  force_destroy = var.force_destroy_buckets

  tags = {
    Name = local.sensitive_bucket_name
    Role = "sensitive-demo-data"
  }
}

resource "aws_s3_bucket_public_access_block" "all" {
  for_each = {
    logs      = aws_s3_bucket.logs.id
    evidence  = aws_s3_bucket.evidence.id
    sensitive = aws_s3_bucket.sensitive.id
  }

  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "all" {
  for_each = {
    logs      = aws_s3_bucket.logs.id
    evidence  = aws_s3_bucket.evidence.id
    sensitive = aws_s3_bucket.sensitive.id
  }

  bucket = each.value

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "all" {
  for_each = {
    logs      = aws_s3_bucket.logs.id
    evidence  = aws_s3_bucket.evidence.id
    sensitive = aws_s3_bucket.sensitive.id
  }

  bucket = each.value

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "all" {
  for_each = {
    logs      = aws_s3_bucket.logs.id
    evidence  = aws_s3_bucket.evidence.id
    sensitive = aws_s3_bucket.sensitive.id
  }

  bucket = each.value

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "logs_prefixes" {
  for_each = toset(local.logs_prefixes)

  bucket  = aws_s3_bucket.logs.id
  key     = each.value
  content = ""
}

resource "aws_s3_object" "evidence_prefixes" {
  for_each = toset(local.evidence_prefixes)

  bucket  = aws_s3_bucket.evidence.id
  key     = each.value
  content = ""
}

resource "aws_s3_object" "sensitive_prefixes" {
  for_each = toset(local.sensitive_prefixes)

  bucket  = aws_s3_bucket.sensitive.id
  key     = each.value
  content = ""
}

resource "aws_s3_object" "demo_sensitive_clients" {
  bucket       = aws_s3_bucket.sensitive.id
  key          = "sensible/clientes_demo.json"
  content_type = "application/json"

  content = jsonencode({
    aviso = "Datos ficticios para laboratorio. No usar informacion real."
    clientes = [
      { id = 1, nombre = "Cliente Demo 1", nivel = "interno" },
      { id = 2, nombre = "Cliente Demo 2", nivel = "interno" }
    ]
  })
}

resource "aws_s3_object" "demo_public_readme" {
  bucket       = aws_s3_bucket.sensitive.id
  key          = "public/readme.txt"
  content_type = "text/plain"
  content      = "Bucket de laboratorio. No contiene datos reales.\n"
}

resource "aws_s3_object" "detector_config" {
  bucket       = aws_s3_bucket.evidence.id
  key          = "config/authorized_ips.json"
  content_type = "application/json"

  content = jsonencode({
    authorized_ips = local.authorized_ip_cidrs
    sensitive_buckets = [
      aws_s3_bucket.sensitive.bucket
    ]
    critical_policies = [
      aws_iam_policy.critical_policy.name
    ]
    authorized_admin_users = var.authorized_admin_users
    thresholds = {
      console_login_failures_same_user_5m = var.threshold_console_login_failures_same_user_5m
      console_login_failures_same_ip_5m   = var.threshold_console_login_failures_same_ip_5m
      app_login_failures_same_ip_5m       = var.threshold_app_login_failures_same_ip_5m
      port_scan_distinct_ports_5m         = var.threshold_port_scan_distinct_ports_5m
      s3_getobject_unusual_count_5m       = var.threshold_s3_getobject_unusual_count_5m
      s3_getobject_exfiltration_count_1h  = var.threshold_s3_getobject_exfiltration_count_1h
    }
    resource_ids = {
      vpc_id             = aws_vpc.this.id
      portal_instance_id = aws_instance.portal.id
    }
  })
}

# Bucket policy necesaria para CloudTrail.
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/cloudtrail/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Log Groups.
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = local.common_log_groups.cloudtrail
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_cloudwatch_log_group" "flowlogs" {
  name              = local.common_log_groups.flowlogs
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_cloudwatch_log_group" "config" {
  name              = local.common_log_groups.config
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_cloudwatch_log_group" "ec2_app" {
  name              = local.common_log_groups.app
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_cloudwatch_log_group" "normalized" {
  name              = local.common_log_groups.normalized
  retention_in_days = var.normalized_log_retention_days
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = local.common_log_groups.lambda
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_cloudwatch_log_group" "playbook_notify" {
  name              = "/aws/lambda/lambda-${var.project_name}-playbook-notify-alert"
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_cloudwatch_log_group" "playbook_block_ip" {
  name              = "/aws/lambda/lambda-${var.project_name}-playbook-block-ip"
  retention_in_days = var.cloudwatch_retention_days
}

# -----------------------------------------------------------------------------
# IAM para EC2: SSM + CloudWatch Agent.
# -----------------------------------------------------------------------------

resource "aws_iam_role" "ec2" {
  name = "role-ec2-${var.project_name}-portal"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "ec2_cloudwatch_agent_limited" {
  name = "policy-ec2-${var.project_name}-cloudwatch-agent-limited"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteOnlyPortalLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          aws_cloudwatch_log_group.ec2_app.arn,
          "${aws_cloudwatch_log_group.ec2_app.arn}:*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  name = "profile-ec2-${var.project_name}-portal"
  role = aws_iam_role.ec2.name
}

# -----------------------------------------------------------------------------
# EC2 portal web de laboratorio.
# -----------------------------------------------------------------------------

resource "aws_instance" "portal" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.public_a.id
  private_ip                  = var.portal_private_ip
  vpc_security_group_ids      = [aws_security_group.portal.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2.name
  key_name                    = var.key_name != "" ? var.key_name : null

  user_data_base64 = base64gzip(templatefile("${path.module}/scripts/user_data.sh.tpl", {
    app_log_group = aws_cloudwatch_log_group.ec2_app.name
    project_name  = var.project_name
  }))

  user_data_replace_on_change = true

  root_block_device {
    volume_size           = var.ec2_volume_size_gb
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name = "${var.project_name}-portal-ec2"
    Role = "portal-web-laboratorio"
  }

  depends_on = [
    aws_cloudwatch_log_group.ec2_app,
    aws_iam_role_policy.ec2_cloudwatch_agent_limited,
    aws_iam_role_policy_attachment.ec2_ssm
  ]
}

# -----------------------------------------------------------------------------
# VPC Flow Logs sobre la ENI de la EC2, no sobre toda la VPC.
# -----------------------------------------------------------------------------

resource "aws_iam_role" "vpc_flowlogs" {
  name = "role-${var.project_name}-vpc-flowlogs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "vpc-flow-logs.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "vpc_flowlogs" {
  name = "policy-${var.project_name}-vpc-flowlogs"
  role = aws_iam_role.vpc_flowlogs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.flowlogs.arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "portal_eni" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  iam_role_arn    = aws_iam_role.vpc_flowlogs.arn
  log_destination = aws_cloudwatch_log_group.flowlogs.arn
  traffic_type    = "ALL"
  eni_id          = aws_instance.portal.primary_network_interface_id

  max_aggregation_interval = 60

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"

  tags = {
    Name = "${var.project_name}-vpc-flowlogs-ec2"
  }

  depends_on = [
    aws_iam_role_policy.vpc_flowlogs
  ]
}

# -----------------------------------------------------------------------------
# CloudTrail: management events por defecto.
# S3 data events quedan apagados por defecto para reducir costos.
# -----------------------------------------------------------------------------

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "role-${var.project_name}-cloudtrail-cloudwatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "policy-${var.project_name}-cloudtrail-cloudwatch"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

resource "aws_cloudtrail" "management" {
  name                          = "${var.project_name}-cloudtrail-management"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = var.cloudtrail_multi_region
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    dynamic "data_resource" {
      for_each = var.enable_s3_data_events ? [1] : []

      content {
        type   = "AWS::S3::Object"
        values = ["${aws_s3_bucket.sensitive.arn}/sensible/"]
      }
    }
  }

  depends_on = [
    aws_s3_bucket_policy.logs,
    aws_iam_role_policy.cloudtrail_cloudwatch
  ]

  tags = {
    Name = "${var.project_name}-cloudtrail-management"
  }
}

# -----------------------------------------------------------------------------
# AWS Config opcional: puede generar cargos por configuration items y reglas.
# Por defecto está desactivado. Actívalo solo para pruebas de cambios IAM.
# -----------------------------------------------------------------------------

resource "aws_iam_role" "config" {
  count = var.enable_aws_config ? 1 : 0

  name = "role-${var.project_name}-aws-config"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  count = var.enable_aws_config ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_delivery" {
  count = var.enable_aws_config ? 1 : 0

  name = "policy-${var.project_name}-aws-config-s3-delivery"
  role = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.logs.arn
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/config/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "this" {
  count = var.enable_aws_config ? 1 : 0

  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = true
    resource_types                = var.config_resource_types
  }

  depends_on = [
    aws_iam_role_policy_attachment.config_managed,
    aws_iam_role_policy.config_s3_delivery
  ]
}

resource "aws_config_delivery_channel" "this" {
  count = var.enable_aws_config ? 1 : 0

  name           = "${var.project_name}-config-delivery"
  s3_bucket_name = aws_s3_bucket.logs.bucket
  s3_key_prefix  = "config"

  depends_on = [
    aws_config_configuration_recorder.this
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = var.enable_aws_config ? 1 : 0

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.this
  ]
}

resource "aws_config_config_rule" "iam_no_admin_access" {
  count = var.enable_aws_config ? 1 : 0

  name = "${var.project_name}-iam-policy-no-admin-access"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  depends_on = [
    aws_config_configuration_recorder_status.this
  ]
}

# -----------------------------------------------------------------------------
# DynamoDB: incidentes y estado temporal de detección.
# -----------------------------------------------------------------------------

resource "aws_dynamodb_table" "incidents" {
  name         = "${var.project_name}_incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  tags = {
    Name = "${var.project_name}_incidents"
    Role = "incident-registry"
  }
}

resource "aws_dynamodb_table" "state" {
  name         = "${var.project_name}_detection_state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}_detection_state"
    Role = "detector-state"
  }
}

# -----------------------------------------------------------------------------
# SNS para alertas.
# -----------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-incident-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# -----------------------------------------------------------------------------
# SQS: cola de incidentes para entregar el JSON normalizado exigido por el
# componente B. Lambda publica aqui las variables obligatorias por incidente.
# -----------------------------------------------------------------------------

resource "aws_sqs_queue" "incident_queue" {
  name                       = "${var.project_name}-incident-queue"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 30
  sqs_managed_sse_enabled    = true

  tags = {
    Name = "${var.project_name}-incident-queue"
    Role = "normalized-incident-queue"
  }
}

resource "aws_sqs_queue" "playbook_notify_queue" {
  name                       = "${var.project_name}-playbook-notify-alert-queue"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 60
  sqs_managed_sse_enabled    = true

  tags = {
    Name = "${var.project_name}-playbook-notify-alert-queue"
    Role = "playbook-dispatch-notify-alert"
  }
}

resource "aws_sqs_queue" "playbook_block_ip_queue" {
  name                       = "${var.project_name}-playbook-block-ip-queue"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 60
  sqs_managed_sse_enabled    = true

  tags = {
    Name = "${var.project_name}-playbook-block-ip-queue"
    Role = "playbook-dispatch-block-ip"
  }
}

resource "aws_sqs_queue" "playbook_revoke_credentials_queue" {
  name                       = "${var.project_name}-playbook-revoke-credentials-queue"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 60
  sqs_managed_sse_enabled    = true

  tags = {
    Name = "${var.project_name}-playbook-revoke-credentials-queue"
    Role = "playbook-dispatch-revoke-credentials"
  }
}


# -----------------------------------------------------------------------------
# IAM policy crítica de prueba e IAM user de laboratorio.
# No se crean access keys ni password de consola.
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "critical_policy" {
  name        = "${var.project_name}-critical-policy"
  description = "Politica critica de laboratorio para detectar cambios controlados"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowReadOnlySensitiveDemoBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.sensitive.arn,
          "${aws_s3_bucket.sensitive.arn}/sensible/*"
        ]
      }
    ]
  })
}

resource "aws_iam_user" "test_user" {
  count = var.create_test_iam_user ? 1 : 0

  name          = "${var.project_name}-user-test"
  force_destroy = true

  tags = {
    Role = "lab-test-user"
  }
}

# -----------------------------------------------------------------------------
# Lambda Detector B.
# -----------------------------------------------------------------------------

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/lambda_function.py"
  output_path = "${path.module}/lambda_tesis_detector.zip"
}

resource "aws_iam_role" "lambda_detector" {
  name = "role-lambda-${var.project_name}-detector"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_detector.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_detector" {
  name = "policy-lambda-${var.project_name}-detector"
  role = aws_iam_role.lambda_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBIncidentAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.incidents.arn,
          aws_dynamodb_table.state.arn
        ]
      },
      {
        Sid    = "EvidenceS3Access"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = [
          "${aws_s3_bucket.evidence.arn}/*"
        ]
      },
      {
        Sid      = "SnsPublishAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid    = "SqsPublishNormalizedIncidentAndPlaybooks"
        Effect = "Allow"
        Action = "sqs:SendMessage"
        Resource = [
          aws_sqs_queue.incident_queue.arn,
          aws_sqs_queue.playbook_notify_queue.arn,
          aws_sqs_queue.playbook_block_ip_queue.arn,
          aws_sqs_queue.playbook_revoke_credentials_queue.arn
        ]
      },
      {
        Sid      = "CloudWatchCustomMetrics"
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "TesisIR"
          }
        }
      }
    ]
  })
}

resource "aws_lambda_function" "detector" {
  function_name = "lambda-${var.project_name}-detector-b"
  role          = aws_iam_role.lambda_detector.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      INCIDENTS_TABLE = aws_dynamodb_table.incidents.name
      STATE_TABLE     = aws_dynamodb_table.state.name
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.bucket
      SNS_TOPIC_ARN      = aws_sns_topic.alerts.arn
      CONFIG_KEY         = aws_s3_object.detector_config.key
      INCIDENT_QUEUE_URL        = aws_sqs_queue.incident_queue.url
      PLAYBOOK_NOTIFY_QUEUE_URL = aws_sqs_queue.playbook_notify_queue.url
      PLAYBOOK_BLOCK_IP_QUEUE_URL = aws_sqs_queue.playbook_block_ip_queue.url
      PLAYBOOK_REVOKE_CREDENTIALS_QUEUE_URL = aws_sqs_queue.playbook_revoke_credentials_queue.url
      VPC_ID                    = aws_vpc.this.id
      PORTAL_INSTANCE_ID        = aws_instance.portal.id
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.lambda_detector,
    aws_cloudwatch_log_group.lambda
  ]

  tags = {
    Name = "lambda-${var.project_name}-detector-b"
    Role = "incident-detector"
  }
}

# Permisos para que CloudWatch Logs invoque Lambda.
resource "aws_lambda_permission" "from_cloudtrail_logs" {
  statement_id  = "AllowCloudWatchCloudTrail"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
}

resource "aws_lambda_permission" "from_app_logs" {
  statement_id  = "AllowCloudWatchAppLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.ec2_app.arn}:*"
}

resource "aws_lambda_permission" "from_flow_logs" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  statement_id  = "AllowCloudWatchFlowLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.flowlogs.arn}:*"
}

# Subscription filters.
resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_to_lambda" {
  name            = "sf-cloudtrail-to-detector"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern  = "{ ($.eventSource = \"signin.amazonaws.com\") || ($.eventSource = \"iam.amazonaws.com\") || ($.eventSource = \"s3.amazonaws.com\") || ($.eventSource = \"sts.amazonaws.com\") }"
  destination_arn = aws_lambda_function.detector.arn

  depends_on = [
    aws_lambda_permission.from_cloudtrail_logs
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "app_to_lambda" {
  name            = "sf-app-to-detector"
  log_group_name  = aws_cloudwatch_log_group.ec2_app.name
  filter_pattern  = "{ $.event_type = \"login_failed\" }"
  destination_arn = aws_lambda_function.detector.arn

  depends_on = [
    aws_lambda_permission.from_app_logs
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "flowlogs_to_lambda" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name            = "sf-flowlogs-to-detector"
  log_group_name  = aws_cloudwatch_log_group.flowlogs.name
  filter_pattern  = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action = \"REJECT\", log_status]"
  destination_arn = aws_lambda_function.detector.arn

  depends_on = [
    aws_lambda_permission.from_flow_logs
  ]
}


# -----------------------------------------------------------------------------
# Playbooks de respuesta para Incidente 1: BRUTE_FORCE.
# notify-alert notifica por SNS y deja auditoria en S3.
# block-ip aplica contencion real en la NACL con una regla DENY para la IP origen.
# -----------------------------------------------------------------------------

data "archive_file" "notify_alert_zip" {
  type        = "zip"
  source_file = "${path.module}/playbooks/notify_alert/handler.py"
  output_path = "${path.module}/lambda_playbook_notify_alert.zip"
}

data "archive_file" "block_ip_zip" {
  type        = "zip"
  source_file = "${path.module}/playbooks/block_ip/handler.py"
  output_path = "${path.module}/lambda_playbook_block_ip.zip"
}

resource "aws_iam_role" "playbook_notify" {
  name = "role-lambda-${var.project_name}-playbook-notify-alert"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "playbook_block_ip" {
  name = "role-lambda-${var.project_name}-playbook-block-ip"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "playbook_notify_basic" {
  role       = aws_iam_role.playbook_notify.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "playbook_block_ip_basic" {
  role       = aws_iam_role.playbook_block_ip.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "playbook_notify" {
  name = "policy-lambda-${var.project_name}-playbook-notify-alert"
  role = aws_iam_role.playbook_notify.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadDedicatedQueue"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.playbook_notify_queue.arn
      },
      {
        Sid      = "PublishAlert"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid    = "WritePlaybookAudit"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.evidence.arn}/responses/notify-alert/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "playbook_block_ip" {
  name = "policy-lambda-${var.project_name}-playbook-block-ip"
  role = aws_iam_role.playbook_block_ip.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadDedicatedQueue"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.playbook_block_ip_queue.arn
      },
      {
        Sid    = "ManageNaclDenyRule"
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry"
        ]
        Resource = "*"
      },
      {
        Sid    = "WriteBlockAudit"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.evidence.arn}/responses/block-ip/*"
      },
      {
        Sid      = "PublishAlert"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_lambda_function" "playbook_notify" {
  function_name = "lambda-${var.project_name}-playbook-notify-alert"
  role          = aws_iam_role.playbook_notify.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]
  memory_size   = 128
  timeout       = 20

  filename         = data.archive_file.notify_alert_zip.output_path
  source_code_hash = data.archive_file.notify_alert_zip.output_base64sha256

  environment {
    variables = {
      SNS_ALERTS_ARN = aws_sns_topic.alerts.arn
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.bucket
      RESPONSE_PREFIX = "responses/notify-alert"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.playbook_notify_basic,
    aws_iam_role_policy.playbook_notify,
    aws_cloudwatch_log_group.playbook_notify
  ]

  tags = {
    Name = "lambda-${var.project_name}-playbook-notify-alert"
    Role = "playbook-notify-alert"
  }
}

resource "aws_lambda_function" "playbook_block_ip" {
  function_name = "lambda-${var.project_name}-playbook-block-ip"
  role          = aws_iam_role.playbook_block_ip.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]
  memory_size   = 128
  timeout       = 30

  filename         = data.archive_file.block_ip_zip.output_path
  source_code_hash = data.archive_file.block_ip_zip.output_base64sha256

  environment {
    variables = {
      SNS_ALERTS_ARN = aws_sns_topic.alerts.arn
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.bucket
      TARGET_NACL_ID = aws_vpc.this.default_network_acl_id
      RESPONSE_PREFIX = "responses/block-ip"
      RULE_MIN = "1"
      RULE_MAX = "99"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.playbook_block_ip_basic,
    aws_iam_role_policy.playbook_block_ip,
    aws_cloudwatch_log_group.playbook_block_ip
  ]

  tags = {
    Name = "lambda-${var.project_name}-playbook-block-ip"
    Role = "playbook-block-ip"
  }
}

resource "aws_lambda_event_source_mapping" "playbook_notify_from_queue" {
  event_source_arn = aws_sqs_queue.playbook_notify_queue.arn
  function_name    = aws_lambda_function.playbook_notify.arn
  batch_size       = 5
  enabled          = true
}

resource "aws_lambda_event_source_mapping" "playbook_block_ip_from_queue" {
  event_source_arn = aws_sqs_queue.playbook_block_ip_queue.arn
  function_name    = aws_lambda_function.playbook_block_ip.arn
  batch_size       = 1
  enabled          = true
}

# -----------------------------------------------------------------------------
# Playbook de respuesta para Incidente 3 y 4: PRIVILEGE_ESCALATION y CREDENTIAL_LEAK.
# revoke-credentials desactiva las access keys del usuario y le aplica Deny-All.
# -----------------------------------------------------------------------------

data "archive_file" "revoke_credentials_zip" {
  type        = "zip"
  source_file = "${path.module}/playbooks/revoke_credentials/handler.py"
  output_path = "${path.module}/lambda_playbook_revoke_credentials.zip"
}

resource "aws_cloudwatch_log_group" "playbook_revoke_credentials" {
  name              = "/aws/lambda/lambda-${var.project_name}-playbook-revoke-credentials"
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_iam_role" "playbook_revoke_credentials" {
  name = "role-lambda-${var.project_name}-playbook-revoke-credentials"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "playbook_revoke_credentials_basic" {
  role       = aws_iam_role.playbook_revoke_credentials.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "playbook_revoke_credentials" {
  name = "policy-lambda-${var.project_name}-playbook-revoke-credentials"
  role = aws_iam_role.playbook_revoke_credentials.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadDedicatedQueue"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.playbook_revoke_credentials_queue.arn
      },
      {
        Sid    = "ManageUserCredentialsAndPolicies"
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "WriteRevokeAudit"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.evidence.arn}/responses/revoke-credentials/*"
      },
      {
        Sid      = "PublishAlert"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_lambda_function" "playbook_revoke_credentials" {
  function_name = "lambda-${var.project_name}-playbook-revoke-credentials"
  role          = aws_iam_role.playbook_revoke_credentials.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]
  memory_size   = 128
  timeout       = 30

  filename         = data.archive_file.revoke_credentials_zip.output_path
  source_code_hash = data.archive_file.revoke_credentials_zip.output_base64sha256

  environment {
    variables = {
      SNS_ALERTS_ARN  = aws_sns_topic.alerts.arn
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.bucket
      RESPONSE_PREFIX = "responses/revoke-credentials"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.playbook_revoke_credentials_basic,
    aws_iam_role_policy.playbook_revoke_credentials,
    aws_cloudwatch_log_group.playbook_revoke_credentials
  ]

  tags = {
    Name = "lambda-${var.project_name}-playbook-revoke-credentials"
    Role = "playbook-revoke-credentials"
  }
}

resource "aws_lambda_event_source_mapping" "playbook_revoke_credentials_from_queue" {
  event_source_arn = aws_sqs_queue.playbook_revoke_credentials_queue.arn
  function_name    = aws_lambda_function.playbook_revoke_credentials.arn
  batch_size       = 1
  enabled          = true
}

# -----------------------------------------------------------------------------
# Integracion de notificaciones a Telegram via SNS
# -----------------------------------------------------------------------------

data "archive_file" "telegram_notifier_zip" {
  count       = var.telegram_bot_token != "" && var.telegram_chat_id != "" ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/playbooks/telegram_notifier/handler.py"
  output_path = "${path.module}/lambda_playbook_telegram_notifier.zip"
}

resource "aws_cloudwatch_log_group" "telegram_notifier" {
  count             = var.telegram_bot_token != "" && var.telegram_chat_id != "" ? 1 : 0
  name              = "/aws/lambda/lambda-${var.project_name}-telegram-notifier"
  retention_in_days = var.cloudwatch_retention_days
}

resource "aws_iam_role" "telegram_notifier" {
  count = var.telegram_bot_token != "" && var.telegram_chat_id != "" ? 1 : 0
  name  = "role-lambda-${var.project_name}-telegram-notifier"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "telegram_notifier_basic" {
  count      = var.telegram_bot_token != "" && var.telegram_chat_id != "" ? 1 : 0
  role       = aws_iam_role.telegram_notifier[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "telegram_notifier" {
  count         = var.telegram_bot_token != "" && var.telegram_chat_id != "" ? 1 : 0
  function_name = "lambda-${var.project_name}-telegram-notifier"
  role          = aws_iam_role.telegram_notifier[0].arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]
  memory_size   = 128
  timeout       = 15

  filename         = data.archive_file.telegram_notifier_zip[0].output_path
  source_code_hash = data.archive_file.telegram_notifier_zip[0].output_base64sha256

  environment {
    variables = {
      TELEGRAM_BOT_TOKEN = var.telegram_bot_token
      TELEGRAM_CHAT_ID   = var.telegram_chat_id
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.telegram_notifier_basic,
    aws_cloudwatch_log_group.telegram_notifier
  ]

  tags = {
    Name = "lambda-${var.project_name}-telegram-notifier"
    Role = "telegram-alert-notifier"
  }
}

resource "aws_lambda_permission" "from_sns_telegram" {
  count         = var.telegram_bot_token != "" && var.telegram_chat_id != "" ? 1 : 0
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.telegram_notifier[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_subscription" "telegram" {
  count     = var.telegram_bot_token != "" && var.telegram_chat_id != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.telegram_notifier[0].arn

  depends_on = [
    aws_lambda_permission.from_sns_telegram
  ]
}


# -----------------------------------------------------------------------------
# Metric filters y alarmas simples de respaldo.
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "console_login_failure" {
  name           = "mf-console-login-failure"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.responseElements.ConsoleLogin = \"Failure\") }"

  metric_transformation {
    name          = "ConsoleLoginFailure"
    namespace     = "TesisIR"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "iam_critical_action" {
  name           = "mf-iam-critical-action"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventSource = \"iam.amazonaws.com\") && (($.eventName = \"CreateUser\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"CreateAccessKey\") || ($.eventName = \"AddUserToGroup\")) }"

  metric_transformation {
    name          = "IAMCriticalAction"
    namespace     = "TesisIR"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "iam_policy_change" {
  name           = "mf-iam-policy-change"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventSource = \"iam.amazonaws.com\") && (($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"UpdateAssumeRolePolicy\")) }"

  metric_transformation {
    name          = "IAMPolicyChange"
    namespace     = "TesisIR"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "vpc_rejected_traffic" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name           = "mf-vpc-rejected-traffic"
  log_group_name = aws_cloudwatch_log_group.flowlogs.name
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action = \"REJECT\", log_status]"

  metric_transformation {
    name          = "VPCRejectedTraffic"
    namespace     = "TesisIR"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_login_failure" {
  alarm_name          = "alarm-console-login-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleLoginFailure"
  namespace           = "TesisIR"
  period              = 300
  statistic           = "Sum"
  threshold           = var.threshold_console_login_failures_same_user_5m
  alarm_description   = "Alarma por multiples fallos de inicio de sesion"
  treat_missing_data  = "notBreaching"

  depends_on = [aws_cloudwatch_log_metric_filter.console_login_failure]
}

resource "aws_cloudwatch_metric_alarm" "iam_critical_action" {
  alarm_name          = "alarm-iam-critical-action"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMCriticalAction"
  namespace           = "TesisIR"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alarma por accion critica IAM"
  treat_missing_data  = "notBreaching"

  depends_on = [aws_cloudwatch_log_metric_filter.iam_critical_action]
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_change" {
  alarm_name          = "alarm-iam-policy-change"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChange"
  namespace           = "TesisIR"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alarma por cambio de politica IAM"
  treat_missing_data  = "notBreaching"

  depends_on = [aws_cloudwatch_log_metric_filter.iam_policy_change]
}

resource "aws_cloudwatch_metric_alarm" "vpc_rejected_traffic" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  alarm_name          = "alarm-vpc-rejected-traffic"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "VPCRejectedTraffic"
  namespace           = "TesisIR"
  period              = 300
  statistic           = "Sum"
  threshold           = var.threshold_port_scan_distinct_ports_5m
  alarm_description   = "Alarma por trafico rechazado repetido hacia la EC2"
  treat_missing_data  = "notBreaching"

  depends_on = [aws_cloudwatch_log_metric_filter.vpc_rejected_traffic]
}

# -----------------------------------------------------------------------------
# Athena workgroup para consultas históricas sobre S3.
# No crea tablas Glue/CloudTrail automáticamente para evitar complejidad/costos.
# -----------------------------------------------------------------------------

resource "aws_athena_workgroup" "ir" {
  name = "${var.project_name}-athena-workgroup"

  configuration {
    enforce_workgroup_configuration = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.logs.bucket}/athena-results/"
    }
  }

  tags = {
    Name = "${var.project_name}-athena-workgroup"
  }
}
