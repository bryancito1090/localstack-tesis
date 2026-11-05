# Transferencias temporales del plugin amazon.aws.aws_ssm. No mezclar con evidencia.
resource "aws_s3_bucket" "ansible_transfer" {
  bucket        = "${var.project_name}-ansible-${local.account_id}-${var.aws_region}"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_public_access_block" "ansible_transfer" {
  bucket                  = aws_s3_bucket.ansible_transfer.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "ansible_transfer" {
  bucket = aws_s3_bucket.ansible_transfer.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "ansible_transfer" {
  bucket = aws_s3_bucket.ansible_transfer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.ansible_transfer.arn, "${aws_s3_bucket.ansible_transfer.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ansible_transfer" {
  bucket = aws_s3_bucket.ansible_transfer.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Sin versionado: los modulos pueden transportar secretos y deben poder eliminarse.
resource "aws_s3_bucket_lifecycle_configuration" "ansible_transfer" {
  bucket = aws_s3_bucket.ansible_transfer.id
  rule {
    id     = "expire-transfers"
    status = "Enabled"
    filter {}
    expiration {
      days = 1
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

output "ansible_portal" {
  description = "Parametros no secretos para generar el inventario de Ansible."
  value = {
    instance_id = aws_instance.portal.id
    public_ip   = aws_instance.portal.public_ip
    region      = var.aws_region
    asset_name  = "${var.project_name}-portal-ec2"
    log_group   = aws_cloudwatch_log_group.ec2_app.name
    ssm_bucket  = aws_s3_bucket.ansible_transfer.id
    ssh_key     = var.key_name
  }
}
