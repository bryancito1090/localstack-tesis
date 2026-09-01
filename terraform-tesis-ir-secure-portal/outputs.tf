output "region" {
  value = var.aws_region
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_a_id" {
  value = aws_subnet.public_a.id
}

output "public_subnet_b_id" {
  value = aws_subnet.public_b.id
}

output "portal_instance_id" {
  value = aws_instance.portal.id
}

output "portal_public_ip" {
  value = aws_instance.portal.public_ip
}

output "portal_url" {
  value = "http://${aws_instance.portal.public_ip}"
}

output "logs_bucket" {
  value = aws_s3_bucket.logs.bucket
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.bucket
}

output "sensitive_bucket" {
  value = aws_s3_bucket.sensitive.bucket
}

output "cloudtrail_log_group" {
  value = aws_cloudwatch_log_group.cloudtrail.name
}

output "ec2_app_log_group" {
  value = aws_cloudwatch_log_group.ec2_app.name
}

output "vpc_flow_log_group" {
  value = aws_cloudwatch_log_group.flowlogs.name
}

output "lambda_detector_name" {
  value = aws_lambda_function.detector.function_name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "dynamodb_incidents_table" {
  value = aws_dynamodb_table.incidents.name
}

output "dynamodb_state_table" {
  value = aws_dynamodb_table.state.name
}

output "athena_workgroup" {
  value = aws_athena_workgroup.ir.name
}

output "warning_optional_cost_resources" {
  value = "AWS Config=${var.enable_aws_config}, S3 Data Events=${var.enable_s3_data_events}, CloudTrail multi-region=${var.cloudtrail_multi_region}. Mantenerlos apagados reduce riesgo de costos."
}

output "incident_queue_url" {
  value = aws_sqs_queue.incident_queue.url
}

output "incident_queue_arn" {
  value = aws_sqs_queue.incident_queue.arn
}

output "playbook_notify_lambda_name" {
  value = aws_lambda_function.playbook_notify.function_name
}

output "playbook_block_ip_lambda_name" {
  value = aws_lambda_function.playbook_block_ip.function_name
}

output "playbook_revoke_credentials_lambda_name" {
  value = aws_lambda_function.playbook_revoke_credentials.function_name
}

output "playbook_notify_queue_url" {
  value = aws_sqs_queue.playbook_notify_queue.url
}

output "playbook_block_ip_queue_url" {
  value = aws_sqs_queue.playbook_block_ip_queue.url
}

output "playbook_revoke_credentials_queue_url" {
  value = aws_sqs_queue.playbook_revoke_credentials_queue.url
}

output "mitigation_network_acl_id" {
  value = aws_vpc.this.default_network_acl_id
}

output "telegram_notifier_lambda_name" {
  value       = try(aws_lambda_function.telegram_notifier[0].function_name, "disabled")
  description = "Nombre de la Lambda de Telegram (si esta habilitada)."
}

output "ses_subdomain" {
  value       = try(aws_ses_domain_identity.soc[0].domain, "")
  description = "Subdominio registrado para Amazon SES."
}

output "ses_sender_email" {
  value       = var.ses_sender_email
  description = "Direccion del remitente firmada con DKIM para reportes de incidentes."
}

output "cloudflare_dkim_records" {
  value = var.ses_domain != "" ? [
    for token in try(aws_ses_domain_dkim.soc[0].dkim_tokens, []) : {
      tipo         = "CNAME"
      nombre       = "${token}._domainkey.soc"
      contenido    = "${token}.dkim.amazonses.com"
      proxy_status = "DNS only (Proxy deshabilitado / Nube Gris)"
    }
  ] : []
  description = "Registros CNAME exactos para copiar en Cloudflare DNS para activar la Firma Digital DKIM."
}

output "cloudflare_spf_record" {
  value = var.ses_domain != "" ? {
    tipo         = "TXT"
    nombre       = "soc"
    contenido    = "v=spf1 include:amazonses.com ~all"
    proxy_status = "DNS only"
  } : null
  description = "Registro SPF para autorizar el envio de correos desde Amazon SES en Cloudflare."
}

output "cloudflare_dmarc_record" {
  value = var.ses_domain != "" ? {
    tipo         = "TXT"
    nombre       = "_dmarc.soc"
    contenido    = "v=DMARC1; p=none;"
    proxy_status = "DNS only"
  } : null
  description = "Registro DMARC para validar la autenticacion de correos en Cloudflare."
}

