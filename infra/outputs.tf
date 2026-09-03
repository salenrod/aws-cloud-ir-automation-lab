output "aws_region" {
  description = "AWS Region used by the laboratory."
  value       = var.aws_region
}

output "vpc_id" {
  description = "Laboratory VPC ID."
  value       = aws_vpc.lab.id
}

output "isolated_subnet_id" {
  description = "Isolated subnet ID."
  value       = aws_subnet.isolated.id
}

output "lab_instance_id" {
  description = "Disposable EC2 instance used by the response simulation."
  value       = aws_instance.lab_target.id
}

output "baseline_security_group_id" {
  description = "Security group attached before containment."
  value       = aws_security_group.baseline.id
}

output "quarantine_security_group_id" {
  description = "Security group attached during containment."
  value       = aws_security_group.quarantine.id
}

output "evidence_bucket_name" {
  description = "S3 bucket used to store incident evidence."
  value       = aws_s3_bucket.evidence.id
}

output "incidents_table_name" {
  description = "DynamoDB incident ledger table."
  value       = aws_dynamodb_table.incidents.name
}

output "incident_topic_arn" {
  description = "SNS incident notification topic."
  value       = aws_sns_topic.incidents.arn
  sensitive   = true
}

output "sns_confirmation_required" {
  description = "Reminder to confirm the email subscription."
  value       = "Check the configured mailbox and confirm the AWS SNS subscription."
}
output "triage_lambda_name" {
  description = "Name of the GuardDuty triage Lambda function."
  value       = aws_lambda_function.triage.function_name
}

output "triage_lambda_arn" {
  description = "ARN of the GuardDuty triage Lambda function."
  value       = aws_lambda_function.triage.arn
}

output "triage_log_group_name" {
  description = "CloudWatch Logs group used by the triage Lambda."
  value       = aws_cloudwatch_log_group.triage.name
}
output "containment_lambda_name" {
  description = "Name of the EC2 containment Lambda function."
  value       = aws_lambda_function.containment.function_name
}

output "containment_lambda_arn" {
  description = "ARN of the EC2 containment Lambda function."
  value       = aws_lambda_function.containment.arn
}

output "containment_log_group_name" {
  description = "CloudWatch log group used by the containment Lambda."
  value       = aws_cloudwatch_log_group.containment.name
}