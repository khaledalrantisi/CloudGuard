output "vpc_id" {
  description = "CloudGuard VPC ID"
  value       = aws_vpc.cloudguard_vpc.id
}

output "security_group_id" {
  description = "CloudGuard Security Group ID"
  value       = aws_security_group.cloudguard_sg.id
}

output "s3_bucket_name" {
  description = "CloudGuard S3 reports bucket"
  value       = aws_s3_bucket.cloudguard_reports.bucket
}

output "iam_role_arn" {
  description = "CloudGuard IAM role ARN"
  value       = aws_iam_role.cloudguard_role.arn
}