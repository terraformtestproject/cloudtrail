output "account_id" {
  value = local.account_id
}

output "terraform_state_bucket_name" {
  description = "The name of the terraform state bucket."
  value       = aws_s3_bucket.terraform_state.id
}
