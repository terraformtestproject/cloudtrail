data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

variable "account_name" {
  type        = string
  default     = "master"
  description = "AWS account name"
}

variable "aws_profile" {
  type        = string
  default     = "default"
  description = "AWS login profile"
}

variable "aws_region" {
  type        = string
  default     = "eu-west-1"
  description = "AWS region to generate resources in"
}

variable "aws_rep_region" {
  type        = string
  default     = "eu-central-1"
  description = "AWS region to generate replication resources in"
}

variable "acoe_common_tags" {
  description = "Common tags assigned to AWSCoE resources"
  type        = map(any)

  default = {
    "Owner"   = "AWSCoE"
    "Managed" = "terraform"
  }
}
