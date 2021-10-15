variable "cloudtrail_name" {
  description = "Namespace to be used on cloudtrail resources"
  default     = "cloudtrail"
  type        = string
}

variable "cloudwatch_name" {
  description = "Namespace to be used on cloudwatch resources"
  default     = "cloudwatch"
  type        = string
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

variable "acoe_common_tags" {
  description = "Common tags assigned to AWSCoE resources"
  type        = map(any)

  default = {
    "Owner"   = "AWSCoE"
    "Managed" = "terraform"
  }
}
