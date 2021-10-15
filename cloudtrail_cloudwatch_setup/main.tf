############################################################################
#
# Terraform file to create (creates dependent resources and then cloudtrail:
#  -  cloudwatch group
#  -  role to allow cloudtrail to write to cloudwatch log group
#  -  s3 bucket for cloudtrail & key 
#  -  s3 access logging bucket
#  -  cloudtrail & key
#
# State stored in AWS terraform state bucket
# Deployed to eu-west-1
############################################################################

##################
# PROVIDER & STATE
##################
provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

terraform {
  backend "s3" {
    bucket         = "990378569246-terraform-state-recording"
    key            = "cloudtrail/terraform.state"
    region         = "eu-west-1"
    dynamodb_table = "terraform-state-lock-dynamo"
  }
}

#######################
# DATA OBJECTS & LOCALS
#######################
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  cloudtrail_bucket_name = "${var.cloudtrail_name}-${data.aws_caller_identity.current.id}"
}

#########################
# CLOUDTRAIL - CLOUDWATCH
#########################
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name = "${var.cloudtrail_name}-log-group"

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )
}

resource "aws_iam_role" "cloudtrail_cloudwatch_events_role" {
  name = "${var.cloudtrail_name}-cloudwatch-logs-role"

  assume_role_policy = <<POLICY
{ 
  "Version": "2012-10-17",
  "Statement": [
    { 
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch_events_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["logs:CreateLogStream"]

    resources = [
      "arn:${local.partition}:logs:${var.aws_region}:${local.account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_log_group.name}:log-stream:*",
    ]
  }

  statement {
    effect  = "Allow"
    actions = ["logs:PutLogEvents"]

    resources = [
      "arn:${local.partition}:logs:${var.aws_region}:${local.account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_log_group.name}:log-stream:*",
    ]
  }
}

resource "aws_iam_role_policy" "cloudwatch_loggroup_role_policy" {
  name_prefix = "cloudtrail_cloudwatch_events_policy"
  role        = aws_iam_role.cloudtrail_cloudwatch_events_role.id
  policy      = data.aws_iam_policy_document.cloudtrail_cloudwatch_events_role_policy.json
}

#########################
# CLOUDTRAIL - S3 BUCKETS
#########################
resource "aws_s3_bucket" "log_bucket" {
  bucket        = local.cloudtrail_bucket_name
  acl           = "private"
  force_destroy = true
  policy        = data.aws_iam_policy_document.cloudtrail_bucket_policy.json

  versioning {
    enabled = true
  }

  logging {
    target_bucket = aws_s3_bucket.access_log_bucket.id
    target_prefix = "log/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {

  statement {
    sid = "AWSCloudTrailAclCheck"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      "arn:aws:s3:::${local.cloudtrail_bucket_name}",
    ]
  }

  statement {
    sid = "AWSCloudTrailWrite"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${local.cloudtrail_bucket_name}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

resource "aws_s3_bucket" "access_log_bucket" {
  bucket        = "${local.cloudtrail_bucket_name}-access-logs"
  acl           = "log-delivery-write"
  force_destroy = true

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )
}

##################
# CLOUDTRAIL - SNS
##################
resource "aws_sns_topic" "cloudtrail" {
  name = "${var.cloudtrail_name}-sns"

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )

}

data "aws_iam_policy_document" "cloudtrail_sns" {
  statement {
    sid = "AllowSNSPublish"

    effect = "Allow"

    actions = ["sns:Publish"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    resources = [aws_sns_topic.cloudtrail.arn]
  }
}

resource "aws_sns_topic_policy" "cloudtrail" {
  arn    = aws_sns_topic.cloudtrail.arn
  policy = data.aws_iam_policy_document.cloudtrail_sns.json
}

##################
# CLOUDTRAIL & KEY
##################
resource "aws_kms_key" "cloudtrail_key" {
  description = "Bucket Encryption Key"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "Key policy created by CloudTrail",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {"AWS": [
                "arn:aws:iam::${local.account_id}:root"
            ]},
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow CloudTrail to encrypt logs",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "kms:GenerateDataKey*",
            "Resource": "*",
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]}}
        },
        {
            "Sid": "Allow CloudTrail to describe key",
            "Effect": "Allow",
            "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
            "Action": "kms:DescribeKey",
            "Resource": "*"
        },
        {
            "Sid": "Allow principals in the account to decrypt log files",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:CallerAccount": "${local.account_id}"},
                "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${local.account_id}:trail/*"}
            }
        },
        {
            "Sid": "Allow alias creation during setup",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "kms:CreateAlias",
            "Resource": "*",
            "Condition": {"StringEquals": {
                "kms:ViaService": "ec2.region.amazonaws.com",
                "kms:CallerAccount": "${local.account_id}"
            }}
        },
        {
            "Sid": "Enable cross account log decryption",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:CallerAccount": "${local.account_id}"},
                "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${local.account_id}:trail/*"}
            }
        }
    ]
}
POLICY

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )
}

resource "aws_kms_alias" "cloudtrail_key" {
  name          = "alias/cloudtrail_key"
  target_key_id = aws_kms_key.cloudtrail_key.id
}

resource "aws_cloudtrail" "cloudtrail" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  s3_key_prefix                 = "cloudtrail-logs"
  enable_log_file_validation    = true
  include_global_service_events = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_events_role.arn
  is_multi_region_trail         = true
  sns_topic_name                = aws_sns_topic.cloudtrail.name
  kms_key_id                    = aws_kms_key.cloudtrail_key.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }

  }

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )
}

#########################
# CLOUDWATCH - SNS
#########################
resource "aws_sns_topic" "cloudwatch_sns" {
  name = "${var.cloudwatch_name}-sns"

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )

}

data "aws_iam_policy_document" "cloudwatch_sns" {
  statement {
    sid = "AllowSNSPublish"

    effect = "Allow"

    actions = ["sns:Publish"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    resources = [aws_sns_topic.cloudwatch_sns.arn]
  }
}

resource "aws_sns_topic_policy" "cloudwatch" {
  arn    = aws_sns_topic.cloudwatch_sns.arn
  policy = data.aws_iam_policy_document.cloudwatch_sns.json
}

resource "aws_sns_topic_subscription" "email-target" {
  topic_arn = aws_sns_topic.cloudwatch_sns.arn
  protocol  = "email"
  endpoint  = "karlalexandertaylor@gmail.com"
}

################################
# CLOUDWATCH - METRIC ROOT LOGIN 
################################
module "cloudwatch_metric_root_login" {
  source              = "./modules/cloudwatch_alarm"
  alarm_name          = "${var.cloudwatch_name}-root-login"
  alarm_description   = "IAM Root Login CW Rule has been triggered"
  metric_name         = "RootLogin"
  namespace           = "Cloudtrail"
  statistic           = "Sum"
  period              = "60"
  threshold           = "1"
  evaluation_periods  = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  datapoints_to_alarm = "1"
  alarm_actions       = [aws_sns_topic.cloudwatch_sns.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_sns.arn]
  treat_missing_data  = "notBreaching"
  pattern             = "{$.userIdentity.type = Root}"
  log_group_name      = aws_cloudwatch_log_group.cloudtrail_log_group.name
  value               = "1"
}

################################
# CLOUDWATCH - METRIC NO MFA 
################################
module "cloudwatch_metric_no_mfa" {
  source              = "./modules/cloudwatch_alarm"
  alarm_name          = "${var.cloudwatch_name}-no-mfa-console-logins"
  alarm_description   = "A CloudWatch Alarm that triggers if there is a Management Console sign-in without MFA."
  metric_name         = "ConsoleSigninWithoutMFA"
  namespace           = "Cloudtrail"
  statistic           = "Sum"
  period              = "60"
  threshold           = "1"
  evaluation_periods  = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  datapoints_to_alarm = "1"
  alarm_actions       = [aws_sns_topic.cloudwatch_sns.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_sns.arn]
  treat_missing_data  = "notBreaching"
  pattern             = "{($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.responseElements.ConsoleLogin != \"Failure\") && ($.additionalEventData.SamlProviderArn NOT EXISTS) }"
  log_group_name      = aws_cloudwatch_log_group.cloudtrail_log_group.name
  value               = "1"
}

################################
# CLOUDWATCH - METRIC API CALLS 
################################
module "cloudwatch_metric_unauthorised_api_calls" {
  source              = "./modules/cloudwatch_alarm"
  alarm_name          = "${var.cloudwatch_name}-unauthorised-api-calls"
  alarm_description   = "A CloudWatch Alarm that triggers if unauthorised api calls are accessed."
  metric_name         = "UnauthorisedAPICalls"
  namespace           = "Cloudtrail"
  statistic           = "Sum"
  period              = "60"
  threshold           = "1"
  evaluation_periods  = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  datapoints_to_alarm = "1"
  alarm_actions       = [aws_sns_topic.cloudwatch_sns.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_sns.arn]
  treat_missing_data  = "notBreaching"
  pattern             = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name      = aws_cloudwatch_log_group.cloudtrail_log_group.name
  value               = "1"
}

