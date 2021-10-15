############
# PROVIDERS
############
provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

provider "aws" {
  alias  = "replicationregion"
  region = var.aws_rep_region
}

############
# IAM ROLE 
############
resource "aws_iam_role" "terraform_s3_replication" {
  name = "iam-role-terraform-s3-replication"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "terraform_s3_replication" {
  name = "iam-role-policy-terraform-s3-replication"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetReplicationConfiguration",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.terraform_state.arn}"
      ]
    },
    {
      "Action": [
        "s3:GetObjectVersion",
        "s3:GetObjectVersionAcl"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.terraform_state.arn}/*"
      ]
    },
    {
      "Action": [
        "s3:ReplicateObject",
        "s3:ReplicateDelete"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.terraform_state_destination.arn}/*"
    }
  ]
}
POLICY
}

resource "aws_iam_policy_attachment" "terraform_replication" {
  name       = "iam-role-attachment-terraform-replication"
  roles      = [aws_iam_role.terraform_s3_replication.name]
  policy_arn = aws_iam_policy.terraform_s3_replication.arn
}

############
# S3 BUCKETS
############
resource "aws_s3_bucket" "terraform_state" {
  bucket = "${local.account_id}-terraform-state-recording"
  acl    = "private"

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  replication_configuration {
    role = aws_iam_role.terraform_s3_replication.arn

    rules {
      id     = "terraform-state-rep-rule"
      status = "Enabled"

      destination {
        bucket        = aws_s3_bucket.terraform_state_destination.arn
        storage_class = "STANDARD"
      }
    }
  }


  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )

}

resource "aws_s3_bucket" "terraform_state_destination" {
  bucket   = "${local.account_id}-terraform-state-replication"
  provider = aws.replicationregion
  acl      = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }

  tags = merge(var.acoe_common_tags,
    tomap(
      { "Application" = "Terraform-Test" }
    )
  )
}

resource "aws_dynamodb_table" "dynamodb-terraform-state-lock" {
  name           = "terraform-state-lock-dynamo"
  hash_key       = "LockID"
  read_capacity  = 20
  write_capacity = 20

  attribute {
    name = "LockID"
    type = "S"
  }
}
