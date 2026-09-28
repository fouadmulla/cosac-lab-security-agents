# The two Custodian agents, on Bedrock AgentCore Runtime.
#
# AgentCore accepts a zip from S3 as well as a container, so there is no image
# to build and nothing to push -- `terraform apply` is still the whole
# deployment. The package vendors boto3, which the runtime does not provide
# (unlike Lambda) and which was only discoverable by deploying one and
# reading the traceback.
#
# Same package, same role, same model, four environment variables apart --
# and of those, exactly one decides behaviour.

locals {
  agent_package = "${path.module}/.build/agentcore.zip"
}

# Built by demo/build-agent-package.sh, which vendors boto3 alongside the
# agents package. Kept out of Terraform because pip is not something
# archive_file can do, and pretending otherwise would hide the dependency.
data "local_file" "agent_package" {
  filename = local.agent_package
}

resource "aws_s3_bucket" "agent_code" {
  bucket        = "cosac-b-agent-code-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = local.tags
}

resource "aws_s3_bucket_public_access_block" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id

  # AgentCore pins a version id, so a redeploy must not overwrite the object
  # a running runtime is still serving from.
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id

  rule {
    id     = "expire-superseded-packages"
    status = "Enabled"

    filter {}

    # Versioning is on because AgentCore pins a version id, so every deploy
    # leaves the previous package behind. A running runtime only ever needs
    # the version it was created with, so a week is generous.
    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.agent_code]
}

resource "aws_s3_object" "agent_package" {
  bucket = aws_s3_bucket.agent_code.id
  key    = "agentcore.zip"
  source = data.local_file.agent_package.filename
  etag   = filemd5(data.local_file.agent_package.filename)
}

# -- the identity AgentCore assumes -----------------------------------------

resource "aws_iam_role" "agentcore" {
  name = "cosac-b-agentcore"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      # Without these the service refuses the role outright, with an error
      # that says only "role validation failed".
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:bedrock-agentcore:${var.region}:${data.aws_caller_identity.current.account_id}:*"
        }
      }
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "agentcore" {
  name = "custodian"
  role = aws_iam_role.agentcore.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "ec2:ModifyInstanceAttribute"
        Resource = "*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Project" = "cosac" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.agent_code.arn}/*"
      },
      # Both twins get exactly this. Which instance an agent may isolate is
      # not an IAM question, which is precisely why the escalation policy
      # exists.
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:Query"]
        Resource = "arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/${var.ledger_table}"
      },
      {
        Effect = "Allow"
        Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/*",
          "arn:aws:bedrock:${var.region}:${data.aws_caller_identity.current.account_id}:inference-profile/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetResourceApiKey"]
        Resource = "*"
      },
      # It may ask for approval. It may not answer itself.
      {
        Effect   = "Deny"
        Action   = ["dynamodb:UpdateItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/${var.ledger_table}"
      },
    ]
  })
}

# -- the runtimes ------------------------------------------------------------

resource "aws_bedrockagentcore_agent_runtime" "custodian" {
  for_each = local.twins

  agent_runtime_name = "cosac_custodian_${each.key}"
  description        = "Custodian ${each.key} (${each.value.profile})"
  role_arn           = aws_iam_role.agentcore.arn

  agent_runtime_artifact {
    code_configuration {
      runtime     = "PYTHON_3_12"
      entry_point = ["serve.py"]

      code {
        s3 {
          bucket     = aws_s3_bucket.agent_code.id
          prefix     = aws_s3_object.agent_package.key
          version_id = aws_s3_object.agent_package.version_id
        }
      }
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = {
    AGENT_KIND      = "custodian"
    AGENT_ID        = each.value.label
    TWIN            = each.value.label
    ISOLATION_SG_ID = aws_security_group.isolation.id
    LEDGER_TABLE    = var.ledger_table
    COSAC_MODEL_ID  = var.model_id
    AWS_REGION      = var.region

    # THE ONE LINE THAT DIFFERS.
    CUSTODIAN_ESCALATION_PROFILE = each.value.profile
  }

  tags = merge(local.tags, { Twin = each.value.label })
}
