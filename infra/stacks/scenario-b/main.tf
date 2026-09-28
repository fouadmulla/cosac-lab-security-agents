# Scenario B: Custodian.
#
# Two t3.micro victims, one per twin, identical in every respect. Each will
# genuinely trigger GuardDuty, and each will genuinely exfiltrate a synthetic
# canary dataset until something stops it.
#
# Custodian-A quarantines its victim in seconds. Custodian-B routes the same
# finding to an approval queue and contains nothing. The difference is
# measured in bytes, integrated over real elapsed time:
#
#     bytes_exfiltrated = egress_rate * time_to_containment
#
# Nobody types the result.

locals {
  twins = {
    # A is the FLAWED one, B the correct one -- same ordering as Scenario A,
    # so the board reads the same way in both.
    a = { profile = "approval_gated", label = "custodian-a" }
    b = { profile = "non_blocking", label = "custodian-b" }
  }

  tags = {
    Project  = "cosac"
    Scenario = "b-custodian"
  }
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# -- network ----------------------------------------------------------------

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true # GuardDuty's DNS findings come from the
  # Amazon-provided resolver, so this is required.

  tags = merge(local.tags, { Name = "cosac-scenario-b" })
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = local.tags
}

# Emptied, so an instance created without an explicit group is isolated.
resource "aws_default_security_group" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = merge(local.tags, { Name = "cosac-b-default-deny" })
}

resource "aws_subnet" "victim" {
  for_each = local.twins

  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, index(keys(local.twins), each.key))
  availability_zone       = var.availability_zones[0]
  map_public_ip_on_launch = true

  tags = merge(local.tags, { Name = "cosac-b-${each.key}", Twin = each.value.label })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = local.tags
}

resource "aws_route_table_association" "victim" {
  for_each = aws_subnet.victim

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# -- security groups --------------------------------------------------------

resource "aws_security_group" "normal" {
  name        = "cosac-b-normal"
  description = "Pre-compromise state. Egress permitted; this is what the agent replaces."
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "Outbound, including the exfiltration the demo measures"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# The isolation group. No rules at all: no ingress, no egress.
#
# Swapping to this is the containment action. It stops the exfiltration
# immediately, preserves the ENI and the instance for forensics, and is fully
# reversible -- the prior group is written to the ledger before the swap, which
# is Constrain's reversibility leg as a precondition of acting.
# Unattached by design. Nothing wears this group until an agent decides to
# quarantine something, and which instance that is -- if any -- is precisely
# the outcome the demo measures. Waived in .checkov.yml, since graph checks
# do not honour inline skips.
resource "aws_security_group" "isolation" {
  name        = "cosac-b-isolation"
  description = "Quarantine: no ingress, no egress, ENI preserved for forensics"
  vpc_id      = aws_vpc.lab.id

  tags = merge(local.tags, { Name = "cosac-b-isolation" })
}

# -- exfiltration sink ------------------------------------------------------
#
# Inside the lab boundary. The "stolen" data is synthetic and generated on the
# victim; nothing real exists anywhere in this stack.

resource "aws_s3_bucket" "sink" {
  bucket        = "cosac-exfil-sink-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = merge(local.tags, { Name = "exfiltration-sink" })
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_public_access_block" "sink" {
  bucket = aws_s3_bucket.sink.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sink" {
  bucket = aws_s3_bucket.sink.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "sink" {
  bucket = aws_s3_bucket.sink.id

  rule {
    id     = "expire-demo-data"
    status = "Enabled"

    filter {}

    expiration {
      days = 1
    }

    # The victim uploads continuously and is cut off mid-flight when it is
    # quarantined, so interrupted multipart uploads are the expected steady
    # state here rather than an edge case.
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# -- victims ----------------------------------------------------------------

resource "aws_iam_role" "victim" {
  name = "cosac-b-victim"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "victim_ssm" {
  role       = aws_iam_role.victim.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "victim" {
  name = "exfiltrate-and-report"
  role = aws_iam_role.victim.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.sink.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = var.metric_namespace }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "victim" {
  name = "cosac-b-victim"
  role = aws_iam_role.victim.name
}

resource "aws_instance" "victim" {
  for_each = local.twins

  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.victim_instance_type
  subnet_id              = aws_subnet.victim[each.key].id
  vpc_security_group_ids = [aws_security_group.normal.id]
  iam_instance_profile   = aws_iam_instance_profile.victim.name

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/userdata/victim.sh.tftpl", {
    sink_bucket      = aws_s3_bucket.sink.id
    metric_namespace = var.metric_namespace
    region           = var.region
    twin             = each.value.label
    c2_domain        = var.guardduty_test_domain
    egress_bytes     = var.egress_bytes_per_tick
  })

  # Without this, Terraform updates the user_data attribute in place and
  # reports "1 changed" while the running host keeps the old script. The
  # bootstrap only ever executes once, at first boot, so a change to it is
  # only real if the instance is replaced.
  user_data_replace_on_change = true

  # These tags are read by the agent. A quarantine agent must know what it is
  # about to isolate: environment and criticality decide whether containment
  # is inside its unilateral authority, or must be escalated.
  tags = merge(local.tags, {
    Name        = "cosac-b-victim-${each.key}"
    Twin        = each.value.label
    environment = "lab"
    criticality = "low"
  })
}

# -- detection --------------------------------------------------------------

resource "aws_guardduty_detector" "lab" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = local.tags
}

# Delivers the real finding to the agents. Until PR 3 wires the AgentCore
# runtimes, the log group target lets you confirm end to end that a genuine
# finding arrives -- which is the part of this scenario worth validating
# before anything else is built on it.
resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  name        = "cosac-b-guardduty-finding"
  description = "EC2 C2 activity findings for tagged lab instances"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Backdoor:EC2/C&CActivity" }]
    }
  })

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "findings" {
  name              = "/cosac/scenario-b/findings"
  retention_in_days = 7

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "findings_log" {
  rule      = aws_cloudwatch_event_rule.guardduty_finding.name
  target_id = "log"
  arn       = aws_cloudwatch_log_group.findings.arn
}

resource "aws_cloudwatch_log_resource_policy" "events" {
  policy_name = "cosac-b-events-to-logs"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = ["events.amazonaws.com", "delivery.logs.amazonaws.com"] }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.findings.arn}:*"
    }]
  })
}
