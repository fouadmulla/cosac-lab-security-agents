# The two hosts that make Scenario A genuine rather than simulated.
#
#   attacker   sources real scanning traffic from ~40 AWS-attested IPv6
#              addresses spread across three subnets
#   responder  stands in for the incident response team: probes both
#              applications continuously and reports whether it still has
#              access
#
# Both are driven through Systems Manager, so neither has an inbound port and
# no SSH key exists anywhere in this repository. The GitHub Actions demo
# workflows issue SSM commands; see .github/workflows/agent-warden.yml.

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_iam_role" "host" {
  name = "cosac-a-host"

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

resource "aws_iam_role_policy_attachment" "host_ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "host" {
  name = "cosac-a-host"
  role = aws_iam_role.host.name
}

# -- attacker ---------------------------------------------------------------
#
# Three interfaces in three subnets. This is what makes the aggregate wide
# enough to matter: forty source addresses spanning 0x10, 0x11 and 0x13 have a
# tightest covering prefix of /62, and the responder sits at 0x12 inside it.
#
# Nothing here is spoofed. Every address is allocated by AWS to this ENI, and
# every log line carrying it is AWS-attested.

resource "aws_network_interface" "attacker_primary" {
  subnet_id          = aws_subnet.this["attacker_1"].id
  security_groups    = [aws_security_group.host.id]
  ipv6_address_count = var.attacker_addresses_per_subnet

  tags = merge(local.tags, { Name = "cosac-a-attacker-1" })
}

resource "aws_network_interface" "attacker_secondary" {
  for_each = toset(["attacker_2", "attacker_3"])

  subnet_id          = aws_subnet.this[each.key].id
  security_groups    = [aws_security_group.host.id]
  ipv6_address_count = var.attacker_addresses_per_subnet

  tags = merge(local.tags, { Name = "cosac-a-${replace(each.key, "_", "-")}" })
}

# Instance-type limits are the reason the attacker is not a t3.micro like the
# responder. Both the interface count and the addresses-per-interface count
# are capped per type, and exceeding either does not fail validation -- the
# ENIs create happily and the *launch* fails, minutes into an apply, with
# "Server.InternalError: Internal error on launch" and nothing else. The
# preconditions below turn that into a plan-time error naming the real limit.
data "aws_ec2_instance_type" "attacker" {
  instance_type = var.attacker_instance_type
}

resource "aws_instance" "attacker" {
  ami                  = data.aws_ssm_parameter.al2023.value
  instance_type        = var.attacker_instance_type
  iam_instance_profile = aws_iam_instance_profile.host.name

  lifecycle {
    precondition {
      condition = var.attacker_addresses_per_subnet <= data.aws_ec2_instance_type.attacker.maximum_ipv6_addresses_per_interface
      error_message = format(
        "attacker_addresses_per_subnet is %d, but %s allows only %d IPv6 addresses per interface. Raise the instance type or lower the count.",
        var.attacker_addresses_per_subnet,
        var.attacker_instance_type,
        data.aws_ec2_instance_type.attacker.maximum_ipv6_addresses_per_interface,
      )
    }

    precondition {
      condition = data.aws_ec2_instance_type.attacker.maximum_network_interfaces >= 3
      error_message = format(
        "The attacker needs 3 interfaces to span three subnets, but %s allows only %d.",
        var.attacker_instance_type,
        data.aws_ec2_instance_type.attacker.maximum_network_interfaces,
      )
    }
  }

  network_interface {
    network_interface_id = aws_network_interface.attacker_primary.id
    device_index         = 0
  }

  # checkov:skip=CKV_AWS_79: IMDSv2 is enforced below.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/userdata/attacker.sh.tftpl", {
    target_a = aws_lb.twin["a"].dns_name
    target_b = aws_lb.twin["b"].dns_name
  })

  # Without this, Terraform updates the user_data attribute in place and
  # reports "1 changed" while the running host keeps the old script. The
  # bootstrap only ever executes once, at first boot, so a change to it is
  # only real if the instance is replaced.
  user_data_replace_on_change = true

  tags = merge(local.tags, {
    Name = "cosac-a-attacker"
    Role = "attacker"
  })
}

resource "aws_network_interface_attachment" "attacker_secondary" {
  for_each = aws_network_interface.attacker_secondary

  instance_id          = aws_instance.attacker.id
  network_interface_id = each.value.id
  device_index         = index(keys(aws_network_interface.attacker_secondary), each.key) + 1
}

# -- responder --------------------------------------------------------------
#
# Stands in for the incident response team. Its only job is to answer one
# question continuously, for both twins: can I still reach the application?
#
# Its subnet is the protected prefix Warden-A refuses to block and Warden-B
# blocks without noticing.

resource "aws_instance" "responder" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.host_instance_type
  subnet_id              = aws_subnet.this["responder"].id
  vpc_security_group_ids = [aws_security_group.host.id]
  iam_instance_profile   = aws_iam_instance_profile.host.name

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/userdata/responder.sh.tftpl", {
    target_a         = aws_lb.twin["a"].dns_name
    target_b         = aws_lb.twin["b"].dns_name
    metric_namespace = var.metric_namespace
    region           = var.region
    canary_path      = var.canary_path
  })

  # Without this, Terraform updates the user_data attribute in place and
  # reports "1 changed" while the running host keeps the old script. The
  # bootstrap only ever executes once, at first boot, so a change to it is
  # only real if the instance is replaced.
  user_data_replace_on_change = true

  tags = merge(local.tags, {
    Name = "cosac-a-responder"
    Role = "responder"
  })
}

# The responder publishes its own reachability, so the scoreboard reads from
# CloudWatch rather than from anything the demo operator types.
resource "aws_iam_role_policy" "responder_metrics" {
  name = "publish-canary-metrics"
  role = aws_iam_role.host.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "cloudwatch:PutMetricData"
      Resource = "*"
      Condition = {
        StringEquals = { "cloudwatch:namespace" = var.metric_namespace }
      }
    }]
  })
}
