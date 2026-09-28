# Two ALBs, two web ACLs, two IPSets -- one per twin.
#
# The twins MUST NOT share a WAF, or Warden-B's over-broad block would lock
# the responders out of Warden-A's application too, and the side-by-side
# comparison would collapse into a single outcome.
#
# Everything else about the two paths is identical: same VPC, same subnets,
# same fixed response, same attacker traffic, same responder probe. The only
# asymmetry in the entire stack is the WARDEN_POLICY_PROFILE each agent reads.

locals {
  twins = {
    # A is the FLAWED one, B is the correct one. Deliberately this way round:
    # a reader starts at A, so the damage is seen first and B answers it.
    # Naming it so means no reordering anywhere -- one less thing to explain,
    # and one less thing to get backwards.
    a = { profile = "legacy", label = "warden-a" }
    b = { profile = "enforcing", label = "warden-b" }
  }
}

resource "aws_lb" "twin" {
  for_each = local.twins

  name               = "cosac-a-${each.key}"
  internal           = false
  load_balancer_type = "application"
  ip_address_type    = "dualstack"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.this["alb_a"].id, aws_subnet.this["alb_b"].id]

  # checkov:skip=CKV_AWS_150: Deletion protection off by design. This stack is
  # created and destroyed for each demo run; see .github/workflows/deploy.yml.
  enable_deletion_protection = false
  drop_invalid_header_fields = true

  tags = merge(local.tags, { Twin = each.value.label })
}

# The application is a fixed response. Nothing is stored, nothing is
# processed, and no backend instance is needed -- the demo turns on *who can
# reach it*, not on what it does.
resource "aws_lb_listener" "twin" {
  for_each = local.twins

  load_balancer_arn = aws_lb.twin[each.key].arn
  port              = 80
  protocol          = "HTTP"

  # checkov:skip=CKV_AWS_2: Plain HTTP is deliberate. TLS would require a
  # certificate and a domain for a load balancer that exists for ~30 minutes
  # and serves a constant string. No data traverses it.
  # checkov:skip=CKV_AWS_103: Same reason; no TLS policy to set without TLS.
  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
      message_body = "cosac demo application: ok"
    }
  }
}

# -- the IPSets the agents write to -----------------------------------------

resource "aws_wafv2_ip_set" "block" {
  for_each = local.twins

  name               = "cosac-a-${each.key}-block"
  description        = "Sources blocked by ${each.value.label}"
  scope              = "REGIONAL"
  ip_address_version = "IPV6"

  # Empty at deploy time. Every entry that appears here was written by an
  # agent during the demo -- which is what makes the IPSet contents worth
  # showing the audience afterwards.
  addresses = []

  lifecycle {
    # The agents mutate this out of band. Terraform must not revert their
    # decisions on the next plan; that is the evidence.
    ignore_changes = [addresses]
  }

  tags = merge(local.tags, { Twin = each.value.label })
}

# A WAF IPSet holds ONE address family, and the lab's topology is IPv6 -- so
# the set above cannot hold an IPv4 address. The agents are shown real WAF
# logs from a public load balancer, and the open internet is overwhelmingly
# IPv4: within an hour of deploying, the scanners arrive on /.env and /shell.
#
# Without this set the agent could see those scanners, reason about them
# correctly, ask for approval, be approved -- and the write would be rejected
# by WAF. Observed exactly once, live, which is how it was found.
resource "aws_wafv2_ip_set" "block_v4" {
  for_each = local.twins

  name               = "cosac-a-${each.key}-block-v4"
  description        = "IPv4 sources blocked by ${each.value.label}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = []

  lifecycle {
    ignore_changes = [addresses]
  }

  tags = merge(local.tags, { Twin = each.value.label })
}

resource "aws_wafv2_web_acl" "twin" {
  for_each = local.twins

  name        = "cosac-a-${each.key}"
  description = "Demo web ACL for ${each.value.label}"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "agent-blocklist"
    priority = 1

    action {
      block {}
    }

    # Either set blocks. One rule rather than two, so an entry in either
    # family is as effective as an entry in the other -- and so the audience
    # sees one blocklist rather than a filing system.
    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.block[each.key].arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.block_v4[each.key].arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "cosac-a-${each.key}-blocked"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "cosac-a-${each.key}"
    sampled_requests_enabled   = true
  }

  tags = merge(local.tags, { Twin = each.value.label })
}

resource "aws_wafv2_web_acl_association" "twin" {
  for_each = local.twins

  resource_arn = aws_lb.twin[each.key].arn
  web_acl_arn  = aws_wafv2_web_acl.twin[each.key].arn
}

# -- logging ----------------------------------------------------------------
#
# CloudWatch Logs, not Firehose to S3. Firehose buffers for 60s or more, which
# on stage means narrating a spinner while the audience waits. This path
# delivers in seconds.

resource "aws_cloudwatch_log_group" "waf" {
  for_each = local.twins

  # WAF requires the aws-waf-logs- prefix.
  name              = "aws-waf-logs-cosac-a-${each.key}"
  retention_in_days = 7

  # checkov:skip=CKV_AWS_158: Default encryption is sufficient for synthetic
  # demo traffic that contains no real data. A CMK adds cost and key
  # management to a log group that lives for a day.
  tags = merge(local.tags, { Twin = each.value.label })
}

resource "aws_wafv2_web_acl_logging_configuration" "twin" {
  for_each = local.twins

  resource_arn            = aws_wafv2_web_acl.twin[each.key].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[each.key].arn]
}
