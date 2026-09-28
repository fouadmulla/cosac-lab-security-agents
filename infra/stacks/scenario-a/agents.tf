# Trigger shims for the two Warden agents.
#
# The agents themselves live on AgentCore Runtime -- see agentcore.tf. These
# functions exist only because a CloudWatch Logs subscription cannot call
# InvokeAgentRuntime, so something has to sit between them.
#
# They take no decisions and touch no resources. Their IAM says so: one
# action, on one runtime each.

# Each file is placed explicitly under agents/ inside the zip. source_dir
# would put the *contents* of agents/ at the archive root, and then
# `from agents.common...` -- which is how the package imports itself, and how
# the tests import it -- would fail at runtime inside Lambda while passing
# everywhere else. Placing the files keeps one import path for both.
data "archive_file" "agent" {
  type        = "zip"
  output_path = "${path.module}/.build/agent.zip"

  dynamic "source" {
    for_each = fileset("${path.module}/../../../agents", "**/*.py")
    content {
      content  = file("${path.module}/../../../agents/${source.value}")
      filename = "agents/${source.value}"
    }
  }
}

resource "aws_iam_role" "agent" {
  name = "cosac-a-agent"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "agent" {
  name = "invoke-the-runtime"
  role = aws_iam_role.agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
      # The whole of the shim's authority. It can wake an agent and nothing
      # else -- no WAF, no ledger, no model.
      {
        Effect   = "Allow"
        Action   = "bedrock-agentcore:InvokeAgentRuntime"
        Resource = [for r in aws_bedrockagentcore_agent_runtime.warden : "${r.agent_runtime_arn}*"]
      },
    ]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_lambda_function" "warden" {
  for_each = local.twins

  function_name = "cosac-warden-${each.key}"
  role          = aws_iam_role.agent.arn
  handler       = "agents.invoker.handler"
  runtime       = "python3.12"
  timeout       = 300
  memory_size   = 256

  # Bounding how many copies of an agent may run at once is a Constrain
  # control, not a cost control. A log subscription can deliver in bursts, and
  # an agent that fans out to fifty concurrent invocations is fifty
  # independent decisions nobody is rate-limiting.
  reserved_concurrent_executions = 2

  # Record: every invocation is traceable end to end, including the Bedrock
  # call and the AWS write it leads to.
  tracing_config {
    mode = "Active"
  }

  filename         = data.archive_file.agent.output_path
  source_code_hash = data.archive_file.agent.output_base64sha256

  environment {
    variables = {
      AGENT_RUNTIME_ARN = aws_bedrockagentcore_agent_runtime.warden[each.key].agent_runtime_arn
    }
  }

  # checkov:skip=CKV_AWS_116: A dead-letter queue would hide failures behind
  # an extra hop during a live demo. Failures are read from the function's own
  # log group, which the operator already has open.
  # checkov:skip=CKV_AWS_117: Not in a VPC on purpose -- the agent talks only
  # to AWS service endpoints, and a VPC would need NAT or endpoints for no
  # security gain in a lab that holds nothing.
  # checkov:skip=CKV_AWS_173: Environment holds no secrets, only names and ids.
  # checkov:skip=CKV_AWS_272: Code signing is disproportionate for a stack
  # created and destroyed per demo.
  tags = merge(local.tags, { Twin = each.value.label })
}

resource "aws_cloudwatch_log_group" "warden" {
  for_each = local.twins

  name              = "/aws/lambda/cosac-warden-${each.key}"
  retention_in_days = 7

  # checkov:skip=CKV_AWS_158: Default encryption is enough for demo traffic.
  tags = merge(local.tags, { Twin = each.value.label })
}

# -- what wakes the agents up -----------------------------------------------
#
# A subscription filter, so each agent is invoked as WAF lines are written
# rather than on a timer. Both subscribe to their own twin's log group, so
# neither can see the other's traffic.

resource "aws_lambda_permission" "logs" {
  for_each = local.twins

  statement_id  = "AllowLogsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.warden[each.key].function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.waf[each.key].arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "warden" {
  for_each = local.twins

  name           = "cosac-warden-${each.key}"
  log_group_name = aws_cloudwatch_log_group.waf[each.key].name
  # Allowed requests only -- one already blocked needs no further decision --
  # and never the canary. A SOC allowlists its own monitoring; leaving it in
  # means the agent is woken every few seconds by its own side and reasons
  # about traffic it should never act on.
  filter_pattern  = "{ $.action = \"ALLOW\" && $.httpRequest.uri != \"${var.canary_path}\" }"
  destination_arn = aws_lambda_function.warden[each.key].arn

  depends_on = [aws_lambda_permission.logs]
}
