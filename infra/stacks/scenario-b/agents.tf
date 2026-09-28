# Trigger shims for the two Custodian agents.
#
# The agents live on AgentCore Runtime -- see agentcore.tf. EventBridge cannot
# call InvokeAgentRuntime, so these forward the finding and return the answer.
# They decide nothing.

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
  name = "cosac-b-agent"

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
      {
        Effect   = "Allow"
        Action   = "bedrock-agentcore:InvokeAgentRuntime"
        Resource = [for r in aws_bedrockagentcore_agent_runtime.custodian : "${r.agent_runtime_arn}*"]
      },
    ]
  })
}

resource "aws_lambda_function" "custodian" {
  for_each = local.twins

  function_name = "cosac-custodian-${each.key}"
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
      AGENT_RUNTIME_ARN = aws_bedrockagentcore_agent_runtime.custodian[each.key].agent_runtime_arn
    }
  }

  # checkov:skip=CKV_AWS_116: see scenario-a/agents.tf
  # checkov:skip=CKV_AWS_117: see scenario-a/agents.tf
  # checkov:skip=CKV_AWS_173: environment holds no secrets
  # checkov:skip=CKV_AWS_272: disproportionate for a per-demo stack
  tags = merge(local.tags, { Twin = each.value.label })
}

resource "aws_cloudwatch_log_group" "custodian" {
  for_each = local.twins

  name              = "/aws/lambda/cosac-custodian-${each.key}"
  retention_in_days = 7

  # checkov:skip=CKV_AWS_158: default encryption is enough for demo traffic
  tags = merge(local.tags, { Twin = each.value.label })
}

# -- what wakes the agents up -----------------------------------------------
#
# Both twins are targets of the SAME EventBridge rule, so both are told about
# every finding at the same instant. Each then ignores findings that do not
# implicate its own instance. That symmetry is load-bearing: if one twin heard
# about the compromise sooner than the other, the comparison would mean
# nothing.

resource "aws_cloudwatch_event_target" "custodian" {
  for_each = local.twins

  rule      = aws_cloudwatch_event_rule.guardduty_finding.name
  target_id = "custodian-${each.key}"
  arn       = aws_lambda_function.custodian[each.key].arn
}

resource "aws_lambda_permission" "events" {
  for_each = local.twins

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.custodian[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_finding.arn
}
