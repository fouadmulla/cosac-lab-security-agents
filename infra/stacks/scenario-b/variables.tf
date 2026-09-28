variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.91.0.0/16"
}

variable "victim_instance_type" {
  description = "Deliberately small. A quarantine agent's unilateral authority is scoped to instance types like this one."
  type        = string
  default     = "t3.micro"
}

variable "guardduty_test_domain" {
  description = <<-EOT
    AWS's documented GuardDuty C2 test domain. Resolving it produces a genuine
    Backdoor:EC2/C&CActivity.B!DNS finding from the real detector. It resolves
    to a sinkhole and carries no payload.
  EOT
  type        = string
  default     = "guarddutyc2activityb.com"
}

variable "egress_bytes_per_tick" {
  description = "Synthetic bytes per 2-second exfiltration tick."
  type        = number
  default     = 65536
}

variable "metric_namespace" {
  type    = string
  default = "COSAC/ScenarioB"
}

variable "availability_zones" {
  description = "Pinned, not discovered, for the same reason as Scenario A."
  type        = list(string)
  default     = ["us-east-1a"]
}

variable "ledger_table" {
  type    = string
  default = "cosac-decision-ledger"
}

variable "model_id" {
  description = "The model both twins call. Same for each, by design."
  type        = string
  default     = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}
