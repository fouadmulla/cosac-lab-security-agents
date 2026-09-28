variable "region" {
  description = "AWS region. us-east-1 is nearest to North Carolina and has the broadest Bedrock and AgentCore coverage."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "IPv4 CIDR. Present only so Systems Manager can reach the hosts; the demo itself is IPv6."
  type        = string
  default     = "10.90.0.0/16"
}

variable "host_instance_type" {
  description = "The responder. Only runs a curl loop."
  type        = string
  default     = "t3.micro"
}

variable "attacker_instance_type" {
  description = <<-EOT
    The attacker needs three interfaces and several IPv6 addresses on each,
    and both are capped by instance type. t3.micro allows 2 interfaces and 2
    addresses each; t3.medium allows 3 and 6. Checked at plan time by a
    precondition in hosts.tf.
  EOT
  type        = string
  default     = "t3.medium"
}

variable "attacker_addresses_per_subnet" {
  description = "IPv6 addresses per attacker interface. Three interfaces, so 6 gives 18 sources."
  type        = number
  default     = 6

  validation {
    condition     = var.attacker_addresses_per_subnet >= 2
    error_message = "Below 2 there is nothing to aggregate. The upper bound depends on the instance type and is enforced by a precondition in hosts.tf."
  }
}

variable "metric_namespace" {
  type    = string
  default = "COSAC/ScenarioA"
}

variable "ledger_table" {
  type    = string
  default = "cosac-decision-ledger"
}

variable "availability_zones" {
  description = "Pinned, not discovered. A demo topology that reshuffles when AWS adds a zone is a demo that fails on stage."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "model_id" {
  description = <<-EOT
    The model both twins call. A frontier model is the right choice here: if
    the demo used a weak one, the first question from any audience is "would a
    better model have caught it?", and that question dissolves the argument.
  EOT
  type        = string
  default     = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}

variable "canary_path" {
  description = <<-EOT
    The path the responder's monitoring uses. Excluded from what the agents
    are shown, the way a SOC allowlists its own probes. Without it the canary
    is the only traffic whenever the attacker is quiet, and both agents spend
    the idle time reasoning about their own side.
  EOT
  type        = string
  default     = "/__canary"
}

variable "lookback_minutes" {
  description = <<-EOT
    How far back an agent reads when it wakes. Shorter means a cleared
    blocklist stays cleared sooner: the agent re-reads the window on every
    invocation, so traffic still inside it will be acted on again.
  EOT
  type        = number
  default     = 5
}
