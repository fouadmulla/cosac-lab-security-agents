output "victim_a" {
  description = "Custodian-A's victim. Expected to be quarantined within seconds."
  value       = aws_instance.victim["a"].id
}

output "victim_b" {
  description = "Custodian-B's victim. Expected to keep exfiltrating."
  value       = aws_instance.victim["b"].id
}

output "isolation_security_group" {
  description = "No ingress, no egress. Swapping to this is the containment action."
  value       = aws_security_group.isolation.id
}

output "normal_security_group" {
  description = "Pre-compromise state. Restoring this reverses a quarantine."
  value       = aws_security_group.normal.id
}

output "sink_bucket" {
  value = aws_s3_bucket.sink.id
}

output "findings_log_group" {
  description = "Confirms genuine GuardDuty findings are arriving."
  value       = aws_cloudwatch_log_group.findings.name
}
