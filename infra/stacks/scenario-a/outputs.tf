output "target_a" {
  description = "Warden-A application endpoint."
  value       = aws_lb.twin["a"].dns_name
}

output "target_b" {
  description = "Warden-B application endpoint."
  value       = aws_lb.twin["b"].dns_name
}

output "ipset_a" {
  value = { id = aws_wafv2_ip_set.block["a"].id, name = aws_wafv2_ip_set.block["a"].name }
}

output "ipset_b" {
  value = { id = aws_wafv2_ip_set.block["b"].id, name = aws_wafv2_ip_set.block["b"].name }
}

output "attacker_instance_id" {
  description = "Target of the SSM commands that start the demo."
  value       = aws_instance.attacker.id
}

output "responder_instance_id" {
  value = aws_instance.responder.id
}

output "vpc_ipv6_cidr" {
  description = "The VPC /56. Every subnet /64 is carved from it."
  value       = aws_vpc.lab.ipv6_cidr_block
}

output "responder_prefix" {
  description = "Warden-A's protected prefix. Set as WARDEN_PROTECTED_PREFIXES."
  value       = aws_subnet.this["responder"].ipv6_cidr_block
}

output "expected_aggregate" {
  description = <<-EOT
    The /62 that tightly covers the attacker's source addresses -- and also
    contains the responder subnet. Warden-A denies this; Warden-B writes it.
    Show this value next to the responder prefix during the talk.
  EOT
  value       = local.attacker_aggregate_v62
}
