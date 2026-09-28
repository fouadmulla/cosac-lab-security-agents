terraform {
  required_version = ">= 1.10.0"

  # Terraform 1.10+ locks natively against S3, so the bootstrap does not carry
  # a DynamoDB lock table. Backend settings come from -backend-config in CI.
  backend "s3" {
    key          = "scenario-a/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.65"
    }
    # Packages the agent source into the Lambda zip at plan time, so a code
    # change is visible in the plan as a changed source hash.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "cosac"
      Scenario  = "a-warden"
      ManagedBy = "terraform"
    }
  }
}

locals {
  tags = {
    Project  = "cosac"
    Scenario = "a-warden"
  }
}
