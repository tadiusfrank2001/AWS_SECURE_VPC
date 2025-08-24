# =============================================================================
# TERRAFORM PROVIDER CONFIGURATION
# =============================================================================
# Configure Terraform to use AWS provider with version constraints
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # Use AWS provider version 5.x
    }
  }
}

# Configure AWS provider with region from variables
provider "aws" {
    profile = "terraform"  # matches the profile name in ~/.aws/credentials
    region = var.region
}