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










# =============================================================================
# DATA SOURCES FOR DYNAMIC RESOURCE DISCOVERY
# =============================================================================
# Get all available AWS availability zones in the current region
data "aws_availability_zones" "available" {
  state = "available"
}










# =============================================================================
# EC2 KEY PAIR FOR SSH ACCESS
# =============================================================================
# Create EC2 Key Pair from local public key file for secure SSH access
resource "aws_key_pair" "main" {
  key_name   = "${var.project_name}-keypair"
  public_key = file(var.public_key_path)  # Read public key from local file

  tags = {
    Name        = "${var.project_name}-keypair"
    Environment = var.environment
  }
}










# =============================================================================
# IAM ROLES AND POLICIES FOR SESSION MANAGER ACCESS
# =============================================================================
# IAM Role that allows EC2 instances to use AWS Systems Manager Session Manager
# This enables secure shell access without SSH or bastion hosts
resource "aws_iam_role" "ssm_role" {
  name = "${var.project_name}-ssm-role"

  # Trust policy: Allow EC2 service to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-ssm-role"
    Environment = var.environment
  }
}

# Attach AWS managed policy that provides core Session Manager functionality
resource "aws_iam_role_policy_attachment" "ssm_managed_policy" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Instance profile to attach the IAM role to EC2 instances
resource "aws_iam_instance_profile" "ssm_profile" {
  name = "${var.project_name}-ssm-profile"
  role = aws_iam_role.ssm_role.name

  tags = {
    Name        = "${var.project_name}-ssm-profile"
    Environment = var.environment
  }
}

