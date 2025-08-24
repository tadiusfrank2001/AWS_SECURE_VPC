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







# =============================================================================
# BLUE TEAM IAM GROUP AND COMPREHENSIVE ACCESS POLICIES
# =============================================================================
# IAM Group for Blue Team members with monitoring and incident response capabilities
resource "aws_iam_group" "blue_team" {
  name = "${var.project_name}-blue-team"
  path = "/"
}

# Blue Team Policy - Provides comprehensive access for monitoring, defense, and response
resource "aws_iam_policy" "blue_team_policy" {
  name        = "${var.project_name}-blue-team-policy"
  description = "Policy for Blue Team members - Monitoring and response access"

  # Load policy document from external JSON file for maintainability
  policy = templatefile("${path.module}/scripts/blue-team-policy.json", {
    region = var.region  # Pass region variable to template
  })

  tags = {
    Name        = "${var.project_name}-blue-team-policy"
    Environment = var.environment
  }
}

# Attach Blue Team policy to Blue Team group
resource "aws_iam_group_policy_attachment" "blue_team_policy_attachment" {
  group      = aws_iam_group.blue_team.name
  policy_arn = aws_iam_policy.blue_team_policy.arn
}









# =============================================================================
# RED TEAM IAM GROUP AND RESTRICTED ACCESS POLICIES
# =============================================================================
# IAM Group for Red Team members with limited access to attack infrastructure
resource "aws_iam_group" "red_team" {
  name = "${var.project_name}-red-team"
  path = "/"
}

# Red Team Policy - Restricts access to only Kali Linux instances tagged with Team=Red
resource "aws_iam_policy" "red_team_policy" {
  name        = "${var.project_name}-red-team-policy"
  description = "Policy for Red Team members - Kali instance access only"

  # Load policy document from external JSON file for maintainability
  policy = file("${path.module}/scripts/red-team-policy.json")

  tags = {
    Name        = "${var.project_name}-red-team-policy"
    Environment = var.environment
  }
}

# Attach Red Team policy to Red Team group
resource "aws_iam_group_policy_attachment" "red_team_policy_attachment" {
  group      = aws_iam_group.red_team.name
  policy_arn = aws_iam_policy.red_team_policy.arn
}










# =============================================================================
# SUBNET CONFIGURATION - THREE-TIER ARCHITECTURE
# =============================================================================
# Public Subnet - Houses bastion host and Kali Linux (Red Team) instance
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true  # Auto-assign public IPs

  tags = {
    Name        = "${var.project_name}-public-subnet"
    Type        = "Public"
    Environment = var.environment
  }
}

# Private Application Subnet - Houses application servers (Target infrastructure)
resource "aws_subnet" "private_app" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_app_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name        = "${var.project_name}-private-app-subnet"
    Type        = "Private"
    Tier        = "Application"
    Environment = var.environment
  }
}

# Private Database Subnet - Houses database servers (Most protected tier)
resource "aws_subnet" "private_db" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_db_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[1]  # Different AZ for redundancy

  tags = {
    Name        = "${var.project_name}-private-db-subnet"
    Type        = "Private"
    Tier        = "Database"
    Environment = var.environment
  }
}