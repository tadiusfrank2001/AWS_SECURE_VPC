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


# Get current AWS account ID for policies
data "aws_caller_identity" "current" {}






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
# RANDOM RESOURCES FOR DYNAMIC CONFIGURATIONS
# =============================================================================
# Generate random CIDR blocks for subnets within the VPC
resource "random_id" "vpc_cidr" {
  byte_length = 1
  keepers = {
    project = var.project_name
  }
}

# Generate secure random passwords for team members
resource "random_password" "red_team_passwords" {
  count   = 2
  length  = 16
  special = true
}

resource "random_password" "blue_team_passwords" {
  count   = 2
  length  = 16
  special = true
}










# =============================================================================
# LOCAL VALUES FOR DYNAMIC CIDR CALCULATION
# =============================================================================
locals {
  # Calculate VPC CIDR block dynamically
  vpc_cidr = "10.${random_id.vpc_cidr.dec}.0.0/16"
  
  # Calculate subnet CIDR blocks within the VPC
  public_subnet_cidr     = "10.${random_id.vpc_cidr.dec}.1.0/24"
  private_app_subnet_cidr = "10.${random_id.vpc_cidr.dec}.2.0/24"
  private_db_subnet_cidr  = "10.${random_id.vpc_cidr.dec}.3.0/24"
  
  # Team member configurations
  red_team_members = [
    {
      username = "${var.project_name}-red-member-1"
      password = random_password.red_team_passwords[0].result
    },
    {
      username = "${var.project_name}-red-member-2"
      password = random_password.red_team_passwords[1].result
    }
  ]
  
  blue_team_members = [
    {
      username = "${var.project_name}-blue-member-1"
      password = random_password.blue_team_passwords[0].result
    },
    {
      username = "${var.project_name}-blue-member-2"
      password = random_password.blue_team_passwords[1].result
    }
  ]
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


# Attach Blue Team policy to group
resource "aws_iam_group_policy_attachment" "blue_team_policy_attachment" {
  group      = aws_iam_group.blue_team.name
  policy_arn = aws_iam_policy.blue_team_policy.arn
}

# Blue Team IAM Users
resource "aws_iam_user" "blue_team_members" {
  count = length(local.blue_team_members)
  name  = local.blue_team_members[count.index].username

  tags = {
    Name        = local.blue_team_members[count.index].username
    Team        = "Blue"
    Environment = var.environment
  }
}

# Blue Team User Login Profiles
resource "aws_iam_user_login_profile" "blue_team_profiles" {
  count   = length(local.blue_team_members)
  user    = aws_iam_user.blue_team_members[count.index].name
  password = local.blue_team_members[count.index].password
  password_reset_required = true
}

# Add Blue Team users to group
resource "aws_iam_group_membership" "blue_team_membership" {
  name  = "${var.project_name}-blue-team-membership"
  group = aws_iam_group.blue_team.name
  users = aws_iam_user.blue_team_members[*].name
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


# Attach Red Team policy to group
resource "aws_iam_group_policy_attachment" "red_team_policy_attachment" {
  group      = aws_iam_group.red_team.name
  policy_arn = aws_iam_policy.red_team_policy.arn
}

# Red Team IAM Users
resource "aws_iam_user" "red_team_members" {
  count = length(local.red_team_members)
  name  = local.red_team_members[count.index].username

  tags = {
    Name        = local.red_team_members[count.index].username
    Team        = "Red"
    Environment = var.environment
  }
}

# Red Team User Login Profiles
resource "aws_iam_user_login_profile" "red_team_profiles" {
  count   = length(local.red_team_members)
  user    = aws_iam_user.red_team_members[count.index].name
  password = local.red_team_members[count.index].password
  password_reset_required = true
}

# Add Red Team users to group
resource "aws_iam_group_membership" "red_team_membership" {
  name  = "${var.project_name}-red-team-membership"
  group = aws_iam_group.red_team.name
  users = aws_iam_user.red_team_members[*].name
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
  availability_zone = data.aws_availability_zones.available.names[0] 

  tags = {
    Name        = "${var.project_name}-private-db-subnet"
    Type        = "Private"
    Tier        = "Database"
    Environment = var.environment
  }
}














# =============================================================================
# NAT GATEWAY FOR PRIVATE SUBNET INTERNET ACCESS
# =============================================================================
# Elastic IP for NAT Gateway (static IP for outbound internet access)# Elastic IP for NAT Gateway (static IP for outbound internet access)
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name        = "${var.project_name}-nat-eip"
    Environment = var.environment
  }

  depends_on = [aws_internet_gateway.main]
}

# NAT Gateway allows private subnets to access internet for updates/patches
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name        = "${var.project_name}-nat-gateway"
    Environment = var.environment
  }

  depends_on = [aws_internet_gateway.main]
}











# =============================================================================
# ROUTING TABLES AND ASSOCIATIONS
# =============================================================================
# Public Route Table - Routes internet traffic through Internet Gateway
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"  # All internet traffic
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "${var.project_name}-public-rt"
    Type        = "Public"
    Environment = var.environment
  }
}

# Private Route Table - Routes internet traffic through NAT Gateway
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"  # All internet traffic
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name        = "${var.project_name}-private-rt"
    Type        = "Private"
    Environment = var.environment
  }
}

# Associate public subnet with public route table
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Associate private app subnet with private route table
resource "aws_route_table_association" "private_app" {
  subnet_id      = aws_subnet.private_app.id
  route_table_id = aws_route_table.private.id
}

# Associate private DB subnet with private route table
resource "aws_route_table_association" "private_db" {
  subnet_id      = aws_subnet.private_db.id
  route_table_id = aws_route_table.private.id
}


















# =============================================================================
# SECURITY GROUPS
# =============================================================================
# Security Group for Kali Linux
resource "aws_security_group" "kali_sg" {
  name        = "${var.project_name}-kali-sg"
  description = "Security group for Kali Linux instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-kali-sg"
    Environment = var.environment
  }
}

# Security Group for Application Server
resource "aws_security_group" "app_sg" {
  name        = "${var.project_name}-app-sg"
  description = "Security group for application server"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-app-sg"
    Environment = var.environment
  }
}

# Security Group for Database Server
resource "aws_security_group" "db_sg" {
  name        = "${var.project_name}-db-sg"
  description = "Security group for database server"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "MySQL from app"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  ingress {
    description = "SSH for monitoring"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.private_app_subnet_cidr]
  }

  egress {
    description = "HTTP for updates"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS for updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-db-sg"
    Environment = var.environment
  }
}


















# =============================================================================
# AMI DATA SOURCES FOR INSTANCE CREATION
# =============================================================================
# Get latest Amazon Linux 2 AMI for bastion and target instances
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Get latest Kali Linux AMI from official Kali Linux account
data "aws_ami" "kali_linux" {
  most_recent = true
  owners      = ["679593333241"]  # Official Kali Linux AWS account

  filter {
    name   = "name"
    values = ["kali-linux-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}










# =============================================================================
# EC2 INSTANCES - RED/BLUE TEAM LAB INFRASTRUCTURE
# =============================================================================


# Kali Linux Instance - Red Team attack platform
resource "aws_instance" "kali" {
  ami                    = data.aws_ami.kali_linux.id
  instance_type          = var.kali_instance_type
  key_name               = aws_key_pair.main.key_name
  vpc_security_group_ids = [aws_security_group.kali_sg.id]
  subnet_id              = aws_subnet.public.id
  iam_instance_profile   = aws_iam_instance_profile.ssm_profile.name

  user_data = file("${path.module}/scripts/kali_init.sh")

  tags = {
    Name        = "${var.project_name}-kali"
    Team        = "Red"
    Role        = "Attack-Platform"
    Environment = var.environment
  }
}




# Application Server - Target infrastructure for Red Team attacks
resource "aws_instance" "app_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.app_instance_type
  key_name               = aws_key_pair.main.key_name
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  subnet_id              = aws_subnet.private_app.id
  iam_instance_profile   = aws_iam_instance_profile.ssm_profile.name

  user_data = templatefile("${path.module}/scripts/app_server_init.sh", {
    db_server_ip = aws_instance.db_server.private_ip
  })

  tags = {
    Name        = "${var.project_name}-app-server"
    Team        = "Target"
    Tier        = "Application"
    Environment = var.environment
  }
}


# Database Server (Target)
resource "aws_instance" "db_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.db_instance_type
  key_name               = aws_key_pair.main.key_name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  subnet_id              = aws_subnet.private_db.id
  iam_instance_profile   = aws_iam_instance_profile.ssm_profile.name

  user_data = file("${path.module}/scripts/db_server_init.sh")

  tags = {
    Name        = "${var.project_name}-db-server"
    Team        = "Target"
    Tier        = "Database"
    Environment = var.environment
  }
}


# =============================================================================
# GUARDDUTY CONFIGURATION FOR THREAT DETECTION
# =============================================================================
# Enable GuardDuty Detector
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false # Not using EKS in this setup
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name        = "${var.project_name}-guardduty-detector"
    Environment = var.environment
  }
}

# GuardDuty ThreatIntelSet (optional - for custom threat intelligence)
resource "aws_guardduty_threatintelset" "main" {
  count       = var.enable_custom_threat_intel ? 1 : 0
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.guardduty_bucket[0].bucket}/threat-intel/threats.txt"
  name        = "${var.project_name}-threat-intel"

  depends_on = [aws_s3_bucket_object.threat_intel[0]]

  tags = {
    Name        = "${var.project_name}-threat-intel"
    Environment = var.environment
  }
}

# S3 Bucket for GuardDuty findings and threat intelligence
resource "aws_s3_bucket" "guardduty_bucket" {
  count  = var.enable_custom_threat_intel ? 1 : 0
  bucket = "${var.project_name}-guardduty-${random_id.vpc_cidr.hex}"

  tags = {
    Name        = "${var.project_name}-guardduty-bucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "guardduty_bucket_versioning" {
  count  = var.enable_custom_threat_intel ? 1 : 0
  bucket = aws_s3_bucket.guardduty_bucket[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_bucket_encryption" {
  count  = var.enable_custom_threat_intel ? 1 : 0
  bucket = aws_s3_bucket.guardduty_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Sample threat intelligence file (includes common scanning IPs)
resource "aws_s3_bucket_object" "threat_intel" {
  count  = var.enable_custom_threat_intel ? 1 : 0
  bucket = aws_s3_bucket.guardduty_bucket[0].bucket
  key    = "threat-intel/threats.txt"
  content = <<-EOT
# Sample threat intelligence - known scanning IPs
# Add your custom threat intelligence IPs here
192.0.2.1
198.51.100.1
203.0.113.1
EOT

  tags = {
    Name        = "${var.project_name}-threat-intel-file"
    Environment = var.environment
  }
}

# EventBridge rule to capture GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-findings"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Recon:EC2/PortProbeUnprotectedPort",
        "Recon:EC2/Portscan",
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "UnauthorizedAccess:EC2/RDPBruteForce",
        "Backdoor:EC2/XORDDOS",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "Trojan:EC2/DropPoint",
        "Behavior:EC2/NetworkPortUnusual",
        "Behavior:EC2/TrafficVolumeUnusual"
      ]
    }
  })

  tags = {
    Name        = "${var.project_name}-guardduty-findings-rule"
    Environment = var.environment
  }
}

# EventBridge target to send GuardDuty findings to SNS
resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuardDutyFindingsToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      instance_id = "$.detail.service.resourceRole.detailType.instanceDetails.instanceId"
      title       = "$.detail.title"
      description = "$.detail.description"
      region      = "$.detail.region"
    }

    input_template = <<-EOT
{
  "alert_type": "GuardDuty Finding",
  "severity": "<severity>",
  "finding_type": "<type>",
  "title": "<title>",
  "description": "<description>",
  "instance_id": "<instance_id>",
  "region": "<region>",
  "timestamp": "$.detail.service.eventFirstSeen"
}
EOT
  }
}


