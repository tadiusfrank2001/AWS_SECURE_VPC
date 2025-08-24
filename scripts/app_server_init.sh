#!/bin/bash


# ==========================================================================
# Boot-time setup script for App Server (Private Subnet)
# - Update OS packages
# - Install and start SSM Agent
# - Install and start CloudWatch Agent
# ==========================================================================

# 1️ Update and upgrade system packages
yum update -y
yum upgrade -y

# 2️ Install SSM Agent (Amazon Linux 2 usually pre-installed, just ensure running)
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# 3️ Install CloudWatch Agent
# Download CloudWatch Agent package
yum install -y amazon-cloudwatch-agent

# Enable and start CloudWatch Agent
# Using default config to capture system logs and metrics
systemctl enable amazon-cloudwatch-agent
systemctl start amazon-cloudwatch-agent

# 4️ Optional: Verify status
systemctl status amazon-ssm-agent --no-pager
systemctl status amazon-cloudwatch-agent --no-pager

echo "Boot-time setup complete!"