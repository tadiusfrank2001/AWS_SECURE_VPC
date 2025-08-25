
#!/bin/bash

# Kali Linux Red Team Instance Initialization Script
# Lightweight setup for VPC Flow Log testing

# Update system packages
apt update -y
apt upgrade -y


# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

# Install SSM Agent (needed for EC2 to connect to AWS Systems Manager)
snap install amazon-ssm-agent --classic

# Enable and start the SSM Agent service
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
systemctl status amazon-ssm-agent --no-pager