
# AWS Secure VPC for Cyberattack Simulations

A comprehensive AWS-based cybersecurity training environment that simulates real-world attack and defense scenarios using Terraform Infrastructure as Code.

## 🎯 Overview

This project creates an isolated AWS environment where Red Team members can practice penetration testing while Blue Team members learn to detect, monitor, and respond to security threats. The infrastructure includes intentionally vulnerable applications, comprehensive monitoring, and realistic network segmentation.

## 📋 Prerequisites

### Required Software
1. **AWS CLI v2** - Command line interface for AWS
2. **Terraform** >= 1.0 - Infrastructure as Code tool
3. **SSH Key Pair** - For secure access (though we'll use Session Manager primarily)

### AWS CLI Installation

#### Windows
```powershell
# Download and install AWS CLI v2
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```

#### macOS
```bash
# Using Homebrew
brew install awscli

# Or download installer
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
```

#### Linux
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### AWS Credentials Setup

1. **Create AWS Credentials File**
   ```bash
   mkdir -p ~/.aws
   ```

2. **Configure Credentials** (`~/.aws/credentials`):
   ```ini
   [terraform]
   aws_access_key_id = YOUR_ACCESS_KEY_HERE
   aws_secret_access_key = YOUR_SECRET_KEY_HERE
   region = us-east-1
   ```

3. **Verify Configuration**:
   ```bash
   aws sts get-caller-identity --profile terraform
   ```

## 📁 Project Structure

```
red-blue-team-lab/
├── 📄 README.md                    # This file
├── 📄 .gitignore                   # Git ignore rules
├── 📄 main.tf                      # Main Terraform configuration
├── 📄 variables.tf                 # Input variables
├── 📄 outputs.tf                   # Output values
├── 📄 terraform.tfvars             # Your variable values (create this)
└── 📁 scripts/                     # Initialization scripts
    ├── 📄 app_server_init.sh       # Vulnerable web app setup
    ├── 📄 kali_init.sh              # Red team tools setup
    ├── 📄 db_server_init.sh         # Database server setup
    ├── 📄 blue-team-policy.json     # Blue team IAM policy
    └── 📄 red-team-policy.json      # Red team IAM policy
```

## ⚙️ Setup Instructions

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd red-blue-team-lab
```

### Step 2: Create SSH Key Pair
```bash
# Generate SSH key pair if you don't have one
ssh-keygen -t rsa -b 4096 -f ~/.ssh/red_blue_lab_key
```

### Step 3: Create terraform.tfvars File

Create a `terraform.tfvars` file in the project root:

```hcl
# AWS Configuration
region         = "us-east-1"
my_ip          = "YOUR_IP_HERE/32"        # Get with: curl ifconfig.me
alert_email    = "admin@yourcompany.com"

# SSH Key Configuration  
public_key_path = "~/.ssh/red_blue_lab_key.pub"

# Project Configuration
project_name   = "cybersec-lab"
environment    = "lab"

# Instance Types (Free Tier)
kali_instance_type = "t3.micro"
app_instance_type  = "t3.micro"
db_instance_type   = "t3.micro"

# Network Configuration (Optional - uses dynamic CIDR by default)
# vpc_cidr                = "10.0.0.0/16"
# public_subnet_cidr      = "10.0.1.0/24"
# private_app_subnet_cidr = "10.0.2.0/24"
# private_db_subnet_cidr  = "10.0.3.0/24"
```

### Step 4: Get Your Public IP
```bash
# Find your public IP address
curl ifconfig.me

# Add /32 to the end for CIDR format
# Example: 203.0.113.45/32
```

### Step 5: Initialize and Deploy
```bash
# Initialize Terraform
terraform init

# Review the deployment plan
terraform plan

# Deploy infrastructure (type 'yes' when prompted)
terraform apply

# Save outputs to file
terraform output -json > lab_outputs.json
```

## 🏗️ AWS Services Used

This lab utilizes the following AWS services:

- **🌐 VPC** - Virtual Private Cloud for network isolation
- **🔒 EC2** - Virtual machines for Red/Blue team infrastructure
- **🛡️ Security Groups** - Network-level firewall rules
- **🚪 Internet Gateway** - Internet access for public subnet
- **🔄 NAT Gateway** - Outbound internet for private subnets
- **📊 CloudWatch** - Logging, monitoring, and alerting
- **📧 SNS** - Email notifications for security alerts
- **🔐 IAM** - Identity and Access Management for team members
- **📝 VPC Flow Logs** - Network traffic analysis
- **🖥️ Systems Manager** - Secure instance access via Session Manager
- **🔑 EC2 Key Pairs** - SSH key management

## 🔐 Secure Access with AWS Session Manager

**⚠️ IMPORTANT: NO SSH REQUIRED FOR SECURITY**

This lab uses AWS Systems Manager Session Manager for secure access to instances. This eliminates the need for SSH connections, bastion hosts, or exposing SSH ports to the internet.

### Access Methods

#### 1. AWS Management Console (GUI)
1. Navigate to **EC2 Console**
2. Select your instance
3. Click **"Connect"**
4. Choose **"Session Manager"** tab
5. Click **"Connect"**

#### 2. AWS CLI (Command Line)
```bash
# Access Kali Linux (Red Team)
aws ssm start-session --target i-1234567890abcdef0 --profile terraform

# Access Application Server
aws ssm start-session --target i-abcdef1234567890 --profile terraform

# Access Database Server  
aws ssm start-session --target i-567890abcdef1234 --profile terraform
```

#### 3. Get Instance IDs from Terraform Output
```bash
# View all connection information
terraform output connection_info

# Get specific instance ID
terraform output -raw connection_info | jq '.kali_id'
```

### Session Manager Benefits
- ✅ **No SSH keys to manage**
- ✅ **No bastion hosts required**
- ✅ **All sessions logged in CloudTrail**
- ✅ **IAM-based access control**
- ✅ **No inbound ports needed**

## 👥 Team Credentials

After deployment, team member credentials are generated and can be accessed securely:

```bash
# View all team credentials (sensitive output)
terraform output team_credentials

# Save credentials to JSON file
terraform output -json team_credentials > team_credentials.json
```

### Credential Structure
```json
{
  "red_team": {
    "cybersec-lab-red-member-1": {
      "username": "cybersec-lab-red-member-1",
      "password": "RandomSecurePassword123!"
    },
    "cybersec-lab-red-member-2": {
      "username": "cybersec-lab-red-member-2", 
      "password": "AnotherRandomPassword456!"
    }
  },
  "blue_team": {
    "cybersec-lab-blue-member-1": {
      "username": "cybersec-lab-blue-member-1",
      "password": "BlueTeamPassword789!"
    },
    "cybersec-lab-blue-member-2": {
      "username": "cybersec-lab-blue-member-2",
      "password": "MonitoringPassword012!"
    }
  }
}
```

## 🎮 Training Scenarios

### Red Team Objectives

#### Access Your Attack Platform
```bash
# Get Kali instance ID
KALI_ID=$(terraform output -raw connection_info | jq -r '.kali_id')

# Connect via Session Manager
aws ssm start-session --target $KALI_ID --profile terraform
```

#### Target Infrastructure
- **Web Application**: Access via private IP from Kali instance
- **Database Server**: Network reachable from application subnet

#### Attack Vectors Available

1. **SQL Injection**
   - **Target**: `/login.php`
   - **Payload**: `admin' OR '1'='1' --`
   - **Flag**: `FLAG{SQL_INJECTION_SUCCESS}`

2. **Command Injection**
   - **Target**: `/admin.php?auth=admin123`
   - **Payload**: `127.0.0.1; whoami`
   - **Flag**: `FLAG{COMMAND_INJECTION_ACCESS}`

3. **Directory Traversal**
   - **Target**: `/files.php?file=`
   - **Payload**: `../../../etc/passwd`
   - **Flag**: `FLAG{DIRECTORY_TRAVERSAL_READY}`

4. **Network Reconnaissance**
   ```bash
   # Port scanning
   nmap -sS [target-subnet]
   
   # Service enumeration
   nmap -sV -p- [target-ip]
   
   # Database probing
   nmap -p 3306 --script mysql-enum [db-ip]
   ```

### Blue Team Objectives

#### Access Monitoring Dashboard
```bash
# Get security dashboard URL
terraform output security_monitoring
```

#### Detection Capabilities
- **Port Scan Detection** - Automated alerts for >10 rejected connections
- **SSH Brute Force Monitoring** - Alerts for >20 SSH attempts  
- **Database Access Monitoring** - Suspicious database connection alerts
- **Web Application Attack Detection** - HTTP log analysis for attack patterns

#### Response Activities
1. **Monitor CloudWatch Dashboard** for real-time threat visualization
2. **Analyze VPC Flow Logs** for attack pattern identification
3. **Investigate Security Alerts** from SNS notifications
4. **Practice Incident Response** procedures

## 📊 Monitoring and Alerting

### Security Dashboard
Access your CloudWatch security dashboard:
```bash
terraform output security_monitoring | jq -r '.security_dashboard_url'
```

### Log Analysis Locations
- **VPC Flow Logs**: `/aws/vpc/flowlogs/[project-name]`
- **Application Logs**: Via Session Manager to app server → `/var/log/httpd/access_log`
- **Attack Monitoring**: Via Session Manager to app server → `/var/log/red_team_activity.log`

### Alert Notifications
- Email alerts sent to configured email address
- Real-time notifications for security events
- Threshold-based alerting for anomalous behavior

## 💰 Cost Management

### Free Tier Optimized
- **Instance Types**: t3.micro (free tier eligible)
- **Storage**: Minimal EBS volumes  
- **Monitoring**: 7-day log retention
- **Estimated Cost**: $0-5/month within free tier limits

### Cleanup Instructions
```bash
# Destroy all resources when done
terraform destroy

# Confirm destruction by typing 'yes' when prompted
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Terraform Profile Issues
```bash
# Verify AWS profile
aws sts get-caller-identity --profile terraform

# If profile doesn't exist, reconfigure
aws configure --profile terraform
```

#### 2. SSH Key Problems
```bash
# Check if key exists
ls -la ~/.ssh/red_blue_lab_key*

# Create new key if needed
ssh-keygen -t rsa -b 4096 -f ~/.ssh/red_blue_lab_key
```

#### 3. IP Access Issues
```bash
# Update your current IP
curl ifconfig.me
# Update terraform.tfvars with new IP/32
terraform apply
```

#### 4. Session Manager Connection Issues
```bash
# Install/update Session Manager plugin
# macOS
brew install --cask session-manager-plugin

# Windows - Download from AWS documentation
# Linux
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm" -o "session-manager-plugin.rpm"
sudo yum install -y session-manager-plugin.rpm
```

## 📚 Learning Outcomes

### Red Team Skills Development
- **Network Reconnaissance**: Discovery and enumeration techniques
- **Web Application Security**: OWASP Top 10 vulnerability exploitation
- **Network Penetration**: Lateral movement and privilege escalation
- **Tool Proficiency**: nmap, hydra, sqlmap, nikto, metasploit

### Blue Team Skills Development  
- **Security Monitoring**: Log analysis and pattern recognition
- **Incident Detection**: Alert triage and investigation
- **Threat Hunting**: Proactive security analysis
- **Response Procedures**: Containment and remediation strategies

## 🛡️ Security Best Practices

### Network Security
- **Segmented Architecture**: Three-tier network design
- **Least Privilege**: Role-based access controls
- **Monitoring**: Comprehensive logging and alerting
- **Secure Access**: Session Manager instead of SSH

### Operational Security
- **Credential Management**: Randomly generated passwords
- **Access Logging**: All activities tracked in CloudTrail  
- **Resource Tagging**: Organized resource management
- **Cost Controls**: Free tier optimization

## 📞 Support and Documentation

### Quick Reference Commands
```bash
# View all outputs
terraform output

# Get connection info
terraform output connection_info

# Access specific instance
aws ssm start-session --target $(terraform output -raw connection_info | jq -r '.kali_id') --profile terraform

# View team credentials
terraform output team_credentials

# Clean up everything
terraform destroy
```

### File Locations After Deployment
- **Team Credentials**: `team_credentials.json` (after running terraform output)
- **Lab Outputs**: `lab_outputs.json` (after running terraform output)  
- **Terraform State**: `terraform.tfstate` (managed by Terraform)

---

**⚠️ Security Notice**: This lab contains intentionally vulnerable applications. Use only in isolated environments and never expose to production networks.

**🎯 Educational Purpose**: Designed for cybersecurity training, incident response practice, and security tool evaluation in a controlled environment.
