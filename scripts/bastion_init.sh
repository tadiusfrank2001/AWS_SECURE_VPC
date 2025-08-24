
#!/bin/bash

# Bastion Host Initialization Script
# Blue Team Jump Box Configuration

# Update system
yum update -y

# Install essential monitoring and debugging tools
yum install -y htop net-tools tcpdump nmap-ncat wget curl

# Install additional security tools for blue team
yum install -y bind-utils traceroute iftop iotop

# Configure detailed SSH logging for monitoring
echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
echo "MaxAuthTries 6" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config

# Restart SSH service to apply changes
systemctl restart sshd

# Install CloudWatch agent for log monitoring
cd /tmp
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Configure log rotation for auth logs
cat > /etc/logrotate.d/auth-logs << 'EOF'
/var/log/auth.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF

# Create useful aliases for blue team operations
cat >> /home/ec2-user/.bashrc << 'EOF'

# Blue Team Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias auth-log='sudo tail -f /var/log/auth.log'
alias secure-log='sudo tail -f /var/log/secure'
alias failed-ssh='sudo grep "Failed password" /var/log/secure | tail -20'
alias ssh-attempts='sudo grep "authentication failure" /var/log/secure | tail -20'
alias watch-connections='sudo netstat -tuln'
alias active-connections='sudo ss -tuln'

# Network monitoring shortcuts
alias network-scan='nmap -sP'
alias port-scan='nmap -sS'
EOF

# Set proper ownership
chown ec2-user:ec2-user /home/ec2-user/.bashrc

# Create a welcome message for blue team
cat > /etc/motd << 'EOF'
*************************************************
*        BLUE TEAM BASTION HOST                 *
*                                               *
*  This is your secure jump box for accessing  *
*  private network resources and monitoring     *
*  for red team activities.                     *
*                                               *
*  Useful commands:                             *
*  - auth-log      : Monitor SSH attempts       *
*  - failed-ssh    : Show recent failed logins  *
*  - network-scan  : Scan network ranges        *
*                                               *
*************************************************
EOF

# Enable and configure auditd for additional logging
yum install -y audit
systemctl enable auditd
systemctl start auditd

# Add audit rules for monitoring
cat >> /etc/audit/rules.d/audit.rules << 'EOF'
# Monitor SSH key files
-w /home/ec2-user/.ssh/ -p wa -k ssh_keys
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Monitor network configuration changes
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config
EOF

# Restart auditd
service auditd restart

# Create directory for blue team scripts and tools
mkdir -p /opt/blueteam-tools
chown ec2-user:ec2-user /opt/blueteam-tools

# Create a simple network monitoring script
cat > /opt/blueteam-tools/monitor_network.sh << 'EOF'
#!/bin/bash
echo "=== Network Monitoring Script ==="
echo "Current connections:"
sudo netstat -tuln | grep :22
echo ""
echo "Recent SSH failures:"
sudo grep "Failed password" /var/log/secure | tail -10
echo ""
echo "Active SSH sessions:"
who
EOF

chmod +x /opt/blueteam-tools/monitor_network.sh
chown ec2-user:ec2-user /opt/blueteam-tools/monitor_network.sh

# Log the completion of initialization
echo "$(date): Bastion host initialization completed" >> /var/log/init.log

# Signal that the instance is ready
/opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource bastionHost --region ${AWS::Region} || true

