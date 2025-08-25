
#!/bin/bash

# Kali Linux Red Team Instance Initialization Script
# Lightweight setup for VPC Flow Log testing

# Update system packages
apt update -y
apt upgrade -y

# Install only essential penetration testing tools
apt install -y nmap hydra sqlmap nikto metasploit-framework

# Install network scanning tools
apt install -y masscan zmap

# Install Python and pip for custom scripts
apt install -y python3 python3-pip

# Install Python libraries for network operations
pip3 install paramiko requests scapy

# Enable SSH logging for blue team analysis
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
systemctl restart ssh

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

# Install Session Manager plugin
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
dpkg -i session-manager-plugin.deb
rm session-manager-plugin.deb

# Create red team user directories
mkdir -p /home/kali/targets
mkdir -p /home/kali/results
mkdir -p /home/kali/scripts

# Create target information file with network details
cat > /home/kali/targets/network_info.txt << 'EOF'
=== RED TEAM TARGET NETWORK ===
VPC CIDR: 10.0.0.0/16
Public Subnet: 10.0.1.0/24
App Subnet: 10.0.2.0/24  
DB Subnet: 10.0.3.0/24

Expected Targets:
- App Server: 10.0.2.0/24 range
- DB Server: 10.0.3.0/24 range

Attack Objective:
Generate VPC Flow Log alerts by attempting SSH connections
to trigger blue team detection and response.
EOF

# Create useful red team aliases
cat >> /home/kali/.bashrc << 'EOF'

# Red Team Aliases
alias ll='ls -alF'
alias la='ls -A'
alias targets='cd /home/kali/targets'
alias results='cd /home/kali/results'
alias scripts='cd /home/kali/scripts'

# Quick reconnaissance commands
alias quick-scan='nmap -sS'
alias port-scan='nmap -sS -sV'
alias network-sweep='nmap -sP'
alias host-discovery='nmap -sn'
EOF

# Create network reconnaissance script
cat > /home/kali/scripts/network_recon.sh << 'EOF'
#!/bin/bash
echo "=== RED TEAM NETWORK RECONNAISSANCE ==="
echo "Starting network discovery..."

# Discover live hosts in target subnets
echo "Discovering hosts in 10.0.2.0/24 (App Subnet):"
nmap -sn 10.0.2.0/24

echo "Discovering hosts in 10.0.3.0/24 (DB Subnet):"
nmap -sn 10.0.3.0/24

echo "Quick port scan of discovered hosts:"
nmap -sS -F 10.0.2.0/24 10.0.3.0/24

echo "Results saved to /home/kali/results/recon_$(date +%Y%m%d_%H%M).txt"
nmap -sS -F 10.0.2.0/24 10.0.3.0/24 > /home/kali/results/recon_$(date +%Y%m%d_%H%M).txt
EOF




# Make scripts executable
chmod +x /home/kali/scripts/*.sh


# Set proper ownership for Kali user
chown -R kali:kali /home/kali/

# Create red team MOTD
cat > /etc/motd << 'EOF'
*************************************************
*          RED TEAM ATTACK MACHINE              *
*                                               *
*  Lightweight Kali instance for VPC Flow Log  *
*  testing and blue team detection exercises.   *
*                                               *
*  Quick Start:                                 *
*  - targets     : Go to targets directory      *
*  - scripts     : Access red team scripts      *
*  - quick-scan  : Fast network scan            *
*                                               *
*  Key Scripts:                                 *
*  - network_recon.sh : Discover target hosts   *
*                                               *
*************************************************
EOF

# Create a simple status check
cat > /home/kali/status_check.sh << 'EOF'
#!/bin/bash
echo "=== RED TEAM SYSTEM STATUS ==="
echo "IP Configuration:"
ip addr show eth0 | grep inet
echo ""
echo "Network Connectivity:"
ping -c 2 8.8.8.8
echo ""
echo "Target Reachability:"
ping -c 1 10.0.2.1 2>/dev/null && echo "App subnet gateway reachable" || echo "App subnet gateway not reachable"
ping -c 1 10.0.3.1 2>/dev/null && echo "DB subnet gateway reachable" || echo "DB subnet gateway not reachable"
echo ""
echo "Installed Tools:"
which nmap masscan zmap hydra python3
EOF

chmod +x /home/kali/status_check.sh
chown kali:kali /home/kali/status_check.sh

# Log the completion of initialization
echo "$(date): Kali Linux red team initialization completed" >> /var/log/init.log