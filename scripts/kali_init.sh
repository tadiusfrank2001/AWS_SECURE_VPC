#!/bin/bash

# Minimal Red Team Tools Installation for Amazon Linux 2
# Only installs tools needed for your specific testing scenarios

echo "Installing minimal red team tools..."

# Update system and install dependencies
sudo yum update -y
sudo yum groupinstall -y "Development Tools"
sudo yum install -y git gcc make pcre-devel openssl-devel zlib-devel perl mysql

# Install nmap (available in AL2 repos)
sudo yum install -y nmap

# Install hydra from source
echo "Installing hydra..."
cd /tmp
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra
./configure
make
sudo make install
cd ~

# Install nikto from GitHub
echo "Installing nikto..."
sudo git clone https://github.com/sullo/nikto.git /opt/nikto
sudo chmod +x /opt/nikto/program/nikto.pl
sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Download rockyou.txt wordlist (needed for hydra)
echo "Downloading rockyou.txt wordlist..."
sudo mkdir -p /usr/share/wordlists
cd /usr/share/wordlists
sudo wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
sudo chmod 644 rockyou.txt

# Verify installations
echo "Verifying tool installations..."
echo "nmap: $(which nmap)"
echo "hydra: $(which hydra)"
echo "nikto: $(which nikto)"
echo "mysql: $(which mysql)"
echo "rockyou.txt: $(ls -la /usr/share/wordlists/rockyou.txt)"

# Create quick test aliases
cat >> ~/.bashrc << 'EOF'

# Red Team Testing Aliases
alias db-test='mysql -h 10.237.3.130 -u root -p'
alias port-scan='nmap -sS 10.237.2.189 10.237.3.130'
alias ssh-brute='hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.237.2.189'
alias vuln-scan='nikto -h http://10.237.2.189'
EOF

echo "Installation complete!"
echo "Available commands:"
echo "- nmap -sS 10.237.2.189 10.237.3.130"
echo "- hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.237.2.189"
echo "- nikto -h http://10.237.2.189"
echo "- mysql -h 10.237.3.130 -u root -p"
echo ""
echo "Or use aliases: port-scan, ssh-brute, vuln-scan, db-test"
echo "Restart your shell or run 'source ~/.bashrc' to use aliases"