#!/bin/bash
# =============================================================================
# APPLICATION SERVER INITIALIZATION SCRIPT
# Target infrastructure with intentional vulnerabilities for Red Team
# =============================================================================

# Update system packages
yum update -y

# Install web server and dependencies
yum install -y httpd php php-mysql mysql wget unzip curl vim

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

# Install SSM Agent on Ubuntu/Kali
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Start and enable Apache
systemctl start httpd
systemctl enable httpd

# Create main application page
cat > /var/www/html/index.php << 'EOF'
<?php
echo "<h1>Corporate Web Application</h1>";
echo "<p>Welcome to SecureCorp's internal web application.</p>";
echo "<ul>";
echo "<li><a href='login.php'>Employee Login</a></li>";
echo "<li><a href='admin.php'>Admin Panel</a></li>";
echo "<li><a href='files.php'>File Manager</a></li>";
echo "</ul>";
echo "<hr>";
echo "<h3>Server Information</h3>";
echo "<p>Server: " . $_SERVER['SERVER_SOFTWARE'] . "</p>";
echo "<p>PHP Version: " . phpversion() . "</p>";
echo "<p>Database Server: ${db_server_ip}</p>";
?>
EOF

# =============================================================================
# VULNERABILITY 1: SQL INJECTION
# =============================================================================
# Create vulnerable login page
cat > /var/www/html/login.php << 'EOF'
<?php
$error = "";

if ($_POST['username'] && $_POST['password']) {
    $username = $_POST['username'];  // No sanitization
    $password = $_POST['password'];  // No sanitization
    
    // Vulnerable SQL query - SQL injection vulnerability
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    // Simulate authentication (always fails for demo, but shows query)
    if ($username == "admin" && $password == "admin123") {
        echo "<h2>Login Successful!</h2>";
        echo "<p>Welcome, admin!</p>";
        echo "<p><b>FLAG{SQL_INJECTION_SUCCESS}</b></p>";
        echo "<p><a href='admin.php'>Access Admin Panel</a></p>";
    } else {
        $error = "Invalid credentials. Query executed: " . $query;
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Employee Login</title></head>
<body>
    <h2>Employee Login Portal</h2>
    <form method="post">
        <p>Username: <input type="text" name="username" required></p>
        <p>Password: <input type="password" name="password" required></p>
        <p><input type="submit" value="Login"></p>
    </form>
    <?php if ($error) echo "<p style='color:red'>Error: $error</p>"; ?>
    <p><small>Hint: Try SQL injection techniques like ' OR '1'='1' --</small></p>
    <!-- Developer note: Default credentials admin/admin123 -->
    <p><a href="index.php">Back to Home</a></p>
</body>
</html>
EOF

# =============================================================================
# VULNERABILITY 2: COMMAND INJECTION
# =============================================================================
# Create admin panel with command injection
cat > /var/www/html/admin.php << 'EOF'
<?php
// Simple authentication check
if (!isset($_GET['auth']) || $_GET['auth'] != 'admin123') {
    die("<h2>Access Denied</h2><p>Admin authentication required.</p><p><a href='login.php'>Login First</a></p>");
}

echo "<h2>Administrative Panel</h2>";

// Command injection vulnerability
if (isset($_POST['ping_host'])) {
    $host = $_POST['ping_host'];  // No sanitization
    echo "<h3>Ping Results:</h3>";
    echo "<pre>";
    // Vulnerable command execution
    system("ping -c 3 " . $host);  // Command injection vulnerability
    echo "</pre>";
}
?>

<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
    <h3>Network Diagnostics</h3>
    <form method="post">
        <p>Ping Host: <input type="text" name="ping_host" placeholder="8.8.8.8" value="127.0.0.1"></p>
        <p><input type="submit" value="Ping"></p>
    </form>
    
    <p><small>Hint: Try command injection like: 127.0.0.1; whoami</small></p>
    <p><small>Or try: 127.0.0.1 && cat /etc/passwd</small></p>
    
    <h3>Quick Links</h3>
    <ul>
        <li><a href="files.php">File Manager</a></li>
        <li><a href="index.php">Home</a></li>
    </ul>
    
    <p><b>FLAG{COMMAND_INJECTION_ACCESS}</b></p>
</body>
</html>
EOF

# =============================================================================
# VULNERABILITY 3: DIRECTORY TRAVERSAL
# =============================================================================
# Create file manager with directory traversal
cat > /var/www/html/files.php << 'EOF'
<?php
// File download with directory traversal vulnerability
if (isset($_GET['file'])) {
    $file = $_GET['file'];  // No sanitization
    
    // Attempt to read any file - directory traversal vulnerability
    echo "<h3>File Contents:</h3>";
    echo "<pre>";
    
    if (file_exists($file)) {
        echo htmlspecialchars(file_get_contents($file));
    } else {
        echo "File not found or access denied: " . $file;
    }
    
    echo "</pre>";
    echo "<p><a href='files.php'>Back to File Manager</a></p>";
    exit;
}

echo "<h2>File Manager</h2>";
echo "<p>Select a file to view:</p>";
echo "<ul>";
echo "<li><a href='?file=document1.txt'>Document 1</a></li>";
echo "<li><a href='?file=document2.txt'>Document 2</a></li>";
echo "<li><a href='?file=config.php'>Configuration File</a></li>";
echo "</ul>";

echo "<h3>Manual File Access</h3>";
echo "<form method='get'>";
echo "<p>File path: <input type='text' name='file' placeholder='document1.txt'></p>";
echo "<p><input type='submit' value='View File'></p>";
echo "</form>";

echo "<p><small>Hint: Try directory traversal like: ../../../etc/passwd</small></p>";
echo "<p><small>Or try: /var/log/httpd/access_log</small></p>";
echo "<p><b>FLAG{DIRECTORY_TRAVERSAL_READY}</b></p>";
echo "<p><a href='index.php'>Back to Home</a></p>";
?>
EOF

# Create sample files for testing
mkdir -p /var/www/html/
echo "This is a sample corporate document." > /var/www/html/document1.txt
echo "Employee database backup - CONFIDENTIAL DATA" > /var/www/html/document2.txt

# Create configuration file with sensitive data
cat > /var/www/html/config.php << 'EOF'
<?php
// Database configuration
$db_host = "${db_server_ip}";
$db_user = "webapp";
$db_pass = "SecretPassword123!";
$db_name = "corporate_db";

// API keys
$api_key = "sk-1234567890abcdef";
$secret_key = "AdminSecretKey2023!";

echo "<h3>Configuration Loaded</h3>";
echo "<p>Database Host: " . $db_host . "</p>";
echo "<p>FLAG{CONFIG_FILE_ACCESS}</p>";
?>
EOF

# Set appropriate permissions
chmod 644 /var/www/html/*.php
chmod 644 /var/www/html/*.txt

# Create monitoring script for Blue Team
cat > /root/monitor_attacks.sh << 'EOF'
#!/bin/bash
echo "=== Red Team Activity Monitor ==="
echo "Timestamp: $(date)"
echo ""

echo "=== SQL Injection Attempts ==="
grep -i "union\|select\|drop\|insert\|delete\|'\|--" /var/log/httpd/access_log 2>/dev/null | tail -5

echo ""
echo "=== Command Injection Attempts ==="
grep -i "ping.*;" /var/log/httpd/access_log 2>/dev/null | tail -5

echo ""
echo "=== Directory Traversal Attempts ==="
grep -i "\.\./\|\.\.\\\|etc/passwd\|etc/shadow" /var/log/httpd/access_log 2>/dev/null | tail -5

echo ""
echo "=== Recent Web Access ==="
tail -10 /var/log/httpd/access_log 2>/dev/null

echo ""
echo "=== Active Connections ==="
netstat -tulpn | grep -E ":80|:443"

EOF

chmod +x /root/monitor_attacks.sh

# Set up monitoring cron job
echo "*/5 * * * * root /root/monitor_attacks.sh >> /var/log/red_team_activity.log 2>&1" >> /etc/crontab

# Configure Apache logging
cat >> /etc/httpd/conf/httpd.conf << 'EOF'

# Enhanced logging for security monitoring
CustomLog /var/log/httpd/access_log combined
ErrorLog /var/log/httpd/error_log
LogLevel info
EOF

# Enable and start services
systemctl enable httpd
systemctl restart httpd

# Create vulnerability summary
cat > /root/vulnerability_summary.txt << 'EOF'
VULNERABILITY SUMMARY - APPLICATION SERVER
==========================================

INTENTIONAL VULNERABILITIES FOR RED TEAM:

1. SQL INJECTION
   Location: /login.php
   Test: Username: admin' OR '1'='1' --  Password: anything
   Impact: Authentication bypass

2. COMMAND INJECTION  
   Location: /admin.php?auth=admin123
   Test: 127.0.0.1; whoami
   Test: 127.0.0.1 && cat /etc/passwd
   Impact: Remote command execution

3. DIRECTORY TRAVERSAL
   Location: /files.php?file=
   Test: ../../../etc/passwd
   Test: /var/log/httpd/access_log
   Impact: Arbitrary file read

FLAGS TO CAPTURE:
- FLAG{SQL_INJECTION_SUCCESS}
- FLAG{COMMAND_INJECTION_ACCESS}  
- FLAG{DIRECTORY_TRAVERSAL_READY}
- FLAG{CONFIG_FILE_ACCESS}

MONITORING:
- Attack activity logged to /var/log/red_team_activity.log
- Monitor script: /root/monitor_attacks.sh
EOF

# Set up firewall
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload

# Create welcome message
cat > /etc/motd << 'EOF'
=====================================
    APPLICATION SERVER - TARGET
=====================================
Vulnerable web application for Red Team testing

Access: http://[private-ip]/
- SQL Injection: /login.php
- Command Injection: /admin.php?auth=admin123  
- Directory Traversal: /files.php

Monitor attacks: /root/monitor_attacks.sh
Summary: /root/vulnerability_summary.txt
=====================================
EOF

echo "Application server setup completed with intentional vulnerabilities"
echo "Web application available at http://[instance-ip]/"
echo "Three main vulnerabilities configured for Red Team testing"
