# =============================================================================
# OUTPUTS
# =============================================================================
output "connection_info" {
  description = "Connection information for Red/Blue teams"
  value = {
    # Network Information
    vpc_cidr                = local.vpc_cidr
    public_subnet_cidr      = local.public_subnet_cidr
    private_app_subnet_cidr = local.private_app_subnet_cidr
    private_db_subnet_cidr  = local.private_db_subnet_cidr
    
    # Instance Information
    kali_id           = aws_instance.kali.id
    kali_public_ip    = aws_instance.kali.public_ip
    kali_private_ip   = aws_instance.kali.private_ip
    app_server_id     = aws_instance.app_server.id
    app_server_ip     = aws_instance.app_server.private_ip
    db_server_id      = aws_instance.db_server.id
    db_server_ip      = aws_instance.db_server.private_ip
    
    # Session Manager Connections
    kali_ssm_command  = "aws ssm start-session --target ${aws_instance.kali.id}"
    app_ssm_command   = "aws ssm start-session --target ${aws_instance.app_server.id}"
    db_ssm_command    = "aws ssm start-session --target ${aws_instance.db_server.id}"
  }
}

output "security_monitoring" {
  description = "Security monitoring resources"
  value = {
    
    # CloudWatch Dashboard
    security_dashboard_url    = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${var.project_name}-security-dashboard"
    
    # VPC Flow Logs
    vpc_flow_logs_group      = aws_cloudwatch_log_group.vpc_flow_log.name
    flow_logs_console_url    = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#logsV2:log-groups/log-group/${replace(aws_cloudwatch_log_group.vpc_flow_log.name, "/", "$252F")}"
    
    # SNS Topic
    security_alerts_topic    = aws_sns_topic.security_alerts.arn
    
  }
}

output "team_credentials" {
  description = "Team member credentials (store securely)"
  sensitive   = true
  value = {
    red_team = {
      for i, member in local.red_team_members : member.username => {
        username = member.username
        password = member.password
      }
    }
    blue_team = {
      for i, member in local.blue_team_members : member.username => {
        username = member.username
        password = member.password
      }
    }
  }
}

output "testing_scenarios" {
  description = "Common testing scenarios that will trigger alerts"
  value = {
    nmap_port_scan = {
      description = "Port scan from Kali to app/db servers"
      command     = "nmap -sS ${aws_instance.app_server.private_ip} ${aws_instance.db_server.private_ip}"
      triggers    = ["GuardDuty Recon findings", "CloudWatch port scan alarms"]
    }
    
    ssh_brute_force = {
      description = "SSH brute force attempt"
      command     = "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://${aws_instance.app_server.private_ip}"
      triggers    = ["GuardDuty SSH brute force findings", "CloudWatch SSH brute force alarms"]
    }
    
    database_connection = {
      description = "Direct database connection attempt"
      command     = "mysql -h ${aws_instance.db_server.private_ip} -u root -p"
      triggers    = ["CloudWatch suspicious DB access alarms", "VPC Flow Log entries"]
    }
    
    vulnerability_scan = {
      description = "Vulnerability scanning with tools like Nikto"
      command     = "nikto -h http://${aws_instance.app_server.private_ip}"
      triggers    = ["GuardDuty reconnaissance findings", "Unusual network behavior"]
    }
  }
}