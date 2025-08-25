# ==== AWS REGION ====
variable "region" {
  description = "AWS region to deploy all resources"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.region))
    error_message = "Region must be a valid AWS region format (e.g., us-east-1)."
  }
}



# ==== PUBLIC KEY PATH ====
variable "public_key_path" {
  description = "Path to your SSH public key file (e.g., ~/.ssh/id_rsa.pub)"
  type        = string
  default     = "~/.ssh/id_rsa.pub"

  validation {
    condition     = can(file(var.public_key_path))
    error_message = "The public key file must exist at the specified path."
  }
}

# ===== LOCAL MACHINE IP =====
variable "my_ip" {
  description = "Your public IP address in CIDR format (e.g., 203.0.113.45/32). Use 'curl ifconfig.me' to find your IP."
  type        = string

  validation {
    condition     = can(cidrhost(var.my_ip, 0))
    error_message = "The my_ip value must be a valid CIDR block (e.g., 203.0.113.45/32)."
  }
}

# ===== ALERT EMAIL =====
variable "alert_email" {
  description = "Email address to receive GuardDuty security alerts"
  type        = string

  validation {
    condition     = can(regex("^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,}$", var.alert_email))
    error_message = "The alert_email must be a valid email address format."
  }
}

# ==== NETWORK CONFIGURATION ====
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block (e.g., 10.0.0.0/16)."
  }
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"

  validation {
    condition     = can(cidrhost(var.public_subnet_cidr, 0))
    error_message = "Public subnet CIDR must be a valid CIDR block (e.g., 10.0.1.0/24)."
  }
}

variable "private_app_subnet_cidr" {
  description = "CIDR block for private app subnet"
  type        = string
  default     = "10.0.2.0/24"

  validation {
    condition     = can(cidrhost(var.private_app_subnet_cidr, 0))
    error_message = "Private app subnet CIDR must be a valid CIDR block (e.g., 10.0.2.0/24)."
  }
}

variable "private_db_subnet_cidr" {
  description = "CIDR block for private DB subnet"
  type        = string
  default     = "10.0.3.0/24"

  validation {
    condition     = can(cidrhost(var.private_db_subnet_cidr, 0))
    error_message = "Private DB subnet CIDR must be a valid CIDR block (e.g., 10.0.3.0/24)."
  }
}

# ==== INSTANCE CONFIGURATION ====
variable "bastion_instance_type" {
  description = "Instance type for bastion host (must be free tier eligible)"
  type        = string
  default     = "t3.micro"

  validation {
    condition = contains([
      "t2.micro", "t3.micro", "t3.nano", "t4g.micro", "t4g.nano"
    ], var.bastion_instance_type)
    error_message = "Instance type must be free tier eligible: t2.micro, t3.micro, t3.nano, t4g.micro, or t4g.nano."
  }
}

variable "kali_instance_type" {
  description = "Instance type for Kali Linux (must be free tier eligible)"
  type        = string
  default     = "t3.micro"

  validation {
    condition = contains([
      "t2.micro", "t3.micro", "t3.nano", "t4g.micro", "t4g.nano"
    ], var.kali_instance_type)
    error_message = "Instance type must be free tier eligible: t2.micro, t3.micro, t3.nano, t4g.micro, or t4g.nano."
  }
}

variable "app_instance_type" {
  description = "Instance type for app server (must be free tier eligible)"
  type        = string
  default     = "t3.micro"

  validation {
    condition = contains([
      "t2.micro", "t3.micro", "t3.nano", "t4g.micro", "t4g.nano"
    ], var.app_instance_type)
    error_message = "Instance type must be free tier eligible: t2.micro, t3.micro, t3.nano, t4g.micro, or t4g.nano."
  }
}

variable "db_instance_type" {
  description = "Instance type for database server (must be free tier eligible)"
  type        = string
  default     = "t3.micro"

  validation {
    condition = contains([
      "t2.micro", "t3.micro", "t3.nano", "t4g.micro", "t4g.nano"
    ], var.db_instance_type)
    error_message = "Instance type must be free tier eligible: t2.micro, t3.micro, t3.nano, t4g.micro, or t4g.nano."
  }
}

# ==== PROJECT CONFIGURATION ====
variable "project_name" {
  description = "Name of the project for resource tagging (alphanumeric and hyphens only)"
  type        = string
  default     = "red-blue-team-lab"

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.project_name))
    error_message = "Project name must contain only alphanumeric characters and hyphens."
  }
}

variable "environment" {
  description = "Environment name for resource tagging"
  type        = string
  default     = "lab"

  validation {
    condition = contains([
      "dev", "test", "staging", "prod", "lab", "demo"
    ], var.environment)
    error_message = "Environment must be one of: dev, test, staging, prod, lab, demo."
  }
}

variable "enable_custom_threat_intel" {
  description = "Enable custom threat intelligence feeds"
  type        = bool
  default     = false
}