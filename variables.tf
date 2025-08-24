variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "key_pair_name" {
  description = "EC2 Key Pair name"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR blocks allowed to SSH to bastion"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Change this to your IP range for better security
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_app_subnet_cidr" {
  description = "CIDR block for private app subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_db_subnet_cidr" {
  description = "CIDR block for private DB subnet"
  type        = string
  default     = "10.0.3.0/24"
}

variable "bastion_instance_type" {
  description = "Instance type for bastion host"
  type        = string
  default     = "t3.micro"
}

variable "kali_instance_type" {
  description = "Instance type for Kali Linux"
  type        = string
  default     = "t3.micro"
}

variable "app_instance_type" {
  description = "Instance type for app server"
  type        = string
  default     = "t3.micro"
}

variable "db_instance_type" {
  description = "Instance type for database server"
  type        = string
  default     = "t3.micro"
}

variable "project_name" {
  description = "Name of the project for resource tagging"
  type        = string
  default     = "red-blue-team-lab"
}

