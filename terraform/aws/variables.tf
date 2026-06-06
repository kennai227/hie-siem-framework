variable "aws_region" {
  description = "AWS region — must be Canadian for PIPEDA/PHIPA data residency"
  type        = string
  default     = "ca-central-1"
  validation {
    condition     = contains(["ca-central-1", "ca-west-1"], var.aws_region)
    error_message = "Region must be a Canadian AWS region for PHI data residency compliance."
  }
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for HIE SIEM VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDRs (one per AZ)"
  type        = list(string)
  default     = ["10.10.1.0/24", "10.10.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDRs — NAT/VPN only, no workloads"
  type        = list(string)
  default     = ["10.10.10.0/24", "10.10.11.0/24"]
}

variable "wazuh_manager_instance_type" {
  description = "EC2 instance type for Wazuh manager node"
  type        = string
  default     = "m6i.xlarge"
}

variable "opensearch_instance_type" {
  description = "OpenSearch data node instance type"
  type        = string
  default     = "r6g.large.search"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days (min 365 for HIPAA)"
  type        = number
  default     = 365
  validation {
    condition     = var.log_retention_days >= 365
    error_message = "HIPAA requires minimum 1 year log retention."
  }
}
