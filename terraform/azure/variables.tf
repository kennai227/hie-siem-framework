variable "azure_region" {
  description = "Azure region — must be Canadian for PHIPA/PIPEDA data residency"
  type        = string
  default     = "canadacentral"
  validation {
    condition     = contains(["canadacentral", "canadaeast"], var.azure_region)
    error_message = "Region must be a Canadian Azure region for PHI data residency compliance."
  }
}

variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Must be dev, staging, or prod."
  }
}

variable "vnet_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "private_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}

variable "log_daily_quota_gb" {
  description = "Log Analytics daily ingestion cap (cost guard)"
  type        = number
  default     = 50
}
