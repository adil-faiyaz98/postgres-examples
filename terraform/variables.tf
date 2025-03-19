variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, production)"
  type        = string
}

variable "allocated_storage" {
  description = "The allocated storage in gibibytes"
  type        = number
  default     = 20
}

variable "max_allocated_storage" {
  description = "The upper limit to which Amazon RDS can automatically scale the storage"
  type        = number
  default     = 100
}

variable "postgres_version" {
  description = "Version of PostgreSQL to use"
  type        = string
  default     = "15"
}

variable "instance_class" {
  description = "The instance type of the RDS instance"
  type        = string
  default     = "db.t3.medium"
}

variable "db_username" {
  description = "Username for the master DB user"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Password for the master DB user"
  type        = string
  sensitive   = true
}

variable "allowed_security_groups" {
  description = "List of security group IDs allowed to connect to the database"
  type        = list(string)
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic for CloudWatch alarms"
  type        = string
}

# Database Parameters
variable "max_connections" {
  description = "Maximum number of database connections"
  type        = string
  default     = "200"
}

variable "shared_buffers" {
  description = "Amount of memory dedicated to shared buffers"
  type        = string
  default     = "4GB"
}

variable "work_mem" {
  description = "Amount of memory for internal sort operations and hash tables"
  type        = string
  default     = "64MB"
}

variable "maintenance_work_mem" {
  description = "Maximum amount of memory for maintenance operations"
  type        = string
  default     = "256MB"
}

variable "effective_cache_size" {
  description = "How much memory is available for disk caching"
  type        = string
  default     = "12GB"
} 