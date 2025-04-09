terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.94"
    }
  }

  backend "s3" {
    bucket         = "terraform-state-postgres"
    key            = "postgres/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "postgres-security"
      ManagedBy   = "terraform"
    }
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "postgres" {
  description             = "KMS key for PostgreSQL encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_db_subnet_group" "postgres" {
  name       = "postgres-subnet-group"
  subnet_ids = data.aws_subnets.private.ids
}

# Use the secrets module to manage database credentials
module "secrets" {
  source = "./modules/secrets"

  region      = var.aws_region
  environment = var.environment
  db_username = var.db_username
  db_password = var.db_password
  db_name     = var.db_name
  db_host     = "postgres-${var.environment}.${data.aws_region.current.name}.rds.amazonaws.com"
  oidc_provider = var.oidc_provider
}

resource "aws_db_instance" "postgres" {
  identifier            = "postgres-${var.environment}"
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  engine               = "postgres"
  engine_version       = var.postgres_version
  instance_class       = var.instance_class
  username             = var.db_username
  password             = var.db_password
  db_subnet_group_name = aws_db_subnet_group.postgres.name

  multi_az               = var.environment == "production"
  publicly_accessible    = false
  skip_final_snapshot    = false
  deletion_protection    = true
  storage_encrypted      = true
  kms_key_id            = aws_kms_key.postgres.arn
  parameter_group_name   = aws_db_parameter_group.postgres_params.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_db_parameter_group" "postgres_params" {
  name   = "postgres-params-${var.environment}"
  family = "postgres15"

  parameter {
    name  = "max_connections"
    value = var.max_connections
  }

  parameter {
    name  = "shared_buffers"
    value = var.shared_buffers
  }

  parameter {
    name  = "work_mem"
    value = var.work_mem
  }

  parameter {
    name  = "maintenance_work_mem"
    value = var.maintenance_work_mem
  }

  parameter {
    name  = "effective_cache_size"
    value = var.effective_cache_size
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_lock_waits"
    value = "1"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  parameter {
    name  = "ssl"
    value = "1"
  }
}

resource "aws_security_group" "db_sg" {
  name        = "postgres-sg-${var.environment}"
  description = "Security group for PostgreSQL"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    description     = "PostgreSQL access from allowed security groups"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_s3_bucket" "pg_backups" {
  bucket = "postgres-backups-${var.environment}-${data.aws_caller_identity.current.account_id}"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.postgres.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    id      = "backup-retention"
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pg_backups" {
  bucket = aws_s3_bucket.pg_backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "postgres-high-cpu-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic          = "Average"
  threshold          = "80"
  alarm_description  = "This metric monitors RDS CPU utilization"
  alarm_actions      = [var.sns_topic_arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.postgres.id
  }
}

data "aws_caller_identity" "current" {}

output "db_endpoint" {
  value = aws_db_instance.postgres.endpoint
}

output "backup_bucket" {
  value = aws_s3_bucket.pg_backups.bucket
}

output "kms_key_arn" {
  value = aws_kms_key.postgres.arn
}
