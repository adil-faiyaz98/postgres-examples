provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "postgres" {
  identifier            = "postgres-examples"
  allocated_storage     = 20
  engine               = "postgres"
  engine_version       = "15"
  instance_class       = "db.t3.medium"
  username            = var.db_user
  password            = var.db_password
  publicly_accessible  = false
  skip_final_snapshot  = true
  parameter_group_name = aws_db_parameter_group.postgres_params.name

  vpc_security_group_ids = [aws_security_group.db_sg.id]
}

resource "aws_db_parameter_group" "postgres_params" {
  name   = "postgres-examples-params"
  family = "postgres15"

  parameter {
    name  = "max_connections"
    value = "200"
  }

  parameter {
    name  = "shared_buffers"
    value = "4GB"
  }
}

resource "aws_security_group" "db_sg" {
  name        = "postgres-examples-sg"
  description = "Allow PostgreSQL access"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_user" {
  default = "app_user"
}

variable "db_password" {
  default = "securepassword"
}

resource "aws_s3_bucket" "pg_encrypted_backups" {
  bucket = "your-encrypted-backups-bucket"
  acl    = "private"

  lifecycle_rule {
    id      = "retain-90-days"
    enabled = true
    expiration {
      days = 90
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

output "s3_encrypted_backup_bucket" {
  value = aws_s3_bucket.pg_encrypted_backups.bucket
}
