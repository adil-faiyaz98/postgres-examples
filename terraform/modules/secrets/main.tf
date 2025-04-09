provider "aws" {
  region = var.region
}

resource "aws_secretsmanager_secret" "postgres_credentials" {
  name                    = "${var.environment}-postgres-credentials"
  description             = "PostgreSQL credentials for ${var.environment} environment"
  recovery_window_in_days = 7
  
  tags = {
    Environment = var.environment
    Project     = "postgres-security"
    ManagedBy   = "terraform"
  }
}

resource "aws_secretsmanager_secret_version" "postgres_credentials" {
  secret_id     = aws_secretsmanager_secret.postgres_credentials.id
  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    database = var.db_name
    host     = var.db_host
    port     = var.db_port
  })
}

# IAM Role for EKS to access Secrets Manager
resource "aws_iam_role" "postgres_secrets_role" {
  name = "${var.environment}-postgres-secrets-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${var.oidc_provider}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${var.oidc_provider}:sub": "system:serviceaccount:postgres-security:postgres-sa"
          }
        }
      }
    ]
  })
  
  tags = {
    Environment = var.environment
    Project     = "postgres-security"
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_policy" "postgres_secrets_policy" {
  name        = "${var.environment}-postgres-secrets-policy"
  description = "Policy to allow access to PostgreSQL secrets"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.postgres_credentials.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "postgres_secrets_attachment" {
  role       = aws_iam_role.postgres_secrets_role.name
  policy_arn = aws_iam_policy.postgres_secrets_policy.arn
}

data "aws_caller_identity" "current" {}

output "secret_arn" {
  value = aws_secretsmanager_secret.postgres_credentials.arn
}

output "role_arn" {
  value = aws_iam_role.postgres_secrets_role.arn
}
