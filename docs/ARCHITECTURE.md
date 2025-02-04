

## Overview
This repository is built using PostgreSQL 15 and contains examples related to DevOps tools, including Ansible, Terraform, Docker, Prometheus, and Grafana.

## Architecture Components

### Database Layer
- PostgreSQL 15 with optimized configurations
- Partitioned tables for scalability
- PostgreSQL extensions (`pgcrypto`, `pg_trgm`, `pgtap`)

### Security & Access Control
- Role-Based Access Control (RBAC)
- Row-Level Security (RLS)
- Audit Logging

### Backup & Disaster Recovery
- `pgBackRest` for incremental backups
- `Barman` for point-in-time recovery (PITR)
- Encrypted backup storage in AWS S3

### Monitoring & Observability
- Prometheus for real-time PostgreSQL metrics
- Grafana for visualizing database performance
- Loki for log aggregation

### CI/CD & Testing
- GitHub Actions for automated PostgreSQL deployment
- `pgTAP` for database unit testing
- Automated security scans

## Database Schema

```mermaid
erDiagram
    CUSTOMERS ||--o{ ORDERS : places
    ORDERS ||--o{ PAYMENTS : generates
    TRANSACTIONS ||--o{ PARTITIONS : belongsTo
