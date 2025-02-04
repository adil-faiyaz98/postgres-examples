# PostgreSQL Examples Repository

## Overview
This repository contains advanced PostgreSQL examples, including security best practices, partitioning, indexing, logging, monitoring, and CI/CD integration.

## Features
- Automated PostgreSQL deployment using Docker, Ansible, and Terraform
- Secure database configurations with RBAC, RLS, and audit logging
- Automated backups using `pgBackRest` and `Barman`
- Integrated monitoring with Prometheus, Grafana, and Loki
- Full test automation using `pgTAP` and GitHub Actions

## Prerequisites
- Docker and Docker Compose
- PostgreSQL 15+
- Ansible (for server-based deployment)
- Terraform (for cloud-based deployment)

## Installation and Setup

### Clone the Repository
```sh
git clone https://github.com/adil-faiyaz98/postgres-examples
cd postgres-examples
```

# Run PostgreSQL with Docker
```sh
docker-compose up -d

```

# Verify DB Connection
```sh
psql -h localhost -U app_user -d db_dev

```

# Run tests
```sh
chmod +x test/pgTAP/run-all-tests.sh
test/pgTAP/run-all-tests.sh --sequential
```



