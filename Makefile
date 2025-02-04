# Variables
DB_NAME ?= db_dev
DB_USER ?= admin
DB_HOST ?= localhost
PG_VERSION ?= 15
PG_CONTAINER ?= postgres-examples
PG_DATA_DIR ?= ./pgdata
BACKUP_DIR ?= ./backups
TEST_DIR ?= test/pgTAP

# Default target (show available commands)
.PHONY: help
help:
	@echo "Makefile commands:"
	@echo "  make setup               - Setup PostgreSQL (Docker, Schema, Users)"
	@echo "  make start               - Start PostgreSQL Docker container"
	@echo "  make stop                - Stop PostgreSQL Docker container"
	@echo "  make restart             - Restart PostgreSQL"
	@echo "  make test                - Run pgTAP tests"
	@echo "  make backup              - Perform a database backup"
	@echo "  make restore             - Restore database from backup"
	@echo "  make deploy-ansible      - Deploy PostgreSQL using Ansible"
	@echo "  make deploy-terraform    - Deploy PostgreSQL to AWS using Terraform"

# Setup PostgreSQL: Docker, Schema, Users
.PHONY: setup
setup: start init-db

# Start PostgreSQL Container
.PHONY: start
start:
	docker-compose up -d

# Stop PostgreSQL Container
.PHONY: stop
stop:
	docker-compose down

# Restart PostgreSQL Container
.PHONY: restart
restart: stop start

# Initialize Database Schema & Users
.PHONY: init-db
init-db:
	@echo "Initializing Database Schema..."
	docker exec -i $(PG_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) < init/01-create-databases.sql
	docker exec -i $(PG_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) < init/02-create-schemas.sql
	docker exec -i $(PG_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) < init/03-create-tables.sql
	docker exec -i $(PG_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) < init/seed_data.sql

# Run pgTAP Tests
.PHONY: test
test:
	./test/pgTAP/run-all-tests.sh --parallel

# Perform Database Backup
.PHONY: backup
backup:
	mkdir -p $(BACKUP_DIR)
	docker exec $(PG_CONTAINER) pg_dump -U $(DB_USER) -d $(DB_NAME) > $(BACKUP_DIR)/$(DB_NAME)_$(shell date +%F).sql
	@echo "Backup saved to $(BACKUP_DIR)/$(DB_NAME)_$(shell date +%F).sql"

# Restore Database from Backup
.PHONY: restore
restore:
	docker exec -i $(PG_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) < $(BACKUP_DIR)/$(DB_NAME)_latest.sql
	@echo "Database restored from $(BACKUP_DIR)/$(DB_NAME)_latest.sql"

# Deploy PostgreSQL Using Ansible
.PHONY: deploy-ansible
deploy-ansible:
	ansible-playbook ansible/playbook.yml -i "db_servers,"

# Deploy PostgreSQL to AWS Using Terraform
.PHONY: deploy-terraform
deploy-terraform:
	cd terraform && terraform init && terraform apply -auto-approve
