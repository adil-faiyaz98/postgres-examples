# Variables
DB_NAME ?= db_dev
DB_USER ?= admin
DB_HOST ?= localhost
PG_VERSION ?= 15
PG_CONTAINER ?= postgres-examples
PG_DATA_DIR ?= ./pgdata
BACKUP_DIR ?= ./backups
TEST_DIR ?= test/pgTAP
K8S_NAMESPACE ?= postgres-security

# Default target (show available commands)
.PHONY: help
help:
	@echo "Makefile commands:"
	@echo "  make setup               - Setup PostgreSQL (Docker, Schema, Users)"
	@echo "  make start               - Start PostgreSQL Docker container"
	@echo "  make stop                - Stop PostgreSQL Docker container"
	@echo "  make restart             - Restart PostgreSQL"
	@echo "  make test                - Run all tests"
	@echo "  make backup              - Perform a database backup"
	@echo "  make restore             - Restore database from backup"
	@echo "  make deploy-terraform    - Deploy PostgreSQL to AWS using Terraform"
	@echo "  make deploy-k8s          - Deploy PostgreSQL to Kubernetes"
	@echo "  make deploy-monitoring   - Deploy monitoring stack to Kubernetes"
	@echo "  make apply-basic-security  - Apply the basic security tier"
	@echo "  make apply-standard-security - Apply the standard security tier"
	@echo "  make apply-advanced-security - Apply the advanced security tier"
	@echo "  make benchmark-security  - Benchmark all security tiers"

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

# Run All Tests
.PHONY: test
test:
	@echo "Running all tests..."
	./test/run-all-tests.sh
	cd test/terratest && go test -v ./...
	./test/kubernetes/postgres-deployment-test.sh
	./test/performance/benchmark_security_tiers.sh

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

# Deploy PostgreSQL to AWS Using Terraform
.PHONY: deploy-terraform
deploy-terraform:
	cd terraform && terraform init && terraform apply -auto-approve

# Deploy PostgreSQL to Kubernetes
.PHONY: deploy-k8s
deploy-k8s:
	@echo "Creating Kubernetes namespaces..."
	kubectl create namespace $(K8S_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
	
	@echo "Deploying PostgreSQL..."
	kubectl apply -f kubernetes/base/postgres/
	
	@echo "Waiting for PostgreSQL to be ready..."
	kubectl wait --for=condition=ready pod -l app=postgres -n $(K8S_NAMESPACE) --timeout=300s
	
	@echo "PostgreSQL deployment complete!"

# Deploy Monitoring Stack
.PHONY: deploy-monitoring
deploy-monitoring:
	@echo "Deploying monitoring stack..."
	kubectl apply -f kubernetes/base/monitoring/prometheus/
	kubectl apply -f kubernetes/base/monitoring/grafana/
	kubectl apply -f kubernetes/base/monitoring/exporters/
	
	@echo "Waiting for monitoring stack to be ready..."
	kubectl wait --for=condition=ready pod -l app=prometheus -n monitoring --timeout=300s
	kubectl wait --for=condition=ready pod -l app=grafana -n monitoring --timeout=300s
	kubectl wait --for=condition=ready pod -l app=postgres-exporter -n monitoring --timeout=300s
	
	@echo "Monitoring stack deployment complete!"

# Apply basic security tier
.PHONY: apply-basic-security
apply-basic-security:
	@echo "Applying Basic Security Tier..."
	kubectl apply -f kubernetes/base/postgres/security/basic/
	@echo "Basic Security Tier applied successfully."

# Apply standard security tier
.PHONY: apply-standard-security
apply-standard-security:
	@echo "Applying Standard Security Tier..."
	kubectl apply -f kubernetes/base/postgres/security/standard/
	@echo "Standard Security Tier applied successfully."

# Apply advanced security tier
.PHONY: apply-advanced-security
apply-advanced-security:
	@echo "Applying Advanced Security Tier..."
	kubectl apply -f kubernetes/base/postgres/security/advanced/
	@echo "Advanced Security Tier applied successfully."

# Benchmark security tiers performance
.PHONY: benchmark-security
benchmark-security:
	@echo "Running Security Tiers Performance Benchmark..."
	./test/performance/benchmark_security_tiers.sh
	@echo "Benchmark complete. Check performance_results directory for reports."
