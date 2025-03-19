# Project Structure

```
.
├── .github/
│   └── workflows/
│       ├── ci-tests.yml
│       ├── security-benchmark-pipeline.yml
│       ├── docker-build.yml
│       ├── security_scanning.yml
│       └── backup-validation.yml
├── docker/
│   └── Dockerfile
├── kubernetes/
│   ├── namespace.yaml
│   ├── postgres.yaml
│   └── security-tier-configmap.yaml
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
├── test/
│   ├── integration/
│   │   └── integration_test.sh
│   ├── kubernetes/
│   │   └── postgres-deployment-test.sh
│   └── terratest/
│       └── eks_test.go
├── scripts/
│   └── detect_infrastructure_drift.sh
└── Makefile
