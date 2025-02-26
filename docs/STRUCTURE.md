postgres-examples/
│
├── .github/
│   ├── workflows/
│   │   ├── ansible-terraform.yml
│   │   ├── backup-validation.yml
│   │   ├── ci-tests.yml
│   │   ├── security_scanning.yml
│
├── alerts/
│   ├── business_rule.sql
│   ├── partition_maintenance.sql
│   ├── rls_violation.sql
│
├── ansible/
│   ├── backup.yml
│   ├── playbook.yml
│
├── config/
│   ├── backup-encryption.yml
│   ├── barman.conf.j2
│   ├── grafana.ini
│   ├── logging.conf
│   ├── loki-config.yaml
│   ├── pg_hba.conf
│   ├── pgbackrest.conf.j2
│   ├── postgres.conf
│   ├── prometheus.yml
│   ├── recovery.conf
│   ├── tuning.conf
│
├── docker/
│   ├── initdb/
│   │   ├── constraints.sql
│   │   ├── create_databases.sql
│   │   ├── create_schemas.sql
│   │   ├── create_tables.sql
│   │   ├── create_users.sql
│   │   ├── entrypoint.sh
│   │   ├── extensions.sql
│   │   ├── partitioning.sql
│   │   ├── seed_data.sql
│   │   ├── triggers.sql
│   ├── docker-compose.yml
│   ├── Dockerfile
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── README.md
│   ├── SECURITY.md
│
├── logging/
│   ├── central_notification_log.sql
│   ├── export_logs_to_datadog.sql
│   ├── export_logs_to_elk.sql
│   ├── export_logs_to_splunk.sql
│   ├── log_retention_policy.sql
│   ├── log_rotation.sql
│   ├── log_table_cleanup.sql
│
├── monitoring/
│   ├── anomaly_detection_datadog.sql
│   ├── anomaly_detection_elk.sql
│   ├── aws_security_hub_integration.sql
│   ├── dashboard_queries.sql
│   ├── datadog_log_integration.sql
│   ├── detect_sql_injection.sql
│   ├── detect_suspicious_logins.sql
│   ├── grafana_log_dashboard.sql
│   ├── grafana_security_dashboard.sql
│   ├── kibana_elk_integration.sql
│   ├── siem_integration.sql
│
├── notifications/
│   ├── listen_notifications.sql
│   ├── send_email_alerts.sql
│   ├── send_slack_alerts.sql
│   ├── send_webhook_alerts.sql
│
├── soc/
│   ├── aws_security_hub_integration.sql
│   ├── siem_integration.sql
│   ├── soc_dashboard_grafana.sql
│   ├── view_security_dashboard.sql
│
├── threat_hunting/
│   ├── adaptive_hunting_response.sql
│   ├── integrate_aws_detective.sql
│   ├── integrate_google_chronicle.sql
│   ├── integrate_mitre_caldera.sql
│   ├── view_threat_hunting_results.sql
│
├── threat_intelligence/
│   ├── block_high_risk_ips.sql
│   ├── ingest_guardduty_findings.sql
│   ├── ingest_mitre_attack.sql
│
├── threat_sharing/
│   ├── block_taxii_threats.sql
│   ├── ingest_taxii_threat_feeds.sql
│   ├── stix_integration.sql
│   ├── taxii_sharing.sql
│
├── uba/
│   ├── adaptive_security_policies.sql
│   ├── detect_behavior_anomalies.sql
│   ├── train_ml_model.sql
│   ├── user_behavior_tracking.sql
│   ├── view_behavior_anomalies.sql
│
├── terraform/
│   ├── main.tf
│
├── test/
│   ├── pgTAP/
│   │   ├── 01_basics_test.sql
│   │   ├── 02_functions_test.sql
│   │   ├── 04_security_test.sql
│   │   ├── 05_partitioning_test.sql
│   │   ├── 06_data_integrity_test.sql
│   │   ├── setup_pgtap.sql
│   │   ├── test_constraints.sql
│   │   ├── test_row_level_security.sql
│   │   ├── test_triggers.sql
│   ├── run-all-tests.sh
│
├── .env
├── .gitignore
├── LICENSE
├── Makefile
