\c db_dev;

-- View PostgreSQL security mesh nodes and their status
SELECT * FROM cybersecurity_mesh.security_mesh_nodes
ORDER BY last_checked DESC
LIMIT 50;

-- View PostgreSQL self-healing security actions taken by AI
SELECT * FROM cybersecurity_mesh.self_healing_actions
ORDER BY executed_at DESC
LIMIT 50;

-- View Zero-Knowledge Proof security verifications
SELECT * FROM cybersecurity_mesh.zkp_verifications
ORDER BY verified_at DESC
LIMIT 50;
