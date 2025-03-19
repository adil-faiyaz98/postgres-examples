\c db_dev;

-- 1) Create table to store PostgreSQL security enforcement smart contracts
CREATE TABLE IF NOT EXISTS dso.security_smart_contracts (
    contract_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    contract_address TEXT UNIQUE NOT NULL, -- Blockchain address of the deployed smart contract
    security_rule TEXT NOT NULL, -- (e.g., "Revoke Privileges on Anomaly Detection", "Block Malicious IPs")
    execution_status TEXT DEFAULT 'PENDING', -- PENDING, EXECUTED, FAILED
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to trigger smart contract execution for PostgreSQL security actions
CREATE OR REPLACE FUNCTION dso.execute_smart_contract()
RETURNS TRIGGER AS $$
DECLARE smart_contract_api_url TEXT := 'https://blockchain-security-network.com/api/execute-contract';
DECLARE smart_contract_payload TEXT;
BEGIN
    smart_contract_payload := json_build_object(
        'contract_address', NEW.contract_address,
        'security_rule', NEW.security_rule,
        'execution_status', NEW.execution_status
    )::TEXT;

    -- Execute smart contract security rule
    PERFORM http_post(smart_contract_api_url, 'application/json', smart_contract_payload);

    -- Log smart contract execution
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Smart Contract Executed', 'dso.execute_smart_contract', json_build_object('timestamp', NOW()), 'system', NOW());

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to execute PostgreSQL security policies via smart contracts
CREATE TRIGGER execute_smart_contract_trigger
AFTER INSERT
ON dso.security_smart_contracts
FOR EACH ROW
EXECUTE FUNCTION dso.execute_smart_contract();
