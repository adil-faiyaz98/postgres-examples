\c db_dev;

-- 1) Create table to store smart contract-verified PostgreSQL security rules
CREATE TABLE IF NOT EXISTS decentralized_security.smart_contract_rules (
    contract_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    contract_address TEXT UNIQUE NOT NULL, -- Blockchain address of the deployed smart contract
    security_rule TEXT NOT NULL, -- (e.g., "Disable High-Risk Users", "Block Malicious IPs")
    execution_status TEXT DEFAULT 'PENDING', -- PENDING, EXECUTED, FAILED
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to execute smart contract-based security actions
CREATE OR REPLACE FUNCTION decentralized_security.execute_smart_contract_action()
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
    VALUES ('Smart Contract Executed', 'decentralized_security.execute_smart_contract_action', json_build_object('timestamp', NOW()), 'system', NOW());

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to execute PostgreSQL security rules via smart contracts
CREATE TRIGGER smart_contract_execution_trigger
AFTER INSERT
ON decentralized_security.smart_contract_rules
FOR EACH ROW
EXECUTE FUNCTION decentralized_security.execute_smart_contract_action();
