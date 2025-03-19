\c db_dev;

-- 1) Create table to store locally trained AI security models before sharing
CREATE TABLE IF NOT EXISTS federated_learning.local_ai_models (
    model_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trained_on TIMESTAMPTZ DEFAULT NOW(),
    model_parameters JSONB NOT NULL,  -- Serialized AI model weights
    training_accuracy NUMERIC(5,2)
);

-- 2) Create table to receive global federated AI model updates
CREATE TABLE IF NOT EXISTS federated_learning.global_ai_models (
    model_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    received_on TIMESTAMPTZ DEFAULT NOW(),
    aggregated_parameters JSONB NOT NULL,  -- Aggregated AI model from all nodes
    federated_accuracy NUMERIC(5,2)
);
