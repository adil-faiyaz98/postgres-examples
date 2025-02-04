\c db_dev;

-- 1) Create table to store AI security models trained across decentralized PostgreSQL nodes
CREATE TABLE IF NOT EXISTS cybersecurity_mesh.federated_ai_models (
    model_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID NOT NULL REFERENCES cybersecurity_mesh.mesh_nodes(node_id),
    model_parameters JSONB NOT NULL,  -- Serialized AI model weights
    training_accuracy NUMERIC(5,2),
    trained_on TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to train AI security models on local PostgreSQL security data using Federated Learning
CREATE OR REPLACE FUNCTION cybersecurity_mesh.train_federated_ai_security_model()
RETURNS VOID AS $$
import json
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

# Fetch security incidents from PostgreSQL logs
query = "SELECT event_type, query_execution_time, role_changes, failed_logins FROM ml.anomaly_predictions"
plan = plpy.prepare(query, [])
result = plpy.execute(plan, 1000)

# Convert result into feature vectors
event_list = [list(row.values()) for row in result]
X = np.array([x[:-1] for x in event_list])  # Features
y = np.array([x[-1] for x in event_list])   # Labels (anomaly detected or not)

# Define deep learning model
model = Sequential([
    Dense(32, activation='relu', input_shape=(X.shape[1],)),
    Dense(16, activation='relu'),
    Dense(1, activation='sigmoid')
])

# Compile and train model locally
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.fit(X, y, epochs=5, batch_size=32, verbose=1)

# Store trained model parameters
trained_parameters = model.get_weights()
accuracy = model.evaluate(X, y)[1]

# Insert into PostgreSQL for Federated Learning
plpy.execute(f"INSERT INTO cybersecurity_mesh.federated_ai_models (node_id, model_parameters, training_accuracy) VALUES ('{json.dumps(trained_parameters.tolist())}', {accuracy})")
plpy.info("Federated AI Security Model Training Completed")
$$ LANGUAGE plpython3u;
