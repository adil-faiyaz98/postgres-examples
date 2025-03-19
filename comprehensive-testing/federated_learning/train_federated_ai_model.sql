\c db_dev;

-- 1) Enable PL/Python if not installed
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- 2) Train a local AI model using TensorFlow for security anomaly detection
CREATE OR REPLACE FUNCTION federated_learning.train_local_ai_model()
RETURNS VOID AS $$
import json
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

# Fetch local PostgreSQL security incident data
query = "SELECT event_type, query_execution_time, role_changes, failed_logins FROM deep_learning.security_training_data"
plan = plpy.prepare(query, [])
result = plpy.execute(plan, 1000)

# Convert results into feature vectors
event_list = [list(row.values()) for row in result]
X = np.array([x[:-1] for x in event_list])  # Features
y = np.array([x[-1] for x in event_list])   # Labels (anomaly detected or not)

# Define deep learning model
model = Sequential([
    Dense(32, activation='relu', input_shape=(X.shape[1],)),
    Dense(16, activation='relu'),
    Dense(1, activation='sigmoid')
])

# Compile model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train model locally
model.fit(X, y, epochs=5, batch_size=32, verbose=1)

# Store trained model parameters
trained_parameters = model.get_weights()
accuracy = model.evaluate(X, y)[1]

# Insert into PostgreSQL for federated learning
plpy.execute(f"INSERT INTO federated_learning.local_ai_models (model_parameters, training_accuracy) VALUES ('{json.dumps(trained_parameters.tolist())}', {accuracy})")
plpy.info("Local AI Model Training Completed")
$$ LANGUAGE plpython3u;
