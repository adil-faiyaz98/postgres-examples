\c db_dev;

-- 1) Enable PL/Python if not installed
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- 2) Train a deep learning model using TensorFlow
CREATE OR REPLACE FUNCTION deep_learning.train_security_model()
RETURNS VOID AS $$
import json
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

# Fetch training data from PostgreSQL
query = "SELECT event_type, query_execution_time, role_changes, failed_logins, detected_anomaly FROM deep_learning.security_training_data"
plan = plpy.prepare(query, [])
result = plpy.execute(plan, 1000)

# Convert result into feature vectors
event_list = [list(row.values()) for row in result]
X = np.array([x[:-1] for x in event_list])  # Features
y = np.array([x[-1] for x in event_list])   # Labels (anomaly detected or not)

# Define deep learning model (Simple Neural Network)
model = Sequential([
    Dense(32, activation='relu', input_shape=(X.shape[1],)),
    Dense(16, activation='relu'),
    Dense(1, activation='sigmoid')
])

# Compile model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train model
model.fit(X, y, epochs=10, batch_size=32, verbose=1)

# Store trained model
plpy.info("Deep Learning AI Model Training Completed")
$$ LANGUAGE plpython3u;
