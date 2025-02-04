\c db_dev;

-- 1) Enable PL/Python if not installed
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- 2) Create AI model for anomaly detection using Isolation Forest
CREATE OR REPLACE FUNCTION uba.train_user_behavior_model()
RETURNS VOID AS $$
import json
import numpy as np
from sklearn.ensemble import IsolationForest

# Fetch historical user activity data
query = "SELECT event_details FROM uba.user_activity_logs"
plan = plpy.prepare(query, [])
result = plpy.execute(plan, 1000)  # Fetch up to 1000 records

# Convert result into feature vectors
event_list = [json.loads(row["event_details"]) for row in result]
X = np.array([list(event.values()) for event in event_list])

# Train Isolation Forest model
model = IsolationForest(n_estimators=100, contamination=0.05)
model.fit(X)

# Store trained model (This can be extended with PostgreSQL ML storage)
plpy.info("User Behavior Model Training Completed")
$$ LANGUAGE plpython3u;
