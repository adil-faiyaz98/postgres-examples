\c db_dev;

-- 1) Create function to retrain AI models based on SOAR actions
CREATE OR REPLACE FUNCTION feedback_loop.retrain_ai_models()
RETURNS VOID AS $$
import json
import numpy as np
from sklearn.ensemble import IsolationForest

# Fetch past AI predictions and SOAR responses
query = """
SELECT event_type, user_id, ip_address
FROM feedback_loop.soar_security_responses
"""
plan = plpy.prepare(query, [])
result = plpy.execute(plan, 1000)  # Fetch up to 1000 records

# Convert result into feature vectors
event_list = [list(row.values()) for row in result]
X = np.array(event_list)

# Train updated Isolation Forest model for anomaly detection
model = IsolationForest(n_estimators=150, contamination=0.03)
model.fit(X)

# Store trained model (This can be extended with PostgreSQL ML storage)
plpy.info("Updated AI Model Training Completed")
$$ LANGUAGE plpython3u;
