\c db_dev;

-- 1) Create function to predict security threats using deep learning
CREATE OR REPLACE FUNCTION deep_learning.predict_security_threat(
    event_type TEXT, query_execution_time NUMERIC, role_changes INT, failed_logins INT
) RETURNS BOOLEAN AS $$
import numpy as np
import tensorflow as tf

# Load trained model (assume model is stored in PostgreSQL or external storage)
model = tf.keras.models.load_model('/path/to/security_model')

# Prepare input data
X_new = np.array([[query_execution_time, role_changes, failed_logins]])

# Predict anomaly (1 = Anomaly, 0 = Normal)
prediction = model.predict(X_new)
return bool(prediction[0] > 0.5)
$$ LANGUAGE plpython3u;
