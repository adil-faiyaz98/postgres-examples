\c db_dev;

-- View training accuracy of local PostgreSQL AI models
SELECT trained_on, training_accuracy
FROM federated_learning.local_ai_models
ORDER BY trained_on DESC
LIMIT 10;

-- View federated learning model updates received from global consortium
SELECT received_on, federated_accuracy
FROM federated_learning.global_ai_models
ORDER BY received_on DESC
LIMIT 10;

-- Compare federated model monitoring vs. local models
SELECT l.trained_on, l.training_accuracy, g.received_on, g.federated_accuracy
FROM federated_learning.local_ai_models l
JOIN federated_learning.global_ai_models g
ORDER BY l.trained_on DESC
LIMIT 10;
