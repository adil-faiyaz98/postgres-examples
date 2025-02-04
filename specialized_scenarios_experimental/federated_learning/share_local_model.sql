\c db_dev;

-- 1) Create function to send locally trained AI models to Federated Learning aggregation
CREATE OR REPLACE FUNCTION federated_learning.send_model_to_fl_node()
RETURNS VOID AS $$
DECLARE fl_server_url TEXT := 'https://federated-learning-server.com/api/models';
DECLARE model_payload TEXT;
BEGIN
    -- Select latest trained model
    SELECT model_parameters INTO model_payload
    FROM federated_learning.local_ai_models
    ORDER BY trained_on DESC
    LIMIT 1;

    -- Send trained model to FL aggregation node
    PERFORM http_post(fl_server_url, 'application/json', json_build_object('model', model_payload));

    -- Log federated model sharing
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Federated Learning Model Shared', 'federated_learning.send_model_to_fl_node', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Automate model sharing every 24 hours
SELECT cron.schedule('0 0 * * *', 'SELECT federated_learning.send_model_to_fl_node();');
