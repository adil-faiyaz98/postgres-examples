\c db_dev;

WITH total_spent AS (
    SELECT
      o.customer_id,
      SUM(o.total_amount) AS total_amount
    FROM inventory.orders o
    GROUP BY o.customer_id
    HAVING SUM(o.total_amount) > 500
)
SELECT c.customer_id, c.first_name, c.last_name, t.total_amount
FROM inventory.customers c
JOIN total_spent t ON c.customer_id = t.customer_id
ORDER BY t.total_amount DESC;


-- Recursive CTE: Generate numbers from 1 to 10
WITH RECURSIVE nums AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM nums
    WHERE n < 10
)
SELECT * FROM nums;

