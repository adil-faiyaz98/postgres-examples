\c db_dev;

-- Ranking orders based on total amount
SELECT
    o.order_id,
    o.customer_id,
    o.total_amount,
    ROW_NUMBER() OVER (ORDER BY o.total_amount DESC) AS row_num,
    RANK()       OVER (ORDER BY o.total_amount DESC) AS rank_num
FROM inventory.orders o;

-- Partitioning by customer to calculate total spend per customer
SELECT
    o.customer_id,
    o.order_id,
    o.total_amount,
    SUM(o.total_amount) OVER (PARTITION BY o.customer_id) AS sum_by_customer
FROM inventory.orders o
ORDER BY o.customer_id, o.order_id;
