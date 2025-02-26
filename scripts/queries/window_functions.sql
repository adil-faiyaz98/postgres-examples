\c db_dev;

-- Ranking orders based on total amount
SELECT
    o.order_id,
    o.customer_id,
    o.total_amount,
    ROW_NUMBER() OVER (PARTITION BY o.customer_id ORDER BY o.total_amount DESC) AS row_num,
    RANK()       OVER (PARTITION BY o.customer_id ORDER BY o.total_amount DESC) AS rank_num
FROM inventory.orders o;
