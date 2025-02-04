\c db_dev;

-- ) INNER JOIN (customers -> orders)
SELECT
    c.customer_id,
    c.first_name,
    c.last_name,
    o.order_id,
    o.total_amount
FROM inventory.customers c
INNER JOIN inventory.orders o
    ON c.customer_id = o.customer_id
ORDER BY c.customer_id, o.order_id;

-- 2) LEFT JOIN (customers with orders, including those with no orders)
SELECT
    c.customer_id,
    c.first_name,
    c.last_name,
    COALESCE(o.order_id, 'No Order') AS order_id,
    COALESCE(o.total_amount, 0) AS total_amount
FROM inventory.customers c
LEFT JOIN inventory.orders o
    ON c.customer_id = o.customer_id
ORDER BY c.customer_id;

-- 3) RIGHT JOIN (orders matched to customers, including orders without customers)
SELECT
    COALESCE(c.customer_id::TEXT, 'No Customer') AS customer_id,
    c.first_name,
    o.order_id,
    o.total_amount
FROM inventory.customers c
RIGHT JOIN inventory.orders o
    ON c.customer_id = o.customer_id
ORDER BY o.order_id;

-- 4) FULL OUTER JOIN (combine both sides)
SELECT
    COALESCE(c.customer_id::TEXT, 'No Customer') AS customer_id,
    c.first_name,
    COALESCE(o.order_id::TEXT, 'No Order') AS order_id,
    COALESCE(o.total_amount, 0) AS total_amount
FROM inventory.customers c
FULL JOIN inventory.orders o
    ON c.customer_id = o.customer_id
ORDER BY c.customer_id, o.order_id;
