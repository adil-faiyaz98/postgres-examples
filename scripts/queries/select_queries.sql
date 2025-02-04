\c db_dev;

-- Retrieve all customers
SELECT * FROM inventory.customers LIMIT 10;

-- Get all orders over $100
SELECT order_id, customer_id, total_amount
FROM inventory.orders
WHERE total_amount > 100
ORDER BY total_amount DESC;

-- Get all shipped orders
SELECT order_id, customer_id, total_amount, status
FROM inventory.orders
WHERE status = 'SHIPPED';

-- Get top 5 customers by spending
SELECT c.customer_id, c.first_name, c.last_name, SUM(o.total_amount) AS total_spent
FROM inventory.customers c
JOIN inventory.orders o ON c.customer_id = o.customer_id
GROUP BY c.customer_id, c.first_name, c.last_name
ORDER BY total_spent DESC
LIMIT 5;

-- Count total orders per customer
SELECT customer_id, COUNT(*) AS order_count
FROM inventory.orders
GROUP BY customer_id
ORDER BY order_count DESC;
