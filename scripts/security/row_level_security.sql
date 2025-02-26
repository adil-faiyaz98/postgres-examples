\c db_dev;

-- 1) Enable RLS on Sensitive Tables
ALTER TABLE inventory.customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounting.payments ENABLE ROW LEVEL SECURITY;

-- 2) Create Policies for SELECT Access (Users Can Only See Their Own Data)
CREATE POLICY customers_rls_select
ON inventory.customers
FOR SELECT
TO app_user
USING (customer_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY orders_rls_select
ON inventory.orders
FOR SELECT
TO app_user
USING (customer_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY payments_rls_select
ON accounting.payments
FOR SELECT
TO app_user
USING (order_id IN (SELECT order_id FROM inventory.orders WHERE customer_id = current_setting('app.current_user_id')::uuid));

-- 3) Restrict Updates to Own Records
CREATE POLICY customers_rls_update
ON inventory.customers
FOR UPDATE
TO app_user
USING (customer_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY orders_rls_update
ON inventory.orders
FOR UPDATE
TO app_user
USING (customer_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY payments_rls_update
ON accounting.payments
FOR UPDATE
TO app_user
USING (order_id IN (SELECT order_id FROM inventory.orders WHERE customer_id = current_setting('app.current_user_id')::uuid));

-- 4) Prevent Unauthorized Deletions (Users Can Only Delete Their Own Records)
CREATE POLICY customers_rls_delete
ON inventory.customers
FOR DELETE
TO app_user
USING (customer_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY orders_rls_delete
ON inventory.orders
FOR DELETE
TO app_user
USING (customer_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY payments_rls_delete
ON accounting.payments
FOR DELETE
TO app_user
USING (order_id IN (SELECT order_id FROM inventory.orders WHERE customer_id = current_setting('app.current_user_id')::uuid));

-- 5) Apply RLS Enforcement
ALTER TABLE inventory.customers FORCE ROW LEVEL SECURITY;
ALTER TABLE inventory.orders FORCE ROW LEVEL SECURITY;
ALTER TABLE accounting.payments FORCE ROW LEVEL SECURITY;

-- 6) Enforce Session-Based Security for RLS
SET LOCAL app.current_user_id = '123e4567-e89b-12d3-a456-426614174000';
