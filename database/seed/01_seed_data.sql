--------------------------------------------------------------------------------
-- APEX Component Authorization Framework — Seed Data
-- Optional demo data. Remove before production deployment.
--------------------------------------------------------------------------------

-- Demo roles
INSERT INTO t_app_roles (role_name, short_name, remarks)
VALUES ('APP_ADMIN', 'ADMIN', 'Full application administrator');
INSERT INTO t_app_roles (role_name, short_name, remarks)
VALUES ('APP_MANAGER', 'MGR', 'Department manager with edit access');
INSERT INTO t_app_roles (role_name, short_name, remarks)
VALUES ('APP_VIEWER', 'VIEW', 'Read-only access');

-- Demo user
INSERT INTO t_app_user_accounts (account_id, username) VALUES ('DEMO_ADMIN', 'Demo Admin');
INSERT INTO t_app_user_accounts (account_id, username) VALUES ('DEMO_USER', 'Demo User');

-- Assign roles
INSERT INTO t_app_user_roles (account_id, role_id)
SELECT 'DEMO_ADMIN', role_id FROM t_app_roles WHERE role_name = 'APP_ADMIN';
INSERT INTO t_app_user_roles (account_id, role_id)
SELECT 'DEMO_USER', role_id FROM t_app_roles WHERE role_name = 'APP_VIEWER';

COMMIT;
