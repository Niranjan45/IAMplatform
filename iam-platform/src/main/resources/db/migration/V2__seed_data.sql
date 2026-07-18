-- ============================================================
-- V2: Seed default roles, permissions and an admin user (MySQL Version)
-- Default admin credentials: admin@enterprise-iam.com / Admin@123
-- CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN IN PRODUCTION
-- ============================================================

INSERT INTO permissions (name, description) VALUES
    ('USER_READ', 'View user details'),
    ('USER_WRITE', 'Create or update users'),
    ('USER_DELETE', 'Delete users'),
    ('ROLE_READ', 'View roles'),
    ('ROLE_WRITE', 'Create or update roles'),
    ('ROLE_DELETE', 'Delete roles'),
    ('PERMISSION_READ', 'View permissions'),
    ('PERMISSION_WRITE', 'Create or update permissions'),
    ('AUDIT_READ', 'View audit logs'),
    ('ADMIN_ACCESS', 'General admin console access');

INSERT INTO roles (name, description) VALUES
    ('ROLE_ADMIN', 'System administrator with full access'),
    ('ROLE_MANAGER', 'Manager with elevated read access'),
    ('ROLE_USER', 'Standard authenticated user');

-- ROLE_ADMIN gets every permission
-- Note: MySQL alias wrap used to bypass modification table selection restrictions
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM (SELECT id, name FROM roles) AS r WHERE r.name = 'ROLE_ADMIN'), id 
FROM permissions;

-- ROLE_MANAGER gets read permissions + audit read
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM (SELECT id, name FROM roles) AS r WHERE r.name = 'ROLE_MANAGER'), id
FROM permissions 
WHERE name IN ('USER_READ', 'ROLE_READ', 'PERMISSION_READ', 'AUDIT_READ');

-- Seed default admin user (password: Admin@123)
INSERT INTO users (email, username, password_hash, first_name, last_name, enabled, email_verified, account_non_locked, mfa_enabled)
VALUES ('admin@enterprise-iam.com', 'admin', '$2b$10$ovQn68ckPrRDZglLs.Mice9vcGzTL1r5QuczWMR//1y6oBt7Y6qnK', 'System', 'Administrator', TRUE, TRUE, TRUE, FALSE);

-- Assign ROLE_ADMIN to admin user
INSERT INTO user_roles (user_id, role_id)
SELECT 
    (SELECT id FROM (SELECT id, username FROM users) AS u WHERE u.username = 'admin'), 
    (SELECT id FROM (SELECT id, name FROM roles) AS r WHERE r.name = 'ROLE_ADMIN');
