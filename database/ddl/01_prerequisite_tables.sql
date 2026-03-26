--------------------------------------------------------------------------------
-- APEX Component Authorization Framework
-- File: 01_prerequisite_tables.sql
-- Purpose: Core role/user tables required by the authorization framework.
--          In production, these may already exist in your identity management
--          schema. Adjust names and grants as needed for your environment.
-- Platform: Oracle Database 19c
--------------------------------------------------------------------------------

-- Roles table
CREATE TABLE t_app_roles (
    role_id     NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name   VARCHAR2(100) NOT NULL,
    short_name  VARCHAR2(50),
    remarks     VARCHAR2(4000),
    is_active   VARCHAR2(1)   DEFAULT 'Y' NOT NULL,
    ins_user    VARCHAR2(128) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER'),
    ins_date    TIMESTAMP     DEFAULT SYSTIMESTAMP,
    CONSTRAINT uk_app_roles_name UNIQUE (role_name),
    CONSTRAINT ck_app_roles_active CHECK (is_active IN ('Y','N'))
);
COMMENT ON TABLE t_app_roles IS 'Application roles for RBAC authorization';

-- User accounts table
CREATE TABLE t_app_user_accounts (
    account_id  VARCHAR2(255) NOT NULL,
    username    VARCHAR2(255),
    is_active   VARCHAR2(1)   DEFAULT 'Y' NOT NULL,
    created_at  TIMESTAMP     DEFAULT SYSTIMESTAMP,
    CONSTRAINT pk_app_user_accounts PRIMARY KEY (account_id),
    CONSTRAINT ck_app_ua_active CHECK (is_active IN ('Y','N'))
);
COMMENT ON TABLE t_app_user_accounts IS 'User accounts — maps APEX APP_USER to account_id';

-- User-to-role assignments
CREATE TABLE t_app_user_roles (
    account_id  VARCHAR2(255) NOT NULL,
    role_id     NUMBER        NOT NULL,
    assigned_at TIMESTAMP     DEFAULT SYSTIMESTAMP,
    assigned_by VARCHAR2(128) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER'),
    CONSTRAINT pk_app_user_roles PRIMARY KEY (account_id, role_id),
    CONSTRAINT fk_app_ur_account FOREIGN KEY (account_id)
        REFERENCES t_app_user_accounts (account_id),
    CONSTRAINT fk_app_ur_role FOREIGN KEY (role_id)
        REFERENCES t_app_roles (role_id) ON DELETE CASCADE
);
COMMENT ON TABLE t_app_user_roles IS 'Maps users to roles for RBAC authorization';

CREATE INDEX idx_app_ur_role ON t_app_user_roles (role_id);
