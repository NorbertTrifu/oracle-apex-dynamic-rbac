--------------------------------------------------------------------------------
-- APEX Component Authorization Framework — Master Install
-- Platform: Oracle Database 19c / Oracle APEX 24.1
-- Usage: @scripts/install.sql
--------------------------------------------------------------------------------
SET ECHO ON
SET DEFINE OFF
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT === APEX Component Authorization Framework — Installing ===

PROMPT Step 1/5: Creating prerequisite tables (roles, users, assignments)...
@../database/ddl/01_prerequisite_tables.sql

PROMPT Step 2/5: Creating permission table (t_auth_component_perms)...
@../database/ddl/02_t_auth_component_perms.sql

PROMPT Step 3/5: Creating views...
@../database/views/00_V_APEX_COMPONENTS.sql
@../database/views/V_AUTH_ADMIN.sql
@../database/views/V_AUTH_ADMIN_UI.sql
@../database/views/V_AUTH_COMPONENTS_LOV.sql
@../database/views/V_AUTH_STATS.sql

PROMPT Step 4/5: Compiling apex_auth_api package...
@../database/packages/apex_auth_api.pck

PROMPT Step 5/5: Loading seed data (optional demo data)...
@../database/seed/01_seed_data.sql

PROMPT
PROMPT === Verifying installation ===
SELECT object_type, object_name, status
  FROM user_objects
 WHERE (object_name LIKE '%AUTH%' OR object_name LIKE '%APP_ROLE%' OR object_name LIKE '%APP_USER%')
   AND status != 'VALID'
 ORDER BY object_type, object_name;

PROMPT === Installation complete ===
PROMPT Next: Create APEX authorization scheme (see apex/apex_setup_guide.md)
SET ECHO OFF
SET DEFINE ON
