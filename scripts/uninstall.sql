PROMPT === APEX Component Authorization Framework — Uninstall ===
DROP PACKAGE apex_auth_api;
DROP VIEW v_auth_admin_ui;
DROP VIEW v_auth_admin;
DROP VIEW v_auth_components_lov;
DROP VIEW v_auth_stats;
DROP VIEW v_apex_components;
DROP TABLE t_auth_component_perms CASCADE CONSTRAINTS PURGE;
DROP TABLE t_app_user_roles CASCADE CONSTRAINTS PURGE;
DROP TABLE t_app_user_accounts CASCADE CONSTRAINTS PURGE;
DROP TABLE t_app_roles CASCADE CONSTRAINTS PURGE;
PROMPT === Uninstall complete ===
