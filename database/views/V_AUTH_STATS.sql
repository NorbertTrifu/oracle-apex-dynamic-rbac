CREATE OR REPLACE VIEW V_AUTH_STATS AS
SELECT
    'TOTAL_ROLES' AS stat_key,
    'Total Roles' AS stat_label,
    COUNT(*) AS stat_value,
    'fa-users' AS stat_icon,
    'u-color-1' AS stat_css
FROM t_app_roles
UNION ALL
SELECT
    'ACTIVE_PERMS',
    'Active Permissions',
    COUNT(*),
    'fa-key',
    'u-color-4'
FROM t_auth_component_perms
WHERE SYSDATE BETWEEN effective_from AND NVL(effective_to, SYSDATE + 1)
UNION ALL
SELECT
    'USER_ASSIGNMENTS',
    'User Assignments',
    COUNT(*),
    'fa-user-plus',
    'u-color-9'
FROM t_app_user_roles
UNION ALL
SELECT
    'EXPIRING_SOON',
    'Expiring in 30 days',
    COUNT(*),
    'fa-clock-o',
    'u-color-8'
FROM t_auth_component_perms
WHERE effective_to BETWEEN SYSDATE AND SYSDATE + 30
UNION ALL
SELECT
    'EXPIRED',
    'Expired Permissions',
    COUNT(*),
    'fa-times-circle',
    'u-danger'
FROM t_auth_component_perms
WHERE effective_to IS NOT NULL AND effective_to < SYSDATE
UNION ALL
SELECT
    'FUTURE',
    'Future Permissions',
    COUNT(*),
    'fa-calendar',
    'u-warning'
FROM t_auth_component_perms
WHERE effective_from > SYSDATE;
