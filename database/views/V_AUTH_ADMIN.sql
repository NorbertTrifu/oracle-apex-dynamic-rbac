CREATE OR REPLACE VIEW V_AUTH_ADMIN AS
SELECT
    p.perm_id,
    p.app_id,
    a.application_name,
    p.component_type,
    p.component_key,
    p.page_id,
    p.role_id,
    r.role_name,
    p.permission_code,
    p.effective_from,
    p.effective_to,
    CASE
        WHEN SYSDATE < p.effective_from THEN 'FUTURE'
        WHEN p.effective_to IS NOT NULL
             AND TRUNC(SYSDATE) > p.effective_to THEN 'EXPIRED'
        ELSE 'ACTIVE'
    END AS status,
    p.created_by,
    p.created_on,
    p.modified_by,
    p.modified_on
FROM t_auth_component_perms p
JOIN t_app_roles r ON r.role_id = p.role_id
LEFT JOIN apex_applications a ON a.application_id = p.app_id;
comment on table V_AUTH_ADMIN is 'Admin view for managing component permissions';
