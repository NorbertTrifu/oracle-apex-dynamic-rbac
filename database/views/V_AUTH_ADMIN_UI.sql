CREATE OR REPLACE VIEW V_AUTH_ADMIN_UI AS
SELECT adm.perm_id,
        adm.app_id,
        adm.application_name,
        adm.component_type,
        adm.component_key,
        adm.page_id,
        adm.role_id,
        adm.role_name,
        adm.permission_code,
        adm.effective_from,
        adm.effective_to,
        adm.status,
				-- Computed HTML for status badge
			'<span style="border: 1px solid; border-radius: 4px; padding: 2px 8px; font-size: 11px;" class="' ||
			CASE adm.status
					WHEN 'ACTIVE'  THEN 'u-success-text'
					WHEN 'EXPIRED' THEN 'u-danger-text'
					WHEN 'FUTURE'  THEN 'u-warning-text'
			END || '">' ||
			'<span class="fa ' ||
			CASE adm.status
					WHEN 'ACTIVE'  THEN 'fa-check-circle'
					WHEN 'EXPIRED' THEN 'fa-times-circle'
					WHEN 'FUTURE'  THEN 'fa-clock-o'
			END || '"></span> ' || adm.status ||
	    '</span>' AS status_display,
				-- Friendly display value for component
				adm.component_type || ': ' || NVL(adm.component_key, '(App-level)') ||
						CASE WHEN adm.page_id IS NOT NULL THEN ' (P' || adm.page_id || ')' ELSE '' END
						AS component_display,
				-- Permission icon
				CASE adm.permission_code
						WHEN 'ADMIN' THEN 'fa-shield'
						WHEN 'EDIT'  THEN 'fa-pencil'
						WHEN 'VIEW'  THEN 'fa-eye'
						WHEN 'DENY'  THEN 'fa-ban'
						ELSE 'fa-question'
				END AS permission_icon,
				-- Permission CSS class
				CASE adm.permission_code
						WHEN 'ADMIN' THEN 'u-success-text'
						WHEN 'EDIT'  THEN 'u-info-text'
						WHEN 'VIEW'  THEN 'u-normal-text'
						WHEN 'DENY'  THEN 'u-danger-text'
						ELSE ''
				END AS permission_css,
        adm.created_by,
        adm.created_on,
        adm.modified_by,
        adm.modified_on
	 FROM v_AUTH_admin adm
;
