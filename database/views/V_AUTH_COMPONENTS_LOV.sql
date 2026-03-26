CREATE OR REPLACE VIEW V_AUTH_COMPONENTS_LOV AS
SELECT
    p.application_id AS app_id,
    'PAGE' AS component_type,
    TO_CHAR(p.page_id) AS component_key,
    p.page_id,
    p.page_name AS component_label,
    'Page ' || p.page_id || ' - ' || p.page_name AS display_value,
    1 AS sort_order
FROM apex_application_pages p
UNION ALL
SELECT
    r.application_id, 'REGION',
    COALESCE(r.static_id, r.region_name), r.page_id, r.region_name,
    'Region: ' || r.region_name || ' (P' || r.page_id || ')', 2
FROM apex_application_page_regions r
UNION ALL
SELECT
    i.application_id, 'ITEM',
    i.item_name, i.page_id, COALESCE(i.label, i.item_name),
    'Item: ' || i.item_name || ' (P' || i.page_id ||' - ' ||i.region || ')', 3
FROM apex_application_page_items i
UNION ALL
SELECT
    b.application_id, 'BUTTON',
    COALESCE(b.button_static_id, b.button_name), b.page_id, b.button_name,
    'Button: ' || b.button_name|| ' (P' || b.page_id ||' - ' ||b.region || ')', 4
FROM apex_application_page_buttons b
UNION ALL
SELECT
    pr.application_id, 'PROCESS',
    pr.process_name, pr.page_id, pr.process_name,
    'Process: ' || pr.process_name || ' (P' || pr.page_id ||' - ' ||pr.region_name || ')', 5
FROM apex_application_page_proc pr
UNION ALL
SELECT
    le.application_id, 'LIST_ENTRY',
    COALESCE(le.entry_attribute_01, REPLACE(le.entry_text, ' ', '_')), NULL, le.entry_text,
    'Nav: ' || CASE WHEN le.parent_entry_text IS NOT NULL THEN 'Parent:'|| le.parent_entry_text || '-'
		              ELSE Null END || 'Entry:'  || le.entry_text
		, 6
FROM apex_application_list_entries le
 WHERE le.authorization_scheme IS NOT NULL
	 AND EXISTS (SELECT 1 FROM apex_application_lists l WHERE l.list_id = le.list_id AND l.application_id = le.application_id AND l.component_signature LIKE 'Navigation Menu%');
