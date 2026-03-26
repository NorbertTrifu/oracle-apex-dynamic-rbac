--------------------------------------------------------------------------------
-- APEX Component Authorization Framework
-- File: 03_v_apex_components.sql
-- Purpose: Unified view over APEX metadata views, used by apex_auth_api
--          to resolve parent regions for items/buttons/processes.
-- Platform: Oracle APEX 24.1 / Oracle Database 19c
--------------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_apex_components AS
-- Pages
SELECT
    p.application_id  AS app_id,
    p.page_id,
    'PAGE'            AS component_type,
    TO_CHAR(p.page_id) AS component_name,
    NULL              AS static_id,
    p.page_name       AS component_label,
    p.page_id         AS component_id,
    NULL              AS parent_component_id,
    NULL              AS parent_type,
    p.authorization_scheme AS auth_scheme
FROM apex_application_pages p
UNION ALL
-- Regions
SELECT
    r.application_id, r.page_id, 'REGION',
    r.region_name, r.static_id, r.region_name,
    r.region_id, r.parent_region_id, 'REGION',
    r.authorization_scheme
FROM apex_application_page_regions r
UNION ALL
-- Items
SELECT
    i.application_id, i.page_id, 'ITEM',
    i.item_name, i.item_name, COALESCE(i.label, i.item_name),
    i.item_id, i.region_id, 'REGION',
    i.authorization_scheme
FROM apex_application_page_items i
UNION ALL
-- Buttons
SELECT
    b.application_id, b.page_id, 'BUTTON',
    b.button_name, b.button_static_id, b.label,
    b.button_id, b.region_id, 'REGION',
    b.authorization_scheme
FROM apex_application_page_buttons b
UNION ALL
-- Processes
SELECT
    pr.application_id, pr.page_id, 'PROCESS',
    pr.process_name, NULL, pr.process_name,
    pr.process_id, pr.region_id, 'REGION',
    pr.authorization_scheme
FROM apex_application_page_proc pr;

COMMENT ON TABLE v_apex_components IS 'Unified APEX metadata view — used by apex_auth_api to resolve component hierarchy';
/
