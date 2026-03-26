# APEX Authorization Scheme Setup

## Step 1: Create the Authorization Scheme

| Setting | Value |
|---------|-------|
| Name | 'DYNAMIC_AUTH' |
| Type | PL/SQL Function Returning Boolean |
| Code | 'RETURN apex_auth_api.f_authorized;' |
| Evaluation Point | **Once per component** |
| Error Message | 'You do not have permission to access this component.' |

## Step 2: Set as Default

**Shared Components -> Security Attributes -> Authorization Scheme** -> select 'DYNAMIC_AUTH'.

## Step 3: Apply to Components

For each page/region/item/button that should be protected, set its **Authorization Scheme** to 'DYNAMIC_AUTH' in the component properties.

For **navigation menu entries**: set the Authorization Scheme on the list entry in **Shared Components -> Navigation Menu -> List Entry -> Authorization**.

## Step 4: Grant Permissions

'''sql
-- Full app access for ADMIN role
BEGIN
    apex_auth_api.grant_permission(
        p_app_id => :APP_ID, p_component_type => 'APPLICATION',
        p_component_key => NULL, p_page_id => NULL,
        p_role_id => 1, p_permission => 'ADMIN');
END;
/
'''

## Convenience Functions

'''sql
-- Check in SQL conditions:
SELECT apex_auth_api.f_authorized_yn(100, 10, 'ITEM', 'P10_SALARY') FROM DUAL;

-- Check EDIT in PL/SQL:
IF apex_auth_api.f_can_edit THEN ... END IF;

-- Check ADMIN:
IF apex_auth_api.f_is_admin THEN ... END IF;

-- Check specific role:
IF apex_auth_api.f_has_role('APP_ADMIN') THEN ... END IF;
'''

## Testing Without APEX Context

'''sql
-- Set test user (works in SQL Workshop)
BEGIN apex_auth_api.set_test_user('DEMO_ADMIN'); END;
/

-- Test authorization
SELECT apex_auth_api.f_authorized_yn(100, 10, 'PAGE', '10') FROM DUAL;

-- Clear test mode
BEGIN apex_auth_api.clear_test_user; END;
/
'''
