CREATE OR REPLACE PACKAGE apex_auth_api AS
    /*
    ============================================================================
    APEX Component Authorization API
    ============================================================================
    CREATED BY: Norbert
    PURPOSE:
        Provides role-based authorization for APEX components using a single
        authorization scheme.
        Roles are mapped to components in the t_auth_component_perms table,
        and here we check if the current user's roles grant access.

    HIERARCHY RULES:
        - APPLICATION > PAGE > REGION > ITEM/BUTTON/PROCESS
				- For LIST_ENTRY: APPLICATION > PARENT_LIST_ENTRY > LIST_ENTRY
        - DENY at any level blocks access (checked first)
        - Permissions inherit down the hierarchy
        - ADMIN implies EDIT implies VIEW
    ============================================================================
    */

    ---------------------------------------------------------------------------
    -- SUBTYPES: Anchored to table columns for maintainability
    ---------------------------------------------------------------------------
    SUBTYPE t_vc2_small      IS VARCHAR2(100);
    SUBTYPE t_vc2_short      IS VARCHAR2(255);
		SUBTYPE t_vc2_normal     IS VARCHAR2(1000);
		SUBTYPE t_vc2_large      IS VARCHAR2(4000);
    SUBTYPE t_vc2_max        IS VARCHAR2(32767);
    
    -- Application and page identifiers
    SUBTYPE t_app_id         IS NUMBER(6);
    SUBTYPE t_page_id        IS NUMBER(6);

    -- Component identification
    SUBTYPE t_component_key  IS t_vc2_short;   -- Static ID or name
    SUBTYPE t_component_type IS VARCHAR2(50);
		SUBTYPE t_component_id   IS NUMBER;

    -- Permission code (ADMIN, EDIT, VIEW, DENY)
    SUBTYPE t_permission     IS VARCHAR2(30);

    -- Role and account identifiers
    SUBTYPE t_role_id        IS t_app_roles.role_id%TYPE;
    SUBTYPE t_account_id     IS t_app_user_accounts.account_id%TYPE;

    -- General purpose types
    SUBTYPE t_username       IS t_vc2_short;
    SUBTYPE t_yes_no         IS CHAR(1);
    SUBTYPE t_error_msg      IS t_vc2_large;
    SUBTYPE t_scope          IS t_vc2_small;

    ---------------------------------------------------------------------------
    -- CONSTANTS: Permission codes
    ---------------------------------------------------------------------------
    c_perm_admin        CONSTANT t_permission := 'ADMIN';
    c_perm_edit         CONSTANT t_permission := 'EDIT';
    c_perm_view         CONSTANT t_permission := 'VIEW';
    c_perm_deny         CONSTANT t_permission := 'DENY';

    ---------------------------------------------------------------------------
    -- CONSTANTS: Internal component types (matching APEX bind variable values)
    ---------------------------------------------------------------------------
    c_type_application  CONSTANT t_component_type := 'APPLICATION';
    c_type_page         CONSTANT t_component_type := 'PAGE';
    c_type_region       CONSTANT t_component_type := 'REGION';
    c_type_item         CONSTANT t_component_type := 'ITEM';
    c_type_button       CONSTANT t_component_type := 'BUTTON';
    c_type_process      CONSTANT t_component_type := 'PROCESS';
    c_type_nav_entry    CONSTANT t_component_type := 'NAV_ENTRY';
    c_type_nav_bar      CONSTANT t_component_type := 'NAV_BAR';
    c_type_list_entry   CONSTANT t_component_type := 'LIST_ENTRY';
    c_type_tab          CONSTANT t_component_type := 'TAB';
    c_type_menu         CONSTANT t_component_type := 'MENU';
    ---------------------------------------------------------------------------
    -- CONSTANTS: APEX metadata view names (what APEX sends in APP_COMPONENT_TYPE)
    ---------------------------------------------------------------------------
    c_apex_pages        CONSTANT t_vc2_small := 'APEX_APPLICATION_PAGES';
    c_apex_regions      CONSTANT t_vc2_small := 'APEX_APPLICATION_PAGE_REGIONS';
    c_apex_items        CONSTANT t_vc2_small := 'APEX_APPLICATION_PAGE_ITEMS';
    c_apex_buttons      CONSTANT t_vc2_small := 'APEX_APPLICATION_PAGE_BUTTONS';
    c_apex_processes    CONSTANT t_vc2_small := 'APEX_APPLICATION_PAGE_PROC';
    c_apex_list_entries CONSTANT t_vc2_small := 'APEX_APPLICATION_LIST_ENTRIES';
    c_apex_navbar       CONSTANT t_vc2_small := 'APEX_APPLICATION_NAV_BAR';
    c_apex_tabs         CONSTANT t_vc2_small := 'APEX_APPLICATION_TABS';
    ---------------------------------------------------------------------------
    -- CONSTANTS: Boolean flags and defaults
    ---------------------------------------------------------------------------
    c_yes               CONSTANT t_yes_no := 'Y';
    c_no                CONSTANT t_yes_no := 'N';
    c_default_on_error  CONSTANT BOOLEAN := FALSE;  -- Fail closed for security
    c_end_of_time       CONSTANT DATE := DATE '9999-12-31';

    ---------------------------------------------------------------------------
    -- EXCEPTIONS
    ---------------------------------------------------------------------------
    e_user_not_found     EXCEPTION;
    PRAGMA EXCEPTION_INIT(e_user_not_found, -20001);
    c_err_user_not_found CONSTANT PLS_INTEGER := -20001;

    e_invalid_permission EXCEPTION;
    PRAGMA EXCEPTION_INIT(e_invalid_permission, -20002);
    c_err_invalid_perm   CONSTANT PLS_INTEGER := -20002;

    e_invalid_component  EXCEPTION;
    PRAGMA EXCEPTION_INIT(e_invalid_component, -20003);
    c_err_invalid_comp   CONSTANT PLS_INTEGER := -20003;
		
		e_component_def EXCEPTION;
		PRAGMA EXCEPTION_INIT(e_component_def, -20010);
		c_err_component_def  CONSTANT PLS_INTEGER := -20010;

    ---------------------------------------------------------------------------
    -- COLLECTION TYPES
    ---------------------------------------------------------------------------
    TYPE t_role_id_tab IS TABLE OF t_role_id;
    
    -- Note: t_pattern_map is defined in body since associative arrays
    -- cannot be initialized in package specification

    ---------------------------------------------------------------------------
    -- AUTHORIZATION FUNCTIONS
    ---------------------------------------------------------------------------
    
    /*
    ---------------------------------------------------------------------------
    SCOPE-Main entry point for APEX authorization scheme
    ---------------------------------------------------------------------------
    Uses APEX bind variables to determine what component is being checked.
    Returns TRUE if user has at least the required permission, FALSE otherwise.

    APEX Bind Variables Used:
        - APP_ID: Current application ID
        - APP_PAGE_ID: Current page ID
        - APP_COMPONENT_TYPE: Type of component being rendered
        - APP_COMPONENT_NAME: Name/identifier of the component
    ---------------------------------------------------------------------------
    */
    FUNCTION f_authorized (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL,
				p_component_id    IN NUMBER           DEFAULT NULL,
        p_required_perm   IN t_permission     DEFAULT c_perm_view
    ) RETURN BOOLEAN;

    /*
    ---------------------------------------------------------------------------
    SCOPE-Same as f_authorized but returns 'Y'/'N'
    ---------------------------------------------------------------------------
    Useful for SQL queries and conditions that need VARCHAR2 instead of BOOLEAN.
    ---------------------------------------------------------------------------
    */
    FUNCTION f_authorized_yn (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL,
        p_required_perm   IN t_permission     DEFAULT c_perm_view
    ) RETURN VARCHAR2;
	
    ---------------------------------------------------------------------------
    -- PERMISSION FUNCTIONS
    ---------------------------------------------------------------------------

    /*
    ---------------------------------------------------------------------------
    SCOPE-Get user's permission level for a component
    ---------------------------------------------------------------------------
    Returns: 'ADMIN', 'EDIT', 'VIEW', 'DENY', or NULL if no permission
    ---------------------------------------------------------------------------
    */
    FUNCTION f_effective_permission (
        p_app_id          IN t_app_id,
        p_page_id         IN t_page_id,
        p_component_type  IN t_component_type,
        p_component_key   IN t_component_key,
				p_component_id    IN t_component_id,
        p_account_id      IN t_account_id DEFAULT NULL
    ) RETURN t_permission;

    /*
    ---------------------------------------------------------------------------
    SCOPE-Shortcut to check for EDIT permission
    ---------------------------------------------------------------------------
    */
    FUNCTION f_can_edit (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL
    ) RETURN BOOLEAN;

    /*
    ---------------------------------------------------------------------------
    SCOPE-Shortcut to check for ADMIN permission
    ---------------------------------------------------------------------------
    */
    FUNCTION f_is_admin (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL
    ) RETURN BOOLEAN;
    
    ---------------------------------------------------------------------------
    -- ROLE CHECK FUNCTIONS
    ---------------------------------------------------------------------------

    /*
    ---------------------------------------------------------------------------
    SCOPE-Check if current user has a specific role
    ---------------------------------------------------------------------------
    */
    FUNCTION f_has_role (
        p_role_name IN t_app_roles.role_name%TYPE
    ) RETURN BOOLEAN;

    /*
    ---------------------------------------------------------------------------
    SCOPE-Check if current user has any of the specified roles
    ---------------------------------------------------------------------------
    p_role_names: Comma-separated list, e.g., 'ADMIN,MANAGER,HR'
    ---------------------------------------------------------------------------
    */
    FUNCTION f_has_any_role (
        p_role_names IN VARCHAR2
    ) RETURN BOOLEAN;

    /*
    ---------------------------------------------------------------------------
    SCOPE- Get current user's account ID
    ---------------------------------------------------------------------------
    */
    FUNCTION f_current_account_id RETURN t_account_id;

    ---------------------------------------------------------------------------
    -- ADMINISTRATIVE PROCEDURES
    ---------------------------------------------------------------------------

    /*
    ---------------------------------------------------------------------------
    SCOPE-Create or update a permission grant
    ---------------------------------------------------------------------------
    */
    PROCEDURE grant_permission (
        p_app_id          IN t_app_id,
        p_component_type  IN t_component_type,
        p_component_key   IN t_component_key,
        p_page_id         IN t_page_id,
        p_role_id         IN t_role_id,
        p_permission      IN t_permission,
        p_effective_from  IN DATE DEFAULT TRUNC(SYSDATE),
        p_effective_to    IN DATE DEFAULT NULL
    );
		/*
    ---------------------------------------------------------------------------
    SCOPE-Adds a new role
    ---------------------------------------------------------------------------
    */
    PROCEDURE add_role(p_role_name IN t_app_roles.role_name%TYPE,
			                     p_remarks   IN t_app_roles.remarks%TYPE );
    /*
    ---------------------------------------------------------------------------
    SCOPE-Remove a permission grant
    ---------------------------------------------------------------------------
    */
    PROCEDURE revoke_permission (
        p_perm_id IN t_auth_component_perms.perm_id%TYPE
    );

    /*
    ---------------------------------------------------------------------------
    SCOPE-Reset cached session data
    ---------------------------------------------------------------------------
    */
    PROCEDURE clear_session_cache;

    ---------------------------------------------------------------------------
    -- DEBUG PROCEDURES
    ---------------------------------------------------------------------------
    PROCEDURE debug_mode_on;
    PROCEDURE debug_mode_off;
    FUNCTION is_debug_mode RETURN BOOLEAN;
    ---------------------------------------------------------------------------
		-- TEST MODE PROCEDURES (for SQL Workshop testing)
		---------------------------------------------------------------------------
		PROCEDURE set_test_user(p_account_id IN t_account_id);
		PROCEDURE clear_test_user;
		FUNCTION  f_test_user RETURN t_account_id;
END apex_auth_api;
/
CREATE OR REPLACE PACKAGE BODY apex_auth_api AS

    ---------------------------------------------------------------------------
    -- PRIVATE CONSTANTS
    ---------------------------------------------------------------------------
    gc_row_separator CONSTANT VARCHAR2(2)  := CHR(3) || CHR(10);
    gc_scope_prefix  CONSTANT VARCHAR2(35) := LOWER($$plsql_unit) || '.';
    -- TEST MODE variables
		gv_test_account_id t_account_id := NULL;
		gv_test_mode       BOOLEAN      := FALSE;
    ---------------------------------------------------------------------------
    -- PRIVATE PACKAGE STATE (Session-level caching)
    ---------------------------------------------------------------------------
    gv_cached_account_id   t_account_id;
    gv_cached_app_user     t_username;
		gv_roles_cache_key     t_vc2_short;
    gv_cache_initialized   BOOLEAN := FALSE;
    gv_debug_mode          BOOLEAN := FALSE;
    
    -- Cache for user's roles (refreshed per session)
    gv_user_roles          t_role_id_tab;
    gv_roles_loaded        BOOLEAN := FALSE;
    
    ---------------------------------------------------------------------------
    -- PRIVATE TYPE: Pattern map for component type resolution
    -- (Cannot be initialized in spec, so defined and initialized here)
    ---------------------------------------------------------------------------
    TYPE t_pattern_map IS TABLE OF t_component_type INDEX BY VARCHAR2(255);
    gv_type_map t_pattern_map;
    gv_type_map_initialized BOOLEAN := FALSE;
    
    ---------------------------------------------------------------------------
    -- PRIVATE: Initialize the component type pattern map
    ---------------------------------------------------------------------------
    PROCEDURE init_type_map IS
    BEGIN
        IF NOT gv_type_map_initialized THEN
            -- Direct APEX view name mappings (exact match)
            gv_type_map(c_apex_pages)        := c_type_page;
            gv_type_map(c_apex_regions)      := c_type_region;
            gv_type_map(c_apex_items)        := c_type_item;
            gv_type_map(c_apex_buttons)      := c_type_button;
            gv_type_map(c_apex_processes)    := c_type_process;
            gv_type_map(c_apex_list_entries) := c_type_list_entry;
            gv_type_map(c_apex_navbar)       := c_type_nav_bar;
            gv_type_map(c_apex_tabs)         := c_type_tab;
            
            -- Internal type names (identity mapping for direct calls)
            gv_type_map(c_type_application)  := c_type_application;
            gv_type_map(c_type_page)         := c_type_page;
            gv_type_map(c_type_region)       := c_type_region;
            gv_type_map(c_type_item)         := c_type_item;
            gv_type_map(c_type_button)       := c_type_button;
            gv_type_map(c_type_process)      := c_type_process;
            gv_type_map(c_type_list_entry)   := c_type_list_entry;
            gv_type_map(c_type_nav_bar)      := c_type_nav_bar;
            gv_type_map(c_type_tab)          := c_type_tab;
            gv_type_map(c_type_menu)         := c_type_menu;
            gv_type_map_initialized := TRUE;
        END IF;
    END init_type_map;

    ---------------------------------------------------------------------------
    -- DEBUG MODE PROCEDURES
    ---------------------------------------------------------------------------
    PROCEDURE debug_mode_on AS
    BEGIN
        gv_debug_mode := TRUE;
        debug_pkg.debug_on;
    END debug_mode_on;

    PROCEDURE debug_mode_off AS
    BEGIN
        gv_debug_mode := FALSE;
        debug_pkg.debug_off;
    END debug_mode_off;

    FUNCTION is_debug_mode RETURN BOOLEAN IS
    BEGIN
        RETURN gv_debug_mode;
    END is_debug_mode;
    
    ---------------------------------------------------------------------------
    -- PRIVATE: Logging Procedures
    ---------------------------------------------------------------------------
		---------------------------------------------------------------------------
    -- PRIVATE: Map APEX type to internal type
    ---------------------------------------------------------------------------
    FUNCTION map_apex_type_to_internal(
        p_apex_type IN VARCHAR2
    ) RETURN t_component_type IS
        lv_upper VARCHAR2(50);
    BEGIN
        IF p_apex_type IS NULL THEN
            RETURN NULL;
        END IF;
        
        init_type_map;
        lv_upper := UPPER(p_apex_type);
        
        -- Direct lookup first
        IF gv_type_map.EXISTS(lv_upper) THEN
            RETURN gv_type_map(lv_upper);
        END IF;
        
        -- Pattern-based fallback for edge cases
        IF lv_upper LIKE '%LIST%ENTR%' OR lv_upper LIKE '%NAV%MENU%' THEN
            RETURN c_type_list_entry;
        ELSIF lv_upper LIKE '%PAGE%' AND lv_upper NOT LIKE '%REGION%' 
              AND lv_upper NOT LIKE '%ITEM%' AND lv_upper NOT LIKE '%BUTTON%' THEN
            RETURN c_type_page;
        ELSIF lv_upper LIKE '%REGION%' THEN
            RETURN c_type_region;
        ELSIF lv_upper LIKE '%ITEM%' THEN
            RETURN c_type_item;
        ELSIF lv_upper LIKE '%BUTTON%' THEN
            RETURN c_type_button;
        ELSIF lv_upper LIKE '%PROC%' THEN
            RETURN c_type_process;
        ELSIF lv_upper LIKE '%NAV%BAR%' THEN
            RETURN c_type_nav_bar;
        ELSIF lv_upper LIKE '%TAB%' THEN
            RETURN c_type_tab;
        END IF;
        
        -- Unknown type - return as-is (let caller handle)
        RETURN p_apex_type;
    END map_apex_type_to_internal;
		
    PROCEDURE log_error (
        p_message   IN t_error_msg,
        p_scope     IN t_scope DEFAULT gc_scope_prefix
    ) IS
    BEGIN
        BEGIN
            IF is_debug_mode THEN
                debug_pkg.printf('%1 error_info: %2', p_scope, p_message);
            END IF;
            logger.log_error(p_text => p_message, p_scope => p_scope);
        EXCEPTION
            WHEN OTHERS THEN
                BEGIN
                    APEX_DEBUG.ERROR(p_message => p_scope || ': ' || p_message);
                EXCEPTION
                    WHEN OTHERS THEN NULL;
                END;
        END;
    EXCEPTION
        WHEN OTHERS THEN NULL;  
    END log_error;

    PROCEDURE log_info (
        p_message   IN t_error_msg,
        p_scope     IN t_scope DEFAULT gc_scope_prefix
    ) IS
    BEGIN
        BEGIN
            IF is_debug_mode THEN
                debug_pkg.printf('%1 run_info: %2', p_scope, p_message);
            END IF;
            logger.log_info(p_text => p_message, p_scope => p_scope);
        EXCEPTION
            WHEN OTHERS THEN
                BEGIN
                    APEX_DEBUG.INFO(p_message => p_scope || ': ' || p_message);
                EXCEPTION
                    WHEN OTHERS THEN NULL;
                END;
        END;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END log_info;
   
    ---------------------------------------------------------------------------
    -- PRIVATE: Helper Functions
    ---------------------------------------------------------------------------
    /*
    ---------------------------------------------------------------------------
    SCOPE- Load current user's roles into package cache
    ---------------------------------------------------------------------------
    */
    PROCEDURE load_user_roles (
        p_account_id IN t_account_id
    ) IS
        lv_scope t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));

        PROCEDURE init_empty IS
        BEGIN
            gv_user_roles := t_role_id_tab();
            gv_roles_loaded := TRUE;
						gv_roles_cache_key := NULL;
        END init_empty;

    BEGIN
        IF p_account_id IS NULL THEN
            init_empty;
            RETURN;
        END IF;

        SELECT t.role_id
          BULK COLLECT INTO gv_user_roles
          FROM t_app_user_roles t
         WHERE t.account_id = p_account_id;

        gv_roles_loaded := TRUE;
				gv_roles_cache_key := p_account_id;
        log_info('Loaded ' || gv_user_roles.COUNT || ' roles for ' || p_account_id, lv_scope);
				
    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM ||
                             ' for account=' || p_account_id,
                p_scope   => lv_scope
            );
            init_empty;
    END load_user_roles;
		------
		---TEST FUNCTIONALITY (PUBLIC)
		-------
    PROCEDURE set_test_user(p_Account_id IN t_account_id) IS
       lv_scope          t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
      BEGIN
        gv_test_account_id := UPPER(p_account_id);
        gv_test_mode := TRUE;
        --clear cache so it reloads with test values
        clear_session_cache;
        load_user_roles(gv_test_account_id);

        gv_cached_account_id := gv_test_account_id;
        gv_cache_initialized := TRUE;
        log_info('Test mode enabled for user: ' || p_account_id, lv_scope);
    END set_test_user; 
    
    PROCEDURE clear_test_user IS
    BEGIN
        gv_test_account_id := NULL;
        gv_test_mode := FALSE;
        clear_session_cache;
        log_info('Test mode disabled', gc_scope_prefix || 'clear_test_user');
    END clear_test_user;

    FUNCTION f_test_user RETURN t_account_id IS
    BEGIN
        RETURN gv_test_account_id;
    END f_test_user;
		------
    /*
    ---------------------------------------------------------------------------
    SCOPE - Convert permission code to numeric weight
    ---------------------------------------------------------------------------
    Note: This function fetches from app_codes_def via the API.
    Since we need to use this in SQL, we'll compute weights before the query.
    ---------------------------------------------------------------------------
    */
    FUNCTION f_permission_weight (
        p_permission IN t_permission
    ) RETURN PLS_INTEGER
    IS
        lv_ret PLS_INTEGER := -1;
    BEGIN
        -- Permission weight mapping:
        --   ADMIN=3 > EDIT=2 > VIEW=1 > DENY=0
        -- Higher weight implies all lower permissions (ADMIN can EDIT and VIEW)
        lv_ret := CASE UPPER(p_permission)
            WHEN c_perm_admin THEN 3
            WHEN c_perm_edit  THEN 2
            WHEN c_perm_view  THEN 1
            WHEN c_perm_deny  THEN 0
            ELSE -1
        END;
        RETURN lv_ret;
    END f_permission_weight;
		
		---------------------------------------------------------------------------
    -- PRIVATE: Resolve list entry key from APEX component ID
    ---------------------------------------------------------------------------
    FUNCTION resolve_list_entry_key (
        p_app_id       IN t_app_id,
        p_component_id IN NUMBER,
        p_comp_name    IN VARCHAR2
    ) RETURN t_component_key IS
        lv_scope t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_key   t_component_key;
    BEGIN
        -- First try: use APP_COMPONENT_ID (list_entry_id) - most reliable
        IF p_component_id IS NOT NULL THEN
            BEGIN
                SELECT COALESCE(entry_attribute_01, REPLACE(entry_text, ' ', '_'))
                  INTO lv_key
                  FROM apex_application_list_entries
                 WHERE application_id = p_app_id  
                   AND list_entry_id  = p_component_id
                   AND ROWNUM = 1;
                
                log_info('Resolved list_entry_id=' || p_component_id || ' to key=' || lv_key, lv_scope);
                RETURN lv_key;
            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    log_info('No entry found for list_entry_id=' || p_component_id, lv_scope);
            END;
        END IF;
        
        -- Second try: match by entry_text (APP_COMPONENT_NAME)
        IF p_comp_name IS NOT NULL THEN
            BEGIN
                SELECT COALESCE(entry_attribute_01, REPLACE(entry_text, ' ', '_'))
                  INTO lv_key
                  FROM apex_application_list_entries
                 WHERE application_id = p_app_id
                   AND (entry_text = p_comp_name 
                        OR entry_attribute_01 = p_comp_name
                        OR REPLACE(entry_text, ' ', '_') = p_comp_name)
                   AND ROWNUM = 1;
                
                log_info('Resolved entry_text=' || p_comp_name || ' to key=' || lv_key, lv_scope);
                RETURN lv_key;
            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    log_info('No entry found for name=' || p_comp_name, lv_scope);
            END;
        END IF;
        
        -- Fallback: return original name with spaces replaced
        lv_key := REPLACE(p_comp_name, ' ', '_');
        log_info('Fallback key=' || lv_key, lv_scope);
        RETURN lv_key;
        
    EXCEPTION
        WHEN OTHERS THEN
            log_error('Failed: ' || SQLERRM || ' app=' || p_app_id || ' id=' || p_component_id, lv_scope);
            RETURN REPLACE(p_comp_name, ' ', '_');
    END resolve_list_entry_key;

    /*
    ---------------------------------------------------------------------------
    SCOPE- Resolve APEX bind variables to component info
    ---------------------------------------------------------------------------
    Bind variables are set when the authorization scheme is called from APEX.
    This resolves them to component_type and component_key.
    ---------------------------------------------------------------------------
    */
    PROCEDURE resolve_component_info (
			  p_app_id          IN     t_app_id,
        p_page_id         IN OUT t_page_id,
        p_component_type  IN OUT t_component_type,
        p_component_key   IN OUT t_component_key,
				p_component_id    IN     NUMBER DEFAULT NULL
    ) IS
        lv_scope          t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_apex_comp_type t_vc2_short;
        lv_apex_comp_name t_vc2_short;
				lv_apex_comp_id   NUMBER;
        lv_pattern        t_vc2_short;
    BEGIN
			   
        lv_apex_comp_type := COALESCE(p_component_type,V('APP_COMPONENT_TYPE'));
				lv_apex_comp_name := COALESCE(p_component_key,V('APP_COMPONENT_NAME'));  
        lv_apex_comp_id := TO_NUMBER(COALESCE(p_component_id,V('APP_COMPONENT_ID')));
      
		    log_info('APEX binds: TYPE=' || lv_apex_comp_type || 
                 ' NAME=' || lv_apex_comp_name || 
                 ' ID=' || lv_apex_comp_id ||
                 ' PAGE_ID=' || p_page_id, lv_scope);
				
				 -- Resolve component type
        IF p_component_type IS NULL THEN
            IF lv_apex_comp_type IS NOT NULL THEN
                p_component_type := map_apex_type_to_internal(lv_apex_comp_type);
            ELSE
                -- No component type means page-level authorization
                p_component_type := c_type_page;
            END IF;
        ELSE  
					-- Normalize passed-in type
            p_component_type := map_apex_type_to_internal(p_component_type);
        END IF;
					log_info('Internal type resolved to: ' || p_component_type, lv_scope);

				 -- Resolve component key based on type
   
            CASE p_component_type
                WHEN c_type_page THEN
                    -- Page key is the page_id
                    p_component_key := TO_CHAR(p_page_id);
                    
                WHEN c_type_list_entry THEN
                    -- List entries need special resolution
                    p_component_key := resolve_list_entry_key(
                        p_app_id       => p_app_id,
                        p_component_id => lv_apex_comp_id,
                        p_comp_name    => lv_apex_comp_name
                    );
                    -- List entries have no page context
                    p_page_id := NULL;
                    
                WHEN c_type_region THEN
                    -- Regions: use static_id or region name
                    IF lv_apex_comp_id IS NOT NULL THEN
                        BEGIN
                            SELECT COALESCE(static_id, region_name)
                              INTO p_component_key
                              FROM apex_application_page_regions
                             WHERE application_id = p_app_id
                               AND page_id        = p_page_id
                               AND region_id      = lv_apex_comp_id
                               AND ROWNUM = 1;
                        EXCEPTION
                            WHEN NO_DATA_FOUND THEN
                                p_component_key := lv_apex_comp_name;
                        END;
                    ELSE
                        p_component_key := lv_apex_comp_name;
                    END IF;
                    
                WHEN c_type_button THEN
                    -- Buttons: use button_static_id or button_name
                    IF lv_apex_comp_id IS NOT NULL THEN
                        BEGIN
                            SELECT COALESCE(button_static_id, button_name)
                              INTO p_component_key
                              FROM apex_application_page_buttons
                             WHERE application_id = p_app_id
                               AND page_id        = p_page_id
                               AND button_id      = lv_apex_comp_id
                               AND ROWNUM = 1;
                        EXCEPTION
                            WHEN NO_DATA_FOUND THEN
                                p_component_key := lv_apex_comp_name;
                        END;
                    ELSE
                        p_component_key := lv_apex_comp_name;
                    END IF;
                    
                ELSE
                    -- Items, processes, etc: use the component name directly
                    p_component_key := lv_apex_comp_name;
            END CASE;
        
        log_info('Final: type=' || p_component_type || ' key=' || p_component_key || ' page=' || p_page_id, lv_scope);
        
    EXCEPTION
        WHEN OTHERS THEN
            log_error('Failed: ' || SQLERRM, lv_scope);
            -- Safe fallback
            IF p_component_type IS NULL THEN
                p_component_type := c_type_page;
            END IF;
            IF p_component_key IS NULL AND p_page_id IS NOT NULL THEN
                p_component_key := TO_CHAR(p_page_id);
            END IF;
		END resolve_component_info;

    /*
    ---------------------------------------------------------------------------
    SCOPE - Find parent region key for a component
    ---------------------------------------------------------------------------
    For items, buttons, processes that belong to a region, find the parent.
    Uses V_APEX_COMPONENTS view.
    ---------------------------------------------------------------------------
    */
    FUNCTION f_parent_region_key (
        p_app_id          IN t_app_id,
        p_page_id         IN t_page_id,
        p_component_type  IN t_component_type,
        p_component_key   IN t_component_key
    ) RETURN t_component_key
    IS
        lv_scope      t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_parent_key t_component_key;
    BEGIN
        -- Only look for region parent for leaf components
        IF p_component_type NOT IN (
            c_type_item,
            c_type_button,
            c_type_process
        )  OR p_page_id IS NULL THEN
            RETURN NULL;
        END IF;

        -- Query V_APEX_COMPONENTS for the parent
        SELECT COALESCE(c.static_id, c.component_name)
          INTO lv_parent_key
          FROM v_apex_components c
         WHERE c.app_id = p_app_id
           AND c.page_id = p_page_id
           AND c.component_type = c_type_region
           AND c.component_id = (
               -- Find this component's parent_component_id
               SELECT parent_component_id
                 FROM v_apex_components
                WHERE app_id = p_app_id
                  AND page_id = p_page_id
                  AND component_type = p_component_type
                  AND (component_name = p_component_key
                       OR static_id = p_component_key)
                  AND parent_type = c_type_region
                  AND ROWNUM = 1
           )
           AND ROWNUM = 1;

        RETURN lv_parent_key;

    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN NULL;
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM ||
                             ' for app=' || p_app_id ||
                             ' page=' || p_page_id ||
                             ' type=' || p_component_type ||
                             ' key=' || p_component_key,
                p_scope   => lv_scope
            );
            RETURN NULL;
    END f_parent_region_key;
		
	/*
		---------------------------------------------------------------------------
		SCOPE - Find parent list entry key for nested entries
		---------------------------------------------------------------------------
		*/		
    FUNCTION f_parent_list_entry_key (
			p_app_id        IN t_app_id,
			p_component_key IN t_component_key
		) RETURN t_component_key
		IS
			lv_scope      t_vc2_small := gc_scope_prefix || LOWER(utl_call_stack.subprogram(1)(2));
			lv_parent_key t_component_key;
		BEGIN
			IF p_component_key IS NULL THEN
					RETURN NULL;
			END IF;

			-- Find parent list entry
			SELECT COALESCE(parent_le.entry_attribute_01, REPLACE(parent_le.entry_text, ' ', '_'))
				INTO lv_parent_key
				FROM apex_application_list_entries child_le
				JOIN apex_application_list_entries parent_le 
					ON parent_le.list_entry_id = child_le.list_entry_parent_id
				 AND parent_le.application_id = child_le.application_id
			 WHERE child_le.application_id = p_app_id
				 AND child_le.list_entry_parent_id IS NOT NULL  -- Has a parent
				 AND (
						 child_le.entry_attribute_01 = p_component_key 
						 OR REPLACE(child_le.entry_text, ' ', '_') = p_component_key
				 )
				 AND ROWNUM = 1;

			RETURN lv_parent_key;

		EXCEPTION
			WHEN NO_DATA_FOUND THEN
					RETURN NULL;  -- No parent (top-level entry)
			WHEN OTHERS THEN
					log_error(
							p_message => 'Failed: ' || SQLERRM ||
													 ' app=' || p_app_id ||
													 ' key=' || p_component_key,
							p_scope   => lv_scope
					);
					RETURN NULL;

    END f_parent_list_entry_key;
    ---------------------------------------------------------------------------
    -- PUBLIC: Session Functions
    ---------------------------------------------------------------------------

    FUNCTION f_current_account_id
    RETURN t_account_id
    IS
        lv_scope    t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_app_user t_username;
    BEGIN
			  -- TEST MODE: Return test user if set
				IF gv_test_mode AND gv_test_account_id IS NOT NULL THEN
						RETURN gv_test_account_id;
				END IF;
        -- Get current APP_USER from various sources
        lv_app_user := COALESCE(
				    apex_application.g_user,
            V('APP_USER'),
            SYS_CONTEXT('APEX$SESSION', 'APP_USER'),
            SYS_CONTEXT('USERENV', 'SESSION_USER')
        );

        -- Return cached value if still valid
        IF gv_cache_initialized
           AND gv_cached_app_user = lv_app_user
           AND gv_cached_account_id IS NOT NULL
        THEN
            RETURN gv_cached_account_id;
        END IF;

        -- Fetch account_id from database
        BEGIN
            SELECT t.account_id
              INTO gv_cached_account_id
              FROM t_app_user_accounts t
             WHERE t.account_id = UPPER(lv_app_user)
               AND NVL(t.is_active, 'Y') = c_yes
               AND ROWNUM = 1;

            gv_cached_app_user   := lv_app_user;
            gv_cache_initialized := TRUE;

            -- Also load roles
            load_user_roles(gv_cached_account_id);
            log_info('Account resolved: ' || gv_cached_account_id, lv_scope);
            RETURN gv_cached_account_id;

        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                log_info(
                    p_message => 'User not found or inactive: ' || lv_app_user,
                    p_scope   => lv_scope
                );
                gv_cached_account_id := NULL;
                gv_cached_app_user   := lv_app_user;
                gv_cache_initialized := TRUE;
                gv_user_roles   := t_role_id_tab();
                gv_roles_loaded := TRUE;
                RETURN NULL;
        END;

    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM,
                p_scope   => lv_scope
            );
            RETURN NULL;
    END f_current_account_id;

    PROCEDURE clear_session_cache
    IS
        lv_scope t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
    BEGIN
        gv_cached_account_id := NULL;
        gv_cached_app_user   := NULL;
        gv_cache_initialized := FALSE;
        gv_user_roles   := t_role_id_tab();
        gv_roles_loaded := FALSE;

        log_info(
            p_message => 'Session cache cleared',
            p_scope   => lv_scope
        );
    END clear_session_cache;

    ---------------------------------------------------------------------------
    -- PUBLIC: Role Check Functions
    ---------------------------------------------------------------------------

    FUNCTION f_has_role (
        p_role_name IN t_app_roles.role_name%TYPE
    ) RETURN BOOLEAN
    IS
        lv_scope      t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_account_id t_account_id;
        lv_count      PLS_INTEGER;
    BEGIN
        lv_account_id := f_current_account_id();  
        IF lv_account_id IS NULL THEN
            RETURN FALSE;
        END IF;

        SELECT COUNT(*)
          INTO lv_count
          FROM t_app_user_roles ur
          JOIN t_app_roles r ON r.role_id = ur.role_id
         WHERE ur.account_id = lv_account_id
           AND UPPER(r.role_name) = UPPER(p_role_name)
           AND ROWNUM = 1;

        RETURN (lv_count > 0);

    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM || ' role=' || p_role_name,
                p_scope   => lv_scope
            );
            RETURN FALSE;
    END f_has_role;

    FUNCTION f_has_any_role (
        p_role_names IN VARCHAR2
    ) RETURN BOOLEAN
    IS
        lv_scope      t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_account_id t_account_id;
        lv_count      PLS_INTEGER;
    BEGIN
        lv_account_id := f_current_account_id();   
        IF lv_account_id IS NULL THEN
            RETURN FALSE;
        END IF;

        -- Parse comma-separated list and check for any match
        SELECT COUNT(*)
          INTO lv_count
          FROM t_app_user_roles ur
          JOIN t_app_roles r ON r.role_id = ur.role_id
         WHERE ur.account_id = lv_account_id
           AND UPPER(r.role_name) IN (
               SELECT UPPER(TRIM(REGEXP_SUBSTR(p_role_names, '[^,]+', 1, LEVEL)))
                 FROM DUAL
               CONNECT BY LEVEL <= REGEXP_COUNT(p_role_names, ',') + 1
           )
           AND ROWNUM = 1;

        RETURN (lv_count > 0);

    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM || ' roles=' || p_role_names,
                p_scope   => lv_scope
            );
            RETURN FALSE;
    END f_has_any_role;

    ---------------------------------------------------------------------------
    -- PUBLIC: Permission Functions
    ---------------------------------------------------------------------------

    FUNCTION f_effective_permission (
        p_app_id          IN t_app_id,
        p_page_id         IN t_page_id,
        p_component_type  IN t_component_type,
        p_component_key   IN t_component_key,
				p_component_id    IN t_component_id,
        p_account_id      IN t_account_id DEFAULT NULL
    ) RETURN t_permission
    IS
        lv_scope          t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_account_id     t_account_id;
        lv_permission     t_permission;
        lv_today          DATE := SYSDATE;
        lv_parent_key     t_component_key;
        lv_comp_type      t_component_type := p_component_type;
        lv_comp_key       t_component_key  := p_component_key;
				lv_comp_id        t_component_id   := p_component_id;
        lv_page_id        t_page_id := p_page_id;
				lv_app_id         t_app_id  := COALESCE(p_app_id,NV('APP_ID'));
        
        -- Pre-computed weights for use in SQL (avoids PLS-00231)
        lv_weight_admin   PLS_INTEGER;
        lv_weight_edit    PLS_INTEGER;
        lv_weight_view    PLS_INTEGER;
        lv_weight_deny    PLS_INTEGER;
    BEGIN
			  IF lv_app_id IS NULL THEN
           log_error('Cannot determine APP_ID', lv_scope);
           RETURN NULL;
        END IF;
        -- Resolve account
        lv_account_id := COALESCE(p_account_id, f_current_account_id());
        IF lv_account_id IS NULL THEN
					  log_info('No account resolved', lv_scope);
            RETURN NULL;
        END IF;

        -- Ensure roles are loaded
        IF NOT gv_roles_loaded THEN
            load_user_roles(lv_account_id);
        END IF;

        -- No roles = no permissions
        IF gv_user_roles IS NULL OR gv_user_roles.COUNT = 0 THEN
					  log_info('No roles for account=' || lv_account_id, lv_scope);
            RETURN NULL;
        END IF;

        -- Resolve component info
        resolve_component_info(lv_app_id, lv_page_id, lv_comp_type, lv_comp_key, lv_comp_id);
        
        -- Get parent region for leaf components
        IF lv_comp_type IN (c_type_item, c_type_button, c_type_process) THEN
           lv_parent_key := f_parent_region_key(
                lv_app_id, lv_page_id, lv_comp_type, lv_comp_key
            );
				ELSIF lv_comp_type = c_type_list_entry THEN
					lv_parent_key := f_parent_list_entry_key(lv_app_id, lv_comp_key);
        END IF;
         log_info('Checking permission: app=' || lv_app_id || 
                 ' page=' || lv_page_id ||
                 ' type=' || lv_comp_type || 
                 ' key=' || lv_comp_key ||
								 ' parentKey=' || lv_parent_key ||
								 ' id='  || lv_comp_id ||
                 ' account=' || lv_account_id, lv_scope);
        -- Pre-compute permission weights to avoid calling function in SQL
        lv_weight_admin := f_permission_weight(c_perm_admin);
        lv_weight_edit  := f_permission_weight(c_perm_edit);
        lv_weight_view  := f_permission_weight(c_perm_view);
        lv_weight_deny  := f_permission_weight(c_perm_deny);

        /*
        =====================================================================
        HIERARCHY PERMISSION QUERY
        =====================================================================
        Checks permissions at 4 levels (component -> region -> page -> app):

        1. DENY at ANY level = immediate denial (ORDER BY is_deny DESC)
        2. Most specific non-DENY permission wins (ORDER BY hier_level ASC)
        3. Highest permission at that level wins (ORDER BY perm_weight DESC)
        =====================================================================
        */
        BEGIN
            WITH perm_hierarchy AS (
                -- Level 1: Specific component permission
                SELECT
                    1 AS hier_level,
                    p.permission_code,
                    CASE WHEN p.permission_code = c_perm_deny
                         THEN 1 ELSE 0
                    END AS is_deny,
                    CASE p.permission_code
                        WHEN c_perm_admin THEN lv_weight_admin
                        WHEN c_perm_edit  THEN lv_weight_edit
                        WHEN c_perm_view  THEN lv_weight_view
                        WHEN c_perm_deny  THEN lv_weight_deny
                        ELSE -1
                    END AS perm_weight
                FROM t_auth_component_perms p
                WHERE p.app_id         = lv_app_id
                  AND p.component_type = lv_comp_type
                  AND p.component_key  = lv_comp_key
                  AND ((p.page_id = lv_page_id) OR (p.page_id IS NULL OR lv_page_id IS NULL))
                  AND p.role_id  IN (SELECT ur.role_id FROM t_app_user_roles ur WHERE ur.account_id = lv_account_id)
                  AND lv_today BETWEEN p.effective_from
                                   AND NVL(p.effective_to, c_end_of_time)

                UNION ALL

               -- Level 2a: Parent REGION permission (for ITEM/BUTTON/PROCESS only)
            SELECT 2 AS hier_level, p.permission_code,
                CASE WHEN p.permission_code = c_perm_deny THEN 1 ELSE 0 END AS is_deny,
                CASE p.permission_code
                    WHEN c_perm_admin THEN lv_weight_admin
                    WHEN c_perm_edit  THEN lv_weight_edit
                    WHEN c_perm_view  THEN lv_weight_view
                    WHEN c_perm_deny  THEN lv_weight_deny
                    ELSE -1
                END AS perm_weight
            FROM t_auth_component_perms p
            WHERE p.app_id         = lv_app_id
              AND p.component_type = c_type_region
              AND p.component_key  = lv_parent_key
              AND lv_parent_key IS NOT NULL
              AND lv_comp_type IN (c_type_item, c_type_button, c_type_process)
              AND (p.page_id = lv_page_id OR p.page_id IS NULL)
              AND p.role_id IN (SELECT ur.role_id FROM t_app_user_roles ur WHERE ur.account_id = lv_account_id)
              AND lv_today BETWEEN p.effective_from AND NVL(p.effective_to, c_end_of_time)

            UNION ALL

            -- Level 2b: Parent LIST_ENTRY permission (for nested list entries only)
            SELECT 2 AS hier_level, p.permission_code,
                CASE WHEN p.permission_code = c_perm_deny THEN 1 ELSE 0 END AS is_deny,
                CASE p.permission_code
                    WHEN c_perm_admin THEN lv_weight_admin
                    WHEN c_perm_edit  THEN lv_weight_edit
                    WHEN c_perm_view  THEN lv_weight_view
                    WHEN c_perm_deny  THEN lv_weight_deny
                    ELSE -1
                END AS perm_weight
            FROM t_auth_component_perms p
            WHERE p.app_id         = lv_app_id
              AND p.component_type = c_type_list_entry
              AND p.component_key  = lv_comp_key 
              AND (p.parent_key = lv_parent_key OR lv_parent_key IS NULL)
              AND lv_comp_type = c_type_list_entry
              AND p.page_id IS NULL
              AND p.role_id IN (SELECT ur.role_id FROM t_app_user_roles ur WHERE ur.account_id = lv_account_id)
              AND lv_today BETWEEN p.effective_from AND NVL(p.effective_to, c_end_of_time)

            UNION ALL

            -- Level 3: PAGE level permission (skip for LIST_ENTRY - they have no page)
            SELECT 3 AS hier_level, p.permission_code,
                CASE WHEN p.permission_code = c_perm_deny THEN 1 ELSE 0 END AS is_deny,
                CASE p.permission_code
                    WHEN c_perm_admin THEN lv_weight_admin
                    WHEN c_perm_edit  THEN lv_weight_edit
                    WHEN c_perm_view  THEN lv_weight_view
                    WHEN c_perm_deny  THEN lv_weight_deny
                    ELSE -1
                END AS perm_weight
            FROM t_auth_component_perms p
            WHERE p.app_id         = lv_app_id
              AND p.component_type = c_type_page
              AND p.component_key  = TO_CHAR(lv_page_id)
              AND lv_page_id IS NOT NULL
              AND lv_comp_type NOT IN (c_type_list_entry, c_type_application) -- Skip page check for list entries
              AND p.role_id IN (SELECT ur.role_id FROM t_app_user_roles ur WHERE ur.account_id = lv_account_id)
              AND lv_today BETWEEN p.effective_from AND NVL(p.effective_to, c_end_of_time)

            UNION ALL

            -- Level 4: APPLICATION level permission
            SELECT 4 AS hier_level, p.permission_code,
                CASE WHEN p.permission_code = c_perm_deny THEN 1 ELSE 0 END AS is_deny,
                CASE p.permission_code
                    WHEN c_perm_admin THEN lv_weight_admin
                    WHEN c_perm_edit  THEN lv_weight_edit
                    WHEN c_perm_view  THEN lv_weight_view
                    WHEN c_perm_deny  THEN lv_weight_deny
                    ELSE -1
                END AS perm_weight
            FROM t_auth_component_perms p
            WHERE p.app_id         = lv_app_id
              AND p.component_type = c_type_application
              AND p.component_key IS NULL
              AND p.role_id IN (SELECT ur.role_id FROM t_app_user_roles ur WHERE ur.account_id = lv_account_id)
              AND lv_today BETWEEN p.effective_from AND NVL(p.effective_to, c_end_of_time)
            )
            SELECT permission_code
              INTO lv_permission
              FROM perm_hierarchy		 
             ORDER BY hier_level ASC,    -- Most specific level first
						          perm_weight DESC,    -- Highest permission at that level
						          is_deny DESC    -- DENY always wins      
             FETCH FIRST 1 ROW ONLY;
						 
             log_info('Permission found: ' || lv_permission, lv_scope);
            RETURN lv_permission;

        EXCEPTION
            WHEN NO_DATA_FOUND THEN
							  log_info('No permission found', lv_scope);
                RETURN NULL;  -- No permissions found
        END;

    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM ||
                             ' app=' || p_app_id ||
                             ' page=' || p_page_id ||
                             ' type=' || p_component_type ||
                             ' key=' || p_component_key,
                p_scope   => lv_scope
            );
            RETURN NULL;
    END f_effective_permission;

    ---------------------------------------------------------------------------
    -- PUBLIC: Authorization Functions
    ---------------------------------------------------------------------------

    FUNCTION f_authorized (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL,
				p_component_id    IN NUMBER           DEFAULT NULL,
        p_required_perm   IN t_permission     DEFAULT c_perm_view
    ) RETURN BOOLEAN
    IS
        lv_scope          t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_effective_perm t_permission;
        lv_required_weight PLS_INTEGER;
        lv_actual_weight   PLS_INTEGER; 
    BEGIN
		   -- clear_session_cache;
        log_info('f_authorized called: app=' || TO_CHAR(p_app_id) || 
                 ' page=' || COALESCE(TO_CHAR(p_page_id), 'session_val:'||TO_CHAR(sys_context('APEX$SESSION','APP_PAGE_ID')), 'page_id')  ||
                 ' type=' || COALESCE(p_component_type,'session_val:' || TO_CHAR(sys_context('APEX$SESSION','APP_COMPONENT_TYPE')),'type') ||
                 ' key=' || COALESCE(p_component_key,'session_val:'||TO_CHAR(sys_context('APEX$SESSION','APP_COMPONENT_NAME')),'key') ||
								 ' id= ' || COALESCE(p_component_id,'session_val:'||TO_CHAR(sys_context('APEX$SESSION','APP_COMPONENT_ID')),'id') ||
                 ' req_perm=' || p_required_perm, lv_scope);
        -- Validate required permission
        lv_required_weight := f_permission_weight(p_required_perm);
        IF lv_required_weight < 0 THEN
            log_error(
                p_message => 'Invalid required permission: ' || p_required_perm,
                p_scope   => lv_scope
            );
            RETURN c_default_on_error;
        END IF;

        -- Get effective permission
        lv_effective_perm := f_effective_permission(
            p_app_id         => p_app_id,
            p_page_id        => p_page_id,
            p_component_type => p_component_type,
            p_component_key  => p_component_key,
						p_component_id   => p_component_id
        );

        -- Evaluate result
        IF lv_effective_perm IS NULL THEN
            log_info('Result: DENIED (no permission)', lv_scope);
            RETURN FALSE;
        ELSIF lv_effective_perm = c_perm_deny THEN
            log_info('Result: DENIED (explicit DENY)', lv_scope);
            RETURN FALSE;
        ELSE
            lv_actual_weight := f_permission_weight(lv_effective_perm);
            IF lv_actual_weight >= lv_required_weight THEN
                log_info('Result: ALLOWED (' || lv_effective_perm || ' >= ' || p_required_perm || ')', lv_scope);
                RETURN TRUE;
            ELSE
                log_info('Result: DENIED (' || lv_effective_perm || ' < ' || p_required_perm || ')', lv_scope);
                RETURN FALSE;
            END IF;
        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM ||
                             ' app=' || p_app_id ||
                             ' page=' || p_page_id ||
                             ' type=' || p_component_type ||
                             ' key=' || p_component_key,
                p_scope   => lv_scope
            );
            RETURN c_default_on_error;
    END f_authorized;

    FUNCTION f_authorized_yn (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL,
        p_required_perm   IN t_permission     DEFAULT c_perm_view
    ) RETURN VARCHAR2
    IS
    BEGIN
        IF f_authorized(p_app_id, p_page_id, p_component_type,
                       p_component_key, p_required_perm)
        THEN
            RETURN c_yes;
        ELSE
            RETURN c_no;
        END IF;
    END f_authorized_yn;

    FUNCTION f_can_edit (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL
    ) RETURN BOOLEAN
    IS
    BEGIN
        RETURN f_authorized(
            p_app_id, p_page_id, p_component_type,
            p_component_key, c_perm_edit
        );
    END f_can_edit;

    FUNCTION f_is_admin (
        p_app_id          IN t_app_id         DEFAULT NV('APP_ID'),
        p_page_id         IN t_page_id        DEFAULT NV('APP_PAGE_ID'),
        p_component_type  IN t_component_type DEFAULT NULL,
        p_component_key   IN t_component_key  DEFAULT NULL
    ) RETURN BOOLEAN
    IS
    BEGIN
        RETURN f_authorized(
            p_app_id, p_page_id, p_component_type,
            p_component_key, c_perm_admin
        );
    END f_is_admin;

    ---------------------------------------------------------------------------
    -- PUBLIC: Administrative Procedures
    ---------------------------------------------------------------------------
    FUNCTION f_component_has_auth_scheme(p_app_id IN t_app_id
			                                  ,p_component_type IN t_component_type
																				,p_component_key  IN t_component_key
																				,p_page_id IN t_page_id) RETURN BOOLEAN 
		IS
			lv_scope    t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
			lv_cnt      PLS_INTEGER := 0;
		BEGIN
			 log_info(
            p_message => 'checking_if_comp_has_auth_scheme: ' ||
                         'type=' || p_component_type ||
                         ' key=' || p_component_key ||
                         ' page_id=' || p_page_id ||
                         ' app_id=' || p_app_id,
            p_scope   => lv_scope
        );
			SELECT count(*) INTO lv_cnt
			  FROM v_apex_components c
			WHERE c.app_id         = p_app_id
			  AND c.component_type = p_component_type
				AND (c.page_id = p_page_id OR (c.page_id IS NULL AND p_page_id IS NULL))
				AND (c.component_name = p_component_key /*OR c.component_id = p_component_key*/)
				AND c.auth_scheme IS NOT NULL;
				
		  RETURN CASE lv_cnt WHEN 0 THEN FALSE ELSE TRUE END;		
		
		END f_component_has_auth_scheme;
	  
		PROCEDURE add_role(p_role_name IN t_app_roles.role_name%TYPE,
			                     p_remarks   IN t_app_roles.remarks%TYPE ) IS
			  lv_scope    t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_username t_username := f_current_account_id;
	  BEGIN
			INSERT INTO t_app_roles( 
                              role_name,
                              short_name,
                              remarks,
                              ins_user )
			VALUES (p_role_name, null, p_remarks, lv_username);
		EXCEPTION
			WHEN OTHERS THEN
				log_error(
                p_message => 'Failed with: ' || SQLERRM,
                p_scope   => lv_scope
            );
            RAISE;
		END add_role;
    
		PROCEDURE grant_permission (
        p_app_id          IN t_app_id,
        p_component_type  IN t_component_type,
        p_component_key   IN t_component_key,
        p_page_id         IN t_page_id,
        p_role_id         IN t_role_id,
        p_permission      IN t_permission,
        p_effective_from  IN DATE DEFAULT TRUNC(SYSDATE),
        p_effective_to    IN DATE DEFAULT NULL
    )
    IS
        lv_scope    t_vc2_small := gc_scope_prefix || lower(utl_call_stack.subprogram(1) (2));
        lv_username t_username := f_current_account_id;
				lv_parent_key t_component_key;
    BEGIN
        -- Validate permission
        IF f_permission_weight(p_permission) < 0 THEN
            RAISE_APPLICATION_ERROR(
                c_err_invalid_perm,
                'Invalid permission code: ' || p_permission
            );
        END IF;
				-- Check if the component has an authorization scheme defined
				IF NOT f_component_has_auth_scheme(p_app_id         => p_app_id,
																					 p_component_type => p_component_type,
																					 p_component_key  => p_component_key,
																					 p_page_id        => p_page_id
																				  ) THEN
					  RAISE_APPLICATION_ERROR(
              c_err_component_def,
              'No authorization scheme defined for: ' || p_component_type || '=' || p_component_key
          );
				END IF;
      
				
        lv_parent_key := CASE WHEN p_component_type IN (c_type_item, c_type_button, c_type_process) 
				                      THEN f_parent_region_key(p_app_id, p_page_id, p_component_type, p_component_key)
														  WHEN p_component_type = c_type_list_entry
														  THEN f_parent_list_entry_key(p_app_id, p_component_key)
														  ELSE NULL
															END;
        -- MERGE handles insert or update
        MERGE INTO t_auth_component_perms t
        USING (
            SELECT p_app_id AS app_id,
                   p_component_type AS component_type,
                   p_component_key AS component_key,
                   p_page_id AS page_id,
                   p_role_id AS role_id
              FROM DUAL
        ) s
        ON (    t.app_id = s.app_id
            AND t.component_type = s.component_type
            AND t.role_id = s.role_id
						AND ((t.component_key = s.component_key) OR (t.component_key IS NULL AND s.component_key IS NULL))
            AND ((t.page_id = s.page_id) OR (t.page_id IS NULL AND s.page_id IS NULL))
        )
        WHEN MATCHED THEN
            UPDATE SET
                permission_code = p_permission,
                effective_from  = p_effective_from,
                effective_to    = p_effective_to,
                modified_by     = lv_username,
                modified_on     = SYSTIMESTAMP
        WHEN NOT MATCHED THEN
            INSERT (
                app_id, component_type, component_key, parent_key, page_id,
                role_id, permission_code, effective_from, effective_to,
                created_by
            )
            VALUES (
                p_app_id, p_component_type, p_component_key, lv_parent_key, p_page_id,
                p_role_id, p_permission, p_effective_from, p_effective_to,
                lv_username
            );

        log_info(
            p_message => 'Permission granted: ' ||
                         'type=' || p_component_type ||
                         ' key=' || p_component_key ||
                         ' role=' || p_role_id ||
                         ' perm=' || p_permission,
            p_scope   => lv_scope
        );
        
    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM,
                p_scope   => lv_scope
            );
            RAISE;
    END grant_permission;

    PROCEDURE revoke_permission (
        p_perm_id IN t_auth_component_perms.perm_id%TYPE
    )
    IS
        lv_scope t_vc2_small := gc_scope_prefix || 'revoke_permission';
    BEGIN
        DELETE FROM t_auth_component_perms
         WHERE perm_id = p_perm_id;

        IF SQL%ROWCOUNT = 0 THEN
            log_info(
                p_message => 'No permission found: perm_id=' || p_perm_id,
                p_scope   => lv_scope
            );
        ELSE
            log_info(
                p_message => 'Permission revoked: perm_id=' || p_perm_id,
                p_scope   => lv_scope
            );
        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            log_error(
                p_message => 'Failed with: ' || SQLERRM ||
                             ' perm_id=' || p_perm_id,
                p_scope   => lv_scope
            );
            RAISE;
    END revoke_permission;
    ----
		
    ---------------------------------------------------------------------------
    -- PACKAGE INITIALIZATION
    ---------------------------------------------------------------------------
BEGIN
    -- Initialize the component type pattern map on package load
    init_type_map;
    
END apex_auth_api;
/
