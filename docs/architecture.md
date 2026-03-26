# Architecture

## Core Design: Single Table, Single Package

Unlike multi-table RBAC frameworks that maintain a separate component registry synced from APEX metadata, this framework stores permissions directly with **component keys** (static_id or component name) in one table: 't_auth_component_perms'.

### Why Single Table?

1. **No sync jobs**: No need to keep a registry table in sync with APEX metadata. If you rename a region in APEX, you update the 'component_key' in one permission row.
2. **Forward-granting**: You can grant permissions for components that don't exist yet (e.g., a page under development).
3. **Virtual column unique key**: The challenge with a single table is that 'component_key' and 'page_id' can be NULL (for APPLICATION-level permissions). Oracle doesn't enforce uniqueness on NULLs. The solution uses virtual columns that replace NULL with 'CHR(0)':

'''sql
component_key_uk AS (COALESCE(component_key, '' || CHR(0)))
page_id_uk       AS (COALESCE(TO_CHAR(page_id), '' || CHR(0)))
'''

This allows a proper unique index on '(app_id, component_type, component_key_uk, page_id_uk, role_id)'.

## Permission Resolution Flow

'''
f_authorized() called by APEX
    │
    ├── ensure roles cached (PGA session state)
    │
    ├── resolve_component_info()
    │   ├── map APEX view name → internal type (associative array lookup)
    │   ├── resolve component_key from APEX bind variables
    │   └── special handling for LIST_ENTRY (resolve via list_entry_id)
    │
    ├── f_effective_permission()
    │   ├── find parent_key (region for items/buttons, parent entry for nav)
    │   ├── execute 4-level WITH clause:
    │   │   Level 1: exact component match
    │   │   Level 2a: parent REGION (for items/buttons/processes)
    │   │   Level 2b: parent LIST_ENTRY (for nested nav entries)
    │   │   Level 3: PAGE (for non-nav components)
    │   │   Level 4: APPLICATION (always checked last)
    │   └── ORDER BY hier_level ASC, perm_weight DESC, is_deny DESC
    │       → returns highest permission at most specific level, DENY wins
    │
    └── compare effective weight vs required weight
        → ADMIN(3) >= EDIT(2) >= VIEW(1) > DENY(0)
'''

## Session Cache Strategy

The package maintains three caches in PGA (package body state):

| Cache | Contents | Invalidation |
|-------|----------|-------------|
| 'gv_cached_account_id' | Resolved account_id for APP_USER | Changes when APP_USER changes or 'clear_session_cache' called |
| 'gv_user_roles' | 't_role_id_tab' collection of role IDs | Reloaded with account; cleared by 'clear_session_cache' |
| 'gv_type_map' | Associative array mapping APEX view names → internal types | Loaded once, never invalidated (static data) |

There is no cross-session result cache (no 'RESULT_CACHE'). The query inside 'f_effective_permission' runs fresh each time. This is a deliberate trade-off: it ensures permission changes are immediately visible without needing a version counter or cache flush mechanism.

## Component Type Mapping

APEX sends different strings in 'APP_COMPONENT_TYPE' depending on the component:

| APEX Sends | Framework Maps To |
|------------|-------------------|
| 'APEX_APPLICATION_PAGES' | 'PAGE' |
| 'APEX_APPLICATION_PAGE_REGIONS' | 'REGION' |
| 'APEX_APPLICATION_PAGE_ITEMS' | 'ITEM' |
| 'APEX_APPLICATION_PAGE_BUTTONS' | 'BUTTON' |
| 'APEX_APPLICATION_PAGE_PROC' | 'PROCESS' |
| 'APEX_APPLICATION_LIST_ENTRIES' | 'LIST_ENTRY' |
| 'APEX_APPLICATION_NAV_BAR' | 'NAV_BAR' |

The mapping uses an associative array initialized once per session, with pattern-based fallback for edge cases.

## Logging Architecture

The framework uses a **three-tier logging fallback** that adapts to whatever logging infrastructure is available in the target environment:

'''
log_error / log_info called
    │
    ├── Try 1: debug_pkg.printf (if debug mode ON)
    │   Alexandria PL/SQL Utilities — lightweight development tracing
    │   https://github.com/mortenbra/alexandria-plsql-utils
    │
    ├── Try 2: logger.log_error / logger.log_info
    │   OraOpenSource Logger — structured production logging
    │   https://github.com/OraOpenSource/Logger/releases/tag/3.1.1
    │
    ├── Try 3: APEX_DEBUG.ERROR / APEX_DEBUG.INFO
    │   Built-in APEX debug — works in any APEX runtime
    │
    └── Fallback: NULL (silent)
        No logging library causes a runtime failure
'''

Each tier is wrapped in its own 'EXCEPTION WHEN OTHERS THEN' block, so a missing library simply falls through to the next tier. This means:

- **Full environment** (Logger + Alexandria installed): Rich structured logging with scope tracking via Logger, plus development-time 'DBMS_OUTPUT' tracing via 'debug_pkg'
- **APEX-only environment** (no external libraries): Falls back to 'APEX_DEBUG', visible in APEX Debug Mode
- **Minimal environment** (no APEX session, no libraries): Silent — the package still compiles and runs

Debug mode is toggled at runtime via 'apex_auth_api.debug_mode_on' / 'debug_mode_off', which enables the 'debug_pkg.printf' calls without requiring recompilation.
