# Oracle APEX Component Authorization Framework

A production-grade, **data-driven authorization system** for **Oracle APEX 24.1** and **Oracle Database 19c** that replaces multiple hardcoded Authorization Schemes with a **single dynamic scheme** backed by a permission table.

Permissions for APEX pages, regions, items, buttons, processes, and navigation entries are stored as **ADMIN / EDIT / VIEW / DENY** rules per role, resolved at runtime through a **four-level hierarchy query**, and managed without redeploying the application.

---

## Problem Statement

Standard APEX applications create separate Authorization Schemes per role (`IS_ADMIN`, `IS_MANAGER`, `IS_VIEWER`) and manually assign them to every component. This creates three problems:

1. **Scalability**: 50 pages × 5 roles = hundreds of manual scheme assignments
2. **Login overhead**: APEX evaluates all schemes at login — 20+ schemes means 20+ queries at session start
3. **Deployment required**: Changing who can see what requires modifying APEX metadata and redeploying

This framework solves all three with a single authorization scheme backed by one permission table.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Oracle APEX Application                   │
│                                                          │
│   Page 1    Page 2    Page N    Admin Page               │
│      │         │         │         │                     │
│      └─────────┴─────────┴─────────┘                     │
│                    │                                      │
│       ┌────────────▼──────────────┐                      │
│       │  DYNAMIC_AUTHORIZATION    │                      │
│       │  RETURN apex_auth_api     │                      │
│       │       .f_authorized;      │                      │
│       └────────────┬──────────────┘                      │
└────────────────────┼────────────────────────────────────┘
                     │
        ┌────────────▼────────────────┐
        │      apex_auth_api          │
        │  ┌───────────────────────┐  │
        │  │ PGA Session Cache     │  │  ← Roles loaded once per session
        │  │ (account + roles)     │  │
        │  └──────────┬────────────┘  │
        │             │               │
        │  ┌──────────▼────────────┐  │
        │  │ Hierarchy Permission  │  │  ← 4-level WITH clause
        │  │ Query                 │  │    walks component → region
        │  │ (single SQL)         │  │    → page → application
        │  └──────────┬────────────┘  │
        └─────────────┼───────────────┘
                      │
     ┌────────────────▼──────────────────┐
     │    t_auth_component_perms         │
     │  ┌──────┬──────┬─────┬─────────┐  │
     │  │RoleID│Type  │ Key │PermCode │  │
     │  ├──────┼──────┼─────┼─────────┤  │
     │  │  1   │ APP  │NULL │ ADMIN   │  │  ← Inherits to all children
     │  │  2   │ PAGE │ 10  │ VIEW    │  │
     │  │  2   │ ITEM │SAL  │ DENY    │  │  ← Overrides inherited VIEW
     │  └──────┴──────┴─────┴─────────┘  │
     └───────────────────────────────────┘
```

### Hierarchy Resolution

Permissions cascade from parent to child through four levels:

```
APPLICATION (component_key = NULL)
    └── PAGE (component_key = page_id as string)
        └── REGION (component_key = static_id or region_name)
            ├── ITEM (component_key = item_name)
            ├── BUTTON (component_key = button_static_id or button_name)
            └── PROCESS (component_key = process_name)

For navigation:
APPLICATION
    └── LIST_ENTRY (parent) → LIST_ENTRY (child)
```

**Resolution rules:**
- DENY at **any** level blocks access immediately
- ADMIN implies EDIT implies VIEW (permission weight: ADMIN=3, EDIT=2, VIEW=1, DENY=0)
- Most specific level wins (component → region → page → application)
- Highest permission at that level wins

---

## Technology Stack

| Component | Version | Usage |
|-----------|---------|-------|
| Oracle Database | 19c | Single permission table, virtual columns for unique constraint, PGA session caching |
| Oracle APEX | 24.1 | Single authorization scheme, metadata views for component discovery, APEX_DEBUG integration |
| PL/SQL | 19c | `apex_auth_api` package — BULK COLLECT, MERGE, hierarchical WITH clause, subtypes, pattern matching |
| APEX Metadata Views | 24.1 | `APEX_APPLICATION_PAGES`, `_REGIONS`, `_ITEMS`, `_BUTTONS`, `_PROC`, `_LIST_ENTRIES` |

### Optional Dependencies

The framework uses two open-source PL/SQL libraries for structured logging. Both are **optional** — if not installed, the package falls back to `APEX_DEBUG` and then silently swallows log calls. The framework compiles and runs without them.

| Library | Purpose | Repository |
|---------|---------|------------|
| **OraOpenSource Logger 3.x** | Structured PL/SQL logging (`logger.log_error`, `logger.log_info`) with scope tracking, log levels, and purge management | [github.com/OraOpenSource/Logger](https://github.com/OraOpenSource/Logger/releases/tag/3.1.1) |
| **Alexandria PL/SQL Utilities — `debug_pkg`** | Lightweight debug output (`debug_pkg.printf`) for development-time tracing, toggled on/off at runtime | [github.com/mortenbra/alexandria-plsql-utils](https://github.com/mortenbra/alexandria-plsql-utils/blob/master/ora/debug_pkg.pks) |

**Logging fallback chain**: `Logger → APEX_DEBUG → silent` — the package wraps every log call in a double `EXCEPTION WHEN OTHERS THEN NULL` so missing libraries never cause runtime failures.

---

## Repository Structure

```
oracle-apex-dynamic-rbac/
├── README.md
├── INSTALL.md
├── CHANGELOG.md
├── LICENSE
│
├── database/
│   ├── ddl/
│   │   ├── 01_prerequisite_tables.sql    # t_app_roles, t_app_user_accounts, t_app_user_roles
│   │   └── 02_t_auth_component_perms.sql # Core permission table with virtual column UK
│   ├── packages/
│   │   └── apex_auth_api.pck             # Complete package (spec + body)
│   ├── views/
│   │   ├── 00_V_APEX_COMPONENTS.sql      # Unified APEX metadata view
│   │   ├── V_AUTH_ADMIN.sql              # Admin management view
│   │   ├── V_AUTH_ADMIN_UI.sql           # Admin UI with HTML badges
│   │   ├── V_AUTH_COMPONENTS_LOV.sql     # Component LOV from APEX metadata
│   │   └── V_AUTH_STATS.sql              # Dashboard statistics
│   └── seed/
│       └── 01_seed_data.sql              # Demo roles/users/assignments
│
├── apex/
│   └── apex_setup_guide.md               # APEX authorization scheme configuration
│
├── docs/
│   ├── architecture.md                   # Design decisions and data flow
│   └── hierarchy_resolution.md           # How the 4-level query works
│
└── scripts/
    ├── install.sql                       # Master install
    └── uninstall.sql                     # Clean removal
```

---

## Quick Start

### Prerequisites

- Oracle Database 19c (19.3+)
- Oracle APEX 24.1+
- Schema with CREATE TABLE, CREATE VIEW, CREATE PROCEDURE privileges

### Installation

```sql
@scripts/install.sql
```

### Create the APEX Authorization Scheme

1. **Shared Components → Authorization Schemes → Create**
2. Type: **PL/SQL Function Returning Boolean**
3. Code: `RETURN apex_auth_api.f_authorized;`
4. Evaluation Point: **Once per component**
5. Apply as the default scheme

### Grant Permissions

```sql
-- Grant ADMIN role full application access
BEGIN
    apex_auth_api.grant_permission(
        p_app_id         => 100,
        p_component_type => 'APPLICATION',
        p_component_key  => NULL,
        p_page_id        => NULL,
        p_role_id        => 1,
        p_permission     => 'ADMIN'
    );
END;
/

-- Grant VIEWER role VIEW on specific page, DENY on sensitive item
BEGIN
    apex_auth_api.grant_permission(100, 'PAGE', '10', 10, 3, 'VIEW');
    apex_auth_api.grant_permission(100, 'ITEM', 'P10_SALARY', 10, 3, 'DENY');
END;
/
```

---

## Key Design Decisions

### Single Table vs Component Registry

This framework stores permissions with **component keys** (static_id or component name) directly in `t_auth_component_perms`, rather than maintaining a separate component registry table. This design:
- Eliminates the need for sync jobs between APEX metadata and a registry table
- Allows granting permissions for components that don't yet exist in APEX
- Uses virtual columns for a safe unique constraint even with NULLable columns

### Permission Weights Instead of Hierarchy Flags

Instead of ALLOW/DENY/INHERIT flags, the framework uses weighted permission codes (ADMIN=3 > EDIT=2 > VIEW=1 > DENY=0). This simplifies the authorization check to: "does the user's effective permission weight meet or exceed the required weight?"

### APEX Bind Variable Resolution

The framework reads `APP_COMPONENT_TYPE`, `APP_COMPONENT_NAME`, and `APP_COMPONENT_ID` from APEX session state, then maps APEX's internal view names (e.g., `APEX_APPLICATION_PAGE_REGIONS`) to internal types (e.g., `REGION`) using a PGA-cached associative array. This handles all APEX component types including navigation entries and navbar items.

### Test Mode

The package includes `set_test_user` / `clear_test_user` procedures for testing authorization outside of APEX context (e.g., in SQL Workshop or unit tests).

---

## Oracle 19c Features Demonstrated

| Feature | Where | Purpose |
|---------|-------|---------|
| Virtual Columns | `t_auth_component_perms` | `component_key_uk` and `page_id_uk` enable unique constraint on NULLable columns |
| Identity Column | `t_auth_component_perms.perm_id` | Auto-generated primary key |
| `BULK COLLECT` | `load_user_roles` | Loads all user roles into PGA memory in one round-trip |
| `MERGE` | `grant_permission` | Upserts permission rules (insert or update in one statement) |
| Hierarchical `WITH` clause | `f_effective_permission` | 4-level permission resolution in a single SQL statement |
| `FETCH FIRST 1 ROW ONLY` | `f_effective_permission` | Row limiting clause (12c+) for top-1 permission |
| PGA Session Cache | Package body state | Caches account_id, roles, and type map per session |
| Subtypes (`SUBTYPE`) | Package spec | Anchored types for maintainability |
| `UTL_CALL_STACK` | Logging | Dynamic scope resolution for log entries |
| `COALESCE` + `NVL` chain | `f_current_account_id` | Multi-source user resolution (APEX → session → DB) |

## Oracle APEX 24.1 Features Demonstrated

| Feature | Where | Purpose |
|---------|-------|---------|
| Single Dynamic Authorization | All components | Replaces N hardcoded schemes |
| `V('APP_COMPONENT_TYPE')` | `resolve_component_info` | Reads APEX bind variables at render time |
| `APEX_DEBUG.ERROR/INFO` | Logging fallback | APEX-native debug logging when Logger unavailable |
| `apex_application.g_user` | `f_current_account_id` | Direct global variable access for user resolution |
| Metadata Views | `V_AUTH_COMPONENTS_LOV` | Populates admin LOVs from live APEX metadata |
| `NV('APP_ID')` | All public functions | Default parameter from APEX numeric bind |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
