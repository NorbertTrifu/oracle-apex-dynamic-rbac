# Installation Guide

## Prerequisites
- Oracle Database 19c (19.3+)
- Oracle APEX 24.1+
- Schema with CREATE TABLE, CREATE VIEW, CREATE PROCEDURE privileges

### Optional (recommended for production logging)

These libraries are **not required** — the package compiles and runs without them, falling back to `APEX_DEBUG`.

- **[OraOpenSource Logger 3.x](https://github.com/OraOpenSource/Logger/releases/tag/3.1.1)** — Structured PL/SQL logging with scope tracking, log levels, and purge management. Install Logger in the same schema before compiling `apex_auth_api` for full logging support.

- **[Alexandria PL/SQL Utilities — `debug_pkg`](https://github.com/mortenbra/alexandria-plsql-utils/blob/master/ora/debug_pkg.pks)** — Lightweight `DBMS_OUTPUT`-based debug tracing, toggled at runtime via `apex_auth_api.debug_mode_on`. Install the `debug_pkg` spec and body from the Alexandria repository.

## Install
```sql
@scripts/install.sql
```

## Configure APEX
See [apex/apex_setup_guide.md](apex/apex_setup_guide.md)

## Verify
```sql
SELECT object_type, object_name, status FROM user_objects
WHERE object_name IN ('APEX_AUTH_API','T_AUTH_COMPONENT_PERMS','V_AUTH_ADMIN','V_AUTH_ADMIN_UI','V_AUTH_COMPONENTS_LOV','V_AUTH_STATS','V_APEX_COMPONENTS')
ORDER BY object_type;
```

## Uninstall
```sql
@scripts/uninstall.sql
```
