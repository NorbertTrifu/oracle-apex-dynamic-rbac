# Hierarchy Resolution - How the 4-Level Query Works

## The Core Query

The 'f_effective_permission' function resolves permissions using a single 'WITH' clause that checks four hierarchy levels simultaneously:

'''sql
WITH perm_hierarchy AS (
    -- Level 1: Exact component match
    SELECT 1 AS hier_level, permission_code, ...
    FROM t_auth_component_permss
    WHERE component_type = :type AND component_key = :key AND page_id = :page

    UNION ALL

    -- Level 2a: Parent REGION (for ITEM/BUTTON/PROCESS only)
    SELECT 2, permission_code, ...
    WHERE component_type = 'REGION' AND component_key = :parent_region_key

    UNION ALL

    -- Level 2b: Parent LIST_ENTRY (for nested nav entries only)
    SELECT 2, permission_code, ...
    WHERE component_type = 'LIST_ENTRY' AND component_key = :parent_entry_key

    UNION ALL

    -- Level 3: PAGE level
    SELECT 3, permission_code, ...
    WHERE component_type = 'PAGE' AND component_key = TO_CHAR(:page_id)

    UNION ALL

    -- Level 4: APPLICATION level
    SELECT 4, permission_code, ...
    WHERE component_type = 'APPLICATION' AND component_key IS NULL
)
SELECT permission_code
FROM perm_hierarchy
ORDER BY hier_level ASC,      -- most specific first
         perm_weight DESC,    -- highest permission at that level
         is_deny DESC         -- DENY always wins
FETCH FIRST 1 ROW ONLY;
'''

## Worked Examples

### Example 1: ADMIN at APPLICATION level inherits everywhere

| Role | Type | Key | Permission |
|------|------|-----|------------|
| ADMIN | APPLICATION | NULL | ADMIN |

Checking VIEW on ITEM P10_NAME:
- Level 1 (ITEM P10_NAME): no rows
- Level 2 (parent REGION): no rows
- Level 3 (PAGE 10): no rows
- Level 4 (APPLICATION): **ADMIN found** (weight 3 >= required VIEW weight 1)
- **Result: ALLOWED**

### Example 2: DENY overrides inherited permission

| Role | Type | Key | Permission |
|------|------|-----|------------|
| VIEWER | PAGE | 10 | VIEW |
| VIEWER | ITEM | P10_SALARY | DENY |

Checking VIEW on ITEM P10_SALARY:
- Level 1 (ITEM P10_SALARY): **DENY found** (is_deny=1, sorts first)
- **Result: DENIED** (stops - never reaches PAGE level)

Checking VIEW on ITEM P10_NAME:
- Level 1 (ITEM P10_NAME): no rows
- Level 2 (parent REGION): no rows
- Level 3 (PAGE 10): **VIEW found** (weight 1 >= required VIEW weight 1)
- **Result: ALLOWED**

### Example 3: Navigation entry hierarchy

| Role | Type | Key | Parent Key | Permission |
|------|------|-----|------------|------------|
| VIEWER | LIST_ENTRY | Reports | NULL | VIEW |
| VIEWER | LIST_ENTRY | Sales_Report | Reports | DENY |

Checking VIEW on LIST_ENTRY Sales_Report:
- Level 1 (LIST_ENTRY Sales_Report): **DENY found**
- **Result: DENIED**

Checking VIEW on LIST_ENTRY HR_Report (child of Reports, no explicit rule):
- Level 1 (LIST_ENTRY HR_Report): no rows
- Level 2 (parent LIST_ENTRY Reports): **VIEW found**
- **Result: ALLOWED** (inherits from parent nav entry)
