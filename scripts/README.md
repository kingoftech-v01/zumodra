# Migration Fix Scripts

This directory contains helper scripts for fixing and verifying tenant migrations.

## Scripts Overview

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `fix_demo_tenant_migrations.sh` | Apply missing migrations to demo tenant | After deploying the fix, before restarting containers |
| `verify_migration_fixes.sh` | Comprehensive verification of all fixes | After deployment to verify everything works |

## Usage

### Fix Demo Tenant Migrations

**Purpose:** Apply all pending migrations to the demo tenant to fix the `finance_invoice` missing table error.

```bash
# Inside Docker container
docker exec -it zumodra-web-1 bash scripts/fix_demo_tenant_migrations.sh

# Or from within container
bash scripts/fix_demo_tenant_migrations.sh
```

**What it does:**
1. Checks if demo tenant exists
2. Checks current migration status
3. Applies missing migrations with `--fix` flag
4. Verifies all migrations are applied
5. Tests finance tables are accessible

**Exit codes:**
- `0` - Success, all migrations applied
- `1` - Failure, see error messages

### Verify Migration Fixes

**Purpose:** Run comprehensive tests to verify all migration fixes are working correctly.

```bash
# Inside Docker container
docker exec -it zumodra-web-1 bash scripts/verify_migration_fixes.sh
```

**What it tests:**
- Code verification (4 tests)
- Database verification (4 tests)
- Configuration verification (2 tests)

**Exit codes:**
- `0` - All tests passed
- `1` - Some tests failed

## Additional Resources

- **Quick Reference:** `../MIGRATION_FIX_QUICK_REFERENCE.md`
- **Full Deployment Guide:** `../DEPLOYMENT_MIGRATION_FIX.md`
