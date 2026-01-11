# Zumodra Scripts

## 📁 Directory Structure

### `deployment/` - Deployment & Migration Scripts
Scripts for deploying and fixing production issues.

| Script | Purpose | Usage |
| ------ | ------- | ----- |
| `deploy_migration_fix.sh` | Deploy with migration fixes | `bash scripts/deployment/deploy_migration_fix.sh` |
| `deploy_fixes.sh` | General deployment fixes | `bash scripts/deployment/deploy_fixes.sh` |
| `fix_migrations.sh` | Fix missing migrations | `bash scripts/deployment/fix_migrations.sh` |
| `clean_rebuild.sh` | Clean rebuild from scratch | `bash scripts/deployment/clean_rebuild.sh` |

### `maintenance/` - Database & Migration Maintenance
Scripts for ongoing maintenance tasks.

| Script | Purpose | Usage |
| ------ | ------- | ----- |
| `fix_migrations.sh` | Fake existing migrations | `docker compose exec web bash /app/scripts/maintenance/fix_migrations.sh` |
| `create_initial_migrations.sh` | Generate initial migrations | `bash scripts/maintenance/create_initial_migrations.sh` |

### Root Scripts - General Utilities

| Script | Purpose | Usage |
| ------ | ------- | ----- |
| `check_deployment.sh` | Verify deployment status | `bash scripts/check_deployment.sh` |
| `setup_ssl.sh` | Setup SSL certificates | `bash scripts/setup_ssl.sh` |

## 🚀 Quick Start

### For Deployment Issues

1. **Migration errors on server:**
   ```bash
   bash scripts/deployment/deploy_migration_fix.sh
   ```

2. **Complete clean rebuild:**
   ```bash
   bash scripts/deployment/clean_rebuild.sh
   ```

### For Development

1. **Check deployment health:**
   ```bash
   bash scripts/check_deployment.sh
   ```

2. **Create new migrations:**
   ```bash
   docker compose exec web python manage.py makemigrations
   ```

## 📝 Script Details

### deployment/deploy_migration_fix.sh
**Purpose:** Deploy the latest code with automatic migration fixes

**What it does:**
- Pulls latest code from main branch
- Rebuilds Docker images (critical for loading new settings)
- Runs migrations automatically via entrypoint
- Monitors logs for errors

**When to use:**
- After fixing migration issues in code
- When "relation does not exist" errors occur
- After adding apps to SHARED_APPS

### deployment/clean_rebuild.sh
**Purpose:** Nuclear option - complete clean rebuild

**What it does:**
- Stops all containers
- Removes all volumes (⚠️  DATA LOSS)
- Rebuilds images from scratch
- Recreates database

**When to use:**
- Development environment is corrupted
- Testing fresh installation
- Never on production without backup!

### maintenance/fix_migrations.sh
**Purpose:** Fake migrations for existing tables

**What it does:**
- Marks migrations as applied without running them
- Useful when tables already exist

**When to use:**
- "relation already exists" errors
- After manual database creation
- When migrations are out of sync

## ⚠️  Important Notes

### Deployment Scripts
- Always review what the script does before running
- Test in staging before production
- Have backups before clean rebuild

### Docker Context
- Some scripts run on host machine
- Others run inside Docker container
- Check usage column for correct context

### Permissions
- All scripts should be executable: `chmod +x scripts/**/*.sh`
- Docker scripts need proper volume mounts

## 🔗 Related Documentation

- [Deployment Guide](../docs/deployment/DEPLOYMENT_SUMMARY.md)
- [Migration Guide](../docs/deployment/MIGRATION_FIX_README.md)
- [Migration Status](../docs/deployment/MIGRATION_STATUS.md)

---

**Last Updated:** 2026-01-11
