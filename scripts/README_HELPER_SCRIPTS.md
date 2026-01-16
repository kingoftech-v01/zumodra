# Zumodra Helper Scripts

This directory contains helper scripts for setting up, managing, and maintaining the Zumodra platform.

## Available Scripts

### 1. setup_database.sh
**Purpose:** Automated database setup after Docker containers are running.

**Usage:**
```bash
bash scripts/setup_database.sh
```

**What it does:**
1. Checks if Docker containers are running
2. Waits for PostgreSQL to be ready
3. Tests database connection from Django
4. Runs shared schema migrations (PUBLIC schema)
5. Runs tenant schema migrations (if tenants exist)
6. Verifies all migrations are applied
7. Creates superuser account (interactive)
8. Collects static files
9. Runs Django system checks

**Requirements:**
- Docker containers must be running (`docker compose up -d`)
- `.env` file must be configured

### 2. verify_environment.py
**Purpose:** Comprehensive environment verification before development or deployment.

**Usage:**
```bash
python scripts/verify_environment.py
```

**What it checks:**
1. Python version (3.11+ required)
2. GDAL installation and configuration
3. GEOS installation and functionality
4. Django installation (5.x recommended)
5. Django Channels installation
6. Environment file (.env) exists and has critical variables
7. Docker is running with containers
8. Database connection
9. Redis connection
10. Static files collected

**Exit Codes:**
- `0`: All checks passed (100%)
- `1`: Most checks passed (70%+) - warnings present
- `2`: Many checks failed (<70%) - errors require fixing

## Quick Start Workflow

### Initial Setup (First Time)

```bash
# 1. Verify environment
python scripts/verify_environment.py

# 2. Start Docker containers
docker compose up -d

# 3. Wait for services to be ready (30 seconds)
sleep 30

# 4. Setup database (includes migrations and superuser creation)
bash scripts/setup_database.sh

# 5. Start development server
python manage.py runserver
```

### Daily Development Workflow

```bash
# Start Docker containers
docker compose up -d

# Verify everything is working
python scripts/verify_environment.py

# Start development server
python manage.py runserver
```

---

**Last Updated:** January 16, 2026
**Maintainer:** Backend Lead Developer
