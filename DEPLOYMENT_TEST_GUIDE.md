# Deployment and Testing Guide for zumodra.rhematek-solutions.com

This guide provides step-by-step instructions for deploying and testing the Zumodra platform on the development server.

## Server Details

- **URL:** zumodra.rhematek-solutions.com
- **Environment:** Development
- **Note:** Safe to test - no data loss concerns

---

## Quick Start Commands

### 1. SSH Connection

```bash
# Connect to the server
ssh user@zumodra.rhematek-solutions.com

# Or if you have a specific user/key
ssh -i ~/.ssh/your_key user@zumodra.rhematek-solutions.com
```

### 2. Navigate to Project Directory

```bash
cd /path/to/zumodra
# Adjust the path based on your server setup
```

### 3. Pull Latest Changes

```bash
# Pull latest code from repository
git pull origin main

# Or if you're on a different branch
git pull origin <your-branch-name>
```

### 4. Install Dependencies

```bash
# Activate virtual environment
source venv/bin/activate
# or
source .venv/bin/activate

# Install/update Python dependencies
pip install -r requirements.txt
```

### 5. Run Migrations

```bash
# Check for pending migrations
python manage.py showmigrations

# Run migrations
python manage.py migrate

# Create migrations if needed
python manage.py makemigrations
python manage.py migrate
```

---

## Testing Procedures

### A. Run Comprehensive Test Suite

```bash
# Make scripts executable
chmod +x scripts/test_all_apps.py
chmod +x scripts/seed_test_data.py

# Run the comprehensive test suite
python scripts/test_all_apps.py
```

This will:
- Test all 35 Django apps
- Check URL routing
- Verify models and migrations
- Run pytest tests
- Generate detailed reports in each app's `reports/` folder
- Create a master report in `test_results/`

### B. Seed Test Data

```bash
# Install faker if not installed
pip install faker

# Run data seeding script
python scripts/seed_test_data.py
```

This creates test data for:
- Users (including superuser)
- Tenants
- Jobs
- Services
- Blog posts
- Projects
- Notifications
- Appointments
- Invoices

**Default Credentials:**
- Email: `admin@zumodra.com`
- Password: `admin123`

### C. Run Specific App Tests

```bash
# Test a specific app
pytest accounting/tests -v

# Test with coverage
pytest accounting/tests --cov=accounting --cov-report=html

# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Skip slow tests
pytest -m "not slow"
```

### D. Check Database Status

```bash
# Show all migrations status
python manage.py showmigrations

# Check for unapplied migrations
python manage.py showmigrations --plan | grep "\[ \]"

# Inspect database
python manage.py dbshell
```

### E. Start Development Server

```bash
# Start Django development server
python manage.py runserver 0.0.0.0:8000

# Or if using Docker
docker-compose up

# Check if server is running
curl http://localhost:8000
```

### F. Static Files

```bash
# Collect static files
python manage.py collectstatic --noinput

# Clear static files cache
find staticfiles/ -type f -delete
python manage.py collectstatic --noinput
```

---

## Complete Testing Workflow

Here's the recommended complete workflow:

```bash
# 1. SSH into server
ssh user@zumodra.rhematek-solutions.com

# 2. Navigate to project
cd /path/to/zumodra

# 3. Pull latest changes
git status
git pull origin main

# 4. Activate virtual environment
source venv/bin/activate

# 5. Install dependencies
pip install -r requirements.txt

# 6. Run migrations
python manage.py migrate

# 7. Seed test data (first time only)
python scripts/seed_test_data.py

# 8. Run comprehensive tests
python scripts/test_all_apps.py

# 9. Start server (if not running)
python manage.py runserver 0.0.0.0:8000

# 10. Check the reports
cat test_results/master_report.md

# 11. Review individual app reports
cat accounting/reports/test_report.md
cat jobs/reports/test_report.md
# ... etc
```

---

## Docker-based Deployment (if using Docker)

```bash
# Pull latest changes
git pull origin main

# Rebuild containers
docker-compose down
docker-compose build
docker-compose up -d

# Run migrations in container
docker-compose exec web python manage.py migrate

# Seed data in container
docker-compose exec web python scripts/seed_test_data.py

# Run tests in container
docker-compose exec web python scripts/test_all_apps.py

# View logs
docker-compose logs -f web

# Access container shell
docker-compose exec web bash
```

---

## Viewing Test Reports

### Master Report

```bash
# View master report (JSON)
cat test_results/master_report.json | jq '.'

# View master report (Markdown)
cat test_results/master_report.md

# View data seeding report
cat test_results/seed_data_report.md
```

### Individual App Reports

```bash
# List all app reports
find . -path "*/reports/test_report.md" -type f

# View specific app report
cat accounting/reports/test_report.md
cat jobs/reports/test_report.md
cat blog/reports/test_report.md

# View pytest reports (if available)
cat accounting/reports/pytest_report.json | jq '.'
```

### Download Reports to Local Machine

```bash
# From your local machine, download reports
scp -r user@zumodra.rhematek-solutions.com:/path/to/zumodra/test_results ./local_reports/

# Or specific app reports
scp -r user@zumodra.rhematek-solutions.com:/path/to/zumodra/*/reports ./app_reports/
```

---

## Troubleshooting

### Issue: Migration Conflicts

```bash
# Reset migrations (DEV ONLY - data loss!)
python manage.py migrate <app_name> zero
python manage.py migrate <app_name>

# Or recreate database (DEV ONLY)
python manage.py flush
python manage.py migrate
```

### Issue: Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000
# or
netstat -tuln | grep 8000

# Kill the process
kill -9 <PID>
```

### Issue: Permission Denied

```bash
# Fix permissions
chmod +x manage.py
chmod +x scripts/*.py

# Fix ownership (if needed)
sudo chown -R $USER:$USER .
```

### Issue: Module Not Found

```bash
# Verify virtual environment is activated
which python
# Should show path to venv/bin/python

# Reinstall requirements
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Monitoring and Logs

```bash
# View Django logs (if configured)
tail -f logs/django.log

# View system logs
journalctl -u zumodra -f

# View nginx logs (if using nginx)
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# View gunicorn logs (if using gunicorn)
tail -f logs/gunicorn.log
```

---

## Automated Testing Script

Create this script on the server for quick testing:

```bash
#!/bin/bash
# save as: quick_test.sh

echo "=========================================="
echo "Quick Testing Script for Zumodra"
echo "=========================================="

# Activate virtual environment
source venv/bin/activate

# Pull latest code
echo "Pulling latest code..."
git pull origin main

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -q

# Run migrations
echo "Running migrations..."
python manage.py migrate

# Run tests
echo "Running comprehensive tests..."
python scripts/test_all_apps.py

# Display summary
echo ""
echo "Test results available at:"
echo "  - test_results/master_report.md"
echo "  - */reports/test_report.md"
echo ""
echo "View with: cat test_results/master_report.md"
```

Make it executable:
```bash
chmod +x quick_test.sh
./quick_test.sh
```

---

## Summary Checklist

- [ ] SSH into server
- [ ] Navigate to project directory
- [ ] Activate virtual environment
- [ ] Pull latest code
- [ ] Install dependencies
- [ ] Run migrations
- [ ] Seed test data (first time)
- [ ] Run comprehensive test suite
- [ ] Review master report
- [ ] Review individual app reports
- [ ] Start/restart server
- [ ] Verify server is accessible
- [ ] Document any issues found

---

## Report Locations

After running tests, reports will be available at:

1. **Master Reports:**
   - `test_results/master_report.md`
   - `test_results/master_report.json`
   - `test_results/seed_data_report.md`

2. **Individual App Reports:**
   - `<app_name>/reports/test_report.md`
   - `<app_name>/reports/test_report.json`
   - `<app_name>/reports/pytest_report.json`

3. **Apps with Reports:**
   - accounting/reports/
   - ai_matching/reports/
   - analytics/reports/
   - api/reports/
   - billing/reports/
   - blog/reports/
   - careers/reports/
   - configurations/reports/
   - core/reports/
   - core_identity/reports/
   - dashboard/reports/
   - escrow/reports/
   - expenses/reports/
   - finance_webhooks/reports/
   - hr_core/reports/
   - integrations/reports/
   - interviews/reports/
   - jobs/reports/
   - jobs_public/reports/
   - main/reports/
   - marketing_campaigns/reports/
   - messages_sys/reports/
   - notifications/reports/
   - payments/reports/
   - payroll/reports/
   - projects/reports/
   - projects_public/reports/
   - security/reports/
   - services/reports/
   - services_public/reports/
   - stripe_connect/reports/
   - subscriptions/reports/
   - tax/reports/
   - tenant_profiles/reports/
   - tenants/reports/

---

## Contact

For issues or questions, contact the development team.
