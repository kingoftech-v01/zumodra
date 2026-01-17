# Zumodra Automated Deployment Guide

## Quick Start

### Windows Users (Easiest):
```bash
DEPLOY.bat
```

### Linux/Mac/Manual:
```bash
# Option 1: Upload and execute
ssh zumodra 'bash -s' < deploy_and_test.sh

# Option 2: Copy script to server first
scp deploy_and_test.sh zumodra:~/
ssh zumodra
chmod +x deploy_and_test.sh
./deploy_and_test.sh
```

---

## What This Does Automatically

### 1. Code Deployment
- ✅ Pulls latest changes from GitHub (`main` branch)
- ✅ Shows git commit changes
- ✅ Installs/updates Python dependencies
- ✅ Runs database migrations (public + tenant schemas)
- ✅ Collects static files

### 2. Service Management
- ✅ Restarts `zumodra-web` (Django app)
- ✅ Restarts `zumodra-channels` (WebSocket server)
- ✅ Restarts `zumodra-celery` (Background workers)
- ✅ Verifies all services are running

### 3. Automated Testing
- ✅ Runs authentication infrastructure test
- ✅ Runs MFA enforcement test
- ✅ Runs Django health check
- ✅ Runs Django system check
- ✅ Runs pytest suite (if configured)

### 4. Report Generation
- ✅ Creates timestamped test results directory
- ✅ Saves all test logs
- ✅ Generates comprehensive deployment report
- ✅ Displays summary in terminal

---

## Prerequisites

### On Your Local Machine:
- SSH access configured: `ssh zumodra` works
- Git credentials configured (or SSH key added to GitHub)

### On the Server:
- Project path: `/home/zumodra/zumodra.rhematek-solutions.com`
- Virtual environment: `venv/`
- Services configured: `zumodra-web`, `zumodra-channels`, `zumodra-celery`
- Sudo access for service restart

---

## Deployment Output

You'll see a 9-step process:

```
╔════════════════════════════════════════════════════════════════╗
║           ZUMODRA AUTOMATED DEPLOYMENT & TESTING              ║
╚════════════════════════════════════════════════════════════════╝

[1/9] Navigating to project directory...
[2/9] Pulling latest changes from GitHub...
[3/9] Installing/updating dependencies...
[4/9] Running database migrations...
[5/9] Collecting static files...
[6/9] Restarting services...
[7/9] Verifying services...
[8/9] Running automated tests...
[9/9] Generating test report...

╔════════════════════════════════════════════════════════════════╗
║                 DEPLOYMENT COMPLETE                            ║
╚════════════════════════════════════════════════════════════════╝
```

---

## Test Results Location

After deployment, test results are saved on the server:

```
/home/zumodra/zumodra.rhematek-solutions.com/test_results_YYYYMMDD_HHMMSS/
├── DEPLOYMENT_REPORT.txt    (Summary report)
├── auth_test.log             (Authentication test)
├── mfa_test.log              (MFA enforcement test)
├── health_check.log          (Health check results)
├── django_check.log          (System check results)
└── pytest.log                (Pytest results)
```

### Download Results:
```bash
# Download entire test results directory
scp -r zumodra:~/zumodra.rhematek-solutions.com/test_results_* .

# Or just the summary report
scp zumodra:~/zumodra.rhematek-solutions.com/test_results_*/DEPLOYMENT_REPORT.txt .
```

---

## Manual Verification

After automated deployment, manually verify these features:

### 1. Website Access
- Visit: https://zumodra.rhematek-solutions.com
- Verify homepage loads
- Check no errors in browser console

### 2. User Registration
- Go to: `/accounts/signup/`
- Register a new test account
- Verify redirect to dashboard

### 3. MFA Setup
- Go to: `/accounts/two-factor/`
- Verify page loads without errors
- Check QR code displays (if setting up TOTP)

### 4. Public User Dashboard (NEW FEATURE)
- Login as user without tenant
- Go to: `/app/dashboard/`
- Verify new dashboard template displays:
  - ✅ Welcome banner
  - ✅ MFA warning banner (if not enabled)
  - ✅ Profile completion widget
  - ✅ Quick action cards
  - ✅ Recommended jobs section

### 5. Navigation with MFA Link (NEW FEATURE)
- Click user dropdown in header
- Verify "Two-Factor Auth" link present
- Verify "Setup" badge shows if MFA not enabled
- Test link navigates to `/accounts/two-factor/`

### 6. MFA Enforcement (NEW FEATURE)
- Create user > 30 days old (manually set date_joined in admin)
- Login as that user
- Verify redirected to MFA setup
- Verify warning message displays

---

## Troubleshooting

### Deployment Fails at Step 2 (Git Pull)
**Error:** `Permission denied` or `Authentication failed`
**Solution:**
```bash
ssh zumodra
cd zumodra.rhematek-solutions.com
git config --global credential.helper store
git pull origin main  # Enter credentials
```

### Services Don't Restart (Step 6)
**Error:** `Failed to restart zumodra-web.service`
**Solution:**
```bash
ssh zumodra
sudo systemctl status zumodra-web
sudo journalctl -u zumodra-web -n 50  # Check logs
```

### Tests Fail (Step 8)
**Check test logs:**
```bash
ssh zumodra
cd zumodra.rhematek-solutions.com/test_results_*/
cat DEPLOYMENT_REPORT.txt
less auth_test.log
less mfa_test.log
```

### Can't SSH to Server
**Error:** `Connection refused` or `Permission denied`
**Solution:**
```bash
# Test SSH connection
ssh -v zumodra

# If using password:
ssh -o PreferredAuthentications=password zumodra

# If using key:
ssh -i ~/.ssh/id_rsa zumodra
```

---

## Rollback

If deployment causes issues, rollback:

```bash
ssh zumodra
cd zumodra.rhematek-solutions.com

# View recent commits
git log --oneline -10

# Rollback to previous commit
git reset --hard <commit-hash>

# Restart services
sudo systemctl restart zumodra-web zumodra-channels zumodra-celery
```

---

## Configuration

### Customize Project Path
Edit `deploy_and_test.sh`, line 26:
```bash
PROJECT_DIR="/your/custom/path"
```

### Disable Specific Tests
Edit `deploy_and_test.sh`, Step 8:
Comment out tests you don't want to run:
```bash
# echo -e "${YELLOW}→ Test 2: MFA Enforcement${NC}"
# if $PYTHON "$PROJECT_DIR/test_mfa_enforcement.py" ...
```

### Add Custom Tests
Edit `deploy_and_test.sh`, Step 8:
Add your test after existing ones:
```bash
echo -e "${YELLOW}→ Test 6: My Custom Test${NC}"
if $PYTHON "$PROJECT_DIR/my_custom_test.py" > "$TEST_DIR/custom_test.log" 2>&1; then
    echo -e "${GREEN}  ✓ Custom test PASSED${NC}"
else
    echo -e "${RED}  ✗ Custom test FAILED${NC}"
fi
```

---

## CI/CD Integration

### GitHub Actions
Create `.github/workflows/deploy.yml`:
```yaml
name: Deploy to Production

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Deploy to server
        run: |
          echo "$SSH_KEY" > key.pem
          chmod 600 key.pem
          ssh -i key.pem zumodra 'bash -s' < deploy_and_test.sh
        env:
          SSH_KEY: ${{ secrets.SSH_PRIVATE_KEY }}
```

### GitLab CI
Create `.gitlab-ci.yml`:
```yaml
deploy:
  stage: deploy
  script:
    - ssh zumodra 'bash -s' < deploy_and_test.sh
  only:
    - main
```

---

## Files Reference

| File | Purpose |
|------|---------|
| `deploy_and_test.sh` | Main deployment script (runs on server) |
| `DEPLOY.bat` | Windows launcher (runs locally) |
| `DEPLOYMENT_GUIDE.md` | This guide |
| `quick_auth_test.py` | Authentication infrastructure test |
| `test_mfa_enforcement.py` | MFA enforcement test |
| `test_ats_frontend.py` | ATS frontend test (Playwright) |

---

## Support

**Documentation:**
- Deployment: `DEPLOYMENT_GUIDE.md` (this file)
- Testing: `TESTING_INDEX.md`
- MFA: `MFA_TESTING_README.md`
- ATS: `ATS_TEST_README.md`

**Troubleshooting:**
1. Check deployment report: `DEPLOYMENT_REPORT.txt`
2. Check test logs in `test_results_*/`
3. Check service logs: `sudo journalctl -u zumodra-web -n 100`
4. Check application logs: `tail -f logs/zumodra.log`

---

## Quick Commands

```bash
# Deploy from Windows
DEPLOY.bat

# Deploy from Linux/Mac
ssh zumodra 'bash -s' < deploy_and_test.sh

# Check service status
ssh zumodra "sudo systemctl status zumodra-web zumodra-channels zumodra-celery"

# View recent logs
ssh zumodra "sudo journalctl -u zumodra-web -n 50"

# Download test results
scp -r zumodra:~/zumodra.rhematek-solutions.com/test_results_* .

# Rollback deployment
ssh zumodra "cd zumodra.rhematek-solutions.com && git reset --hard HEAD~1 && sudo systemctl restart zumodra-web zumodra-channels zumodra-celery"
```

---

**Ready to Deploy!** 🚀

Just run `DEPLOY.bat` and watch the magic happen!
