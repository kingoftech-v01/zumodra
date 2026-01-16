# Zumodra – Incident Response & Troubleshooting Guide
## Rapid Problem Resolution Procedures

**Project:** Zumodra HR/Management SaaS  
**Created:** January 16, 2026  
**For:** All Team Members + On-Call Support

---

## 1. Incident Response Procedure

### 1.1 Immediate Response (First 5 Minutes)

**When someone reports a critical issue:**

1. **Acknowledge in Slack #zumodra-critical**
   ```
   @Supervisor [Incident] App login not working
   Status: INVESTIGATING
   ```

2. **Verify issue independently**
   - Test the reported feature yourself
   - Check error logs immediately (Sentry, CloudWatch)
   - Ask: Can anyone else reproduce it?

3. **Assess severity**
   - **Critical:** App down, major feature broken, data loss
   - **High:** Feature partially broken, causes errors on save
   - **Medium:** UI issue, slow performance, minor data issue
   - **Low:** Visual glitch, documentation issue

4. **Assign owner**
   - Supervisor assigns to most relevant developer
   - Backend issue → Backend Lead or specific dev
   - Frontend issue → Frontend Lead or specific dev
   - Infrastructure issue → DevOps

### 1.2 Investigation Phase (5–30 Minutes)

**Assigned developer:**

1. **Check logs**
   ```bash
   # Django error logs
   tail -f logs/django.log | grep -i error
   
   # Sentry errors
   # https://sentry.io/zumodra/
   
   # Database logs
   sudo tail -f /var/log/postgresql/postgresql.log
   ```

2. **Test locally**
   ```bash
   # Reproduce on development environment
   docker-compose up
   docker-compose exec web python manage.py shell
   
   # Test database connection
   python manage.py dbshell
   ```

3. **Identify root cause**
   - Database connection issue?
   - Code bug in recent commit?
   - Configuration missing?
   - External API down?
   - Resource exhaustion?

4. **Update team**
   ```
   Status: ROOT CAUSE IDENTIFIED
   Cause: Database migration failed
   Fix: Rolling back to previous version
   ETA: 10 minutes
   ```

### 1.3 Resolution Phase (30 Minutes – 2 Hours)

**If code issue:**
1. Create hotfix branch: `git checkout -b hotfix/issue-name`
2. Make minimal changes
3. Test locally thoroughly
4. Push and create PR with `[HOTFIX]` label
5. Get emergency code review
6. Merge to main
7. Deploy immediately

**If database issue:**
1. Check migrations: `python manage.py showmigrations`
2. Restore from backup if needed
3. Run migrations fresh: `python manage.py migrate`
4. Verify data integrity

**If configuration issue:**
1. Check `.env` file: `cat .env | grep ISSUE_NAME`
2. Verify all required variables are set
3. Restart services: `docker-compose restart web`

### 1.4 Verification & Communication

1. **Test fix thoroughly**
   - Reproduce original issue → Should fail before, pass after
   - Check related features for regressions
   - Monitor logs for new errors

2. **Update team**
   ```
   Status: RESOLVED
   Fix: [Description of fix]
   Deployed at: [timestamp]
   Monitoring: [How we're watching]
   ```

3. **Schedule post-mortem**
   - If critical issue: Within 24 hours
   - If high severity: Within 1 week
   - Document root cause and prevention

---

## 2. Common Issues & Quick Fixes

### 2.1 App Won't Start

**Symptoms:** `python manage.py runserver` fails

**Troubleshooting:**
```bash
# Check Python version
python --version  # Should be 3.10+

# Check imports
python -c "import django; print(django.__version__)"

# Check database connection
python manage.py dbshell  # Should open PostgreSQL prompt

# Check for recent commits
git log --oneline -5

# Try fresh migration
python manage.py migrate --plan
python manage.py migrate
```

**Common Causes:**
| Issue | Fix |
|-------|-----|
| Dependency missing | `pip install -r requirements.txt` |
| Database offline | `docker-compose up -d postgres` |
| Migration failed | `python manage.py migrate --fake [app_name]` |
| Import error in code | Check recent commits for syntax errors |

### 2.2 Database Connection Failed

**Symptoms:** `django.db.utils.OperationalError: FATAL: password authentication failed`

**Troubleshooting:**
```bash
# Check PostgreSQL running
docker-compose ps  # Look for postgres status

# Check connection string
echo $DATABASE_URL  # Should be postgresql://user:pass@host/db

# Test connection directly
psql $DATABASE_URL

# Restart database
docker-compose restart postgres

# Check logs
docker-compose logs postgres
```

**Common Causes:**
| Issue | Fix |
|-------|-----|
| Wrong password in .env | Verify DATABASE_URL in .env |
| PostgreSQL not running | `docker-compose up -d postgres` |
| Port already in use | Check: `lsof -i :5432` |
| Database doesn't exist | Create it: `createdb zumodra` |

### 2.3 TemplateDoesNotExist Error

**Symptoms:** `TemplateDoesNotExist: users/list.html`

**Troubleshooting:**
```bash
# Find the template
find templates/ -name "list.html"

# Check TEMPLATES setting
python manage.py shell
>>> from django.conf import settings
>>> settings.TEMPLATES
# Should show template directories

# List all templates
find templates/ -type f -name "*.html" | sort

# Check app is in INSTALLED_APPS
grep -n "apps.users" zumodra/settings.py
```

**Common Causes:**
| Issue | Fix |
|-------|-----|
| Template doesn't exist | Create file in correct path |
| Wrong path in view | Use `'users/list.html'` not `'users-list'` |
| Template directory not configured | Add to TEMPLATES['DIRS'] |
| App not in INSTALLED_APPS | Add to settings.py |

### 2.4 Static Files Not Loading

**Symptoms:** CSS/JS files return 404, site looks broken

**Troubleshooting:**
```bash
# Collect static files
python manage.py collectstatic

# Check STATIC_URL and STATIC_ROOT
python manage.py shell
>>> from django.conf import settings
>>> settings.STATIC_URL
>>> settings.STATIC_ROOT

# Check file exists
ls -la static/css/

# For production
# Check nginx configuration
cat /etc/nginx/conf.d/zumodra.conf
# Should have correct static files path
```

**Common Causes:**
| Issue | Fix |
|-------|-----|
| collectstatic not run | `python manage.py collectstatic` |
| Wrong STATIC_URL | Usually `/static/` |
| Nginx not configured | Setup static files directive |
| Files in wrong location | Put in `zumodra/static/` |

### 2.5 API Returns 500 Error

**Symptoms:** API endpoint returns 500 Internal Server Error

**Troubleshooting:**
```bash
# Check Django error log
tail -100 logs/django.log | grep "Exception\|ERROR\|Traceback"

# Check Sentry
# Visit https://sentry.io and look for recent errors

# Test endpoint with curl
curl -H "Authorization: Bearer TOKEN" http://localhost:8000/api/v1/users/

# Check database for issues
python manage.py shell
>>> from apps.users.models import User
>>> User.objects.count()  # Can we query the model?

# Check serializer
# Try different queries to isolate issue
```

**Common Causes:**
| Issue | Fix |
|-------|-----|
| Serializer error | Check `serializers.py` for field errors |
| Model error | Check `models.py` for missing fields |
| Database error | Check database is responsive |
| Permission error | Check `permission_classes` in view |
| Missing field in response | Add to serializer.Meta.fields |

### 2.6 Login Not Working

**Symptoms:** Can't login, authentication fails

**Troubleshooting:**
```bash
# Check database has user
python manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.filter(email='test@test.com').exists()

# Check password
>>> user = User.objects.get(email='test@test.com')
>>> user.check_password('password123')  # Should return True

# Check authentication backend
grep "AUTHENTICATION_BACKENDS" zumodra/settings.py

# Check session settings
grep "SESSION_" zumodra/settings.py

# Test authentication directly
python manage.py shell
>>> from django.contrib.auth import authenticate
>>> user = authenticate(username='test@test.com', password='password123')
>>> print(user)
```

**Common Causes:**
| Issue | Fix |
|-------|-----|
| User doesn't exist | Create user: `createsuperuser` |
| Wrong password | Reset password in Django admin |
| Email not username | Use email if custom auth backend |
| Session expired | Clear browser cookies |
| CSRF token missing | Add `{% csrf_token %}` to form |

---

## 3. Performance Issues

### 3.1 App is Slow

**Diagnosis:**
```bash
# Check load
top -b -n 1 | head -10  # CPU usage

# Check memory
free -h  # RAM usage

# Check disk
df -h  # Disk space

# Check database
docker-compose exec postgres psql -U zumodra -d zumodra -c "SELECT count(*) FROM information_schema.tables;"
```

**Common Causes & Fixes:**
| Cause | Fix |
|-------|-----|
| N+1 queries | Use `select_related()` or `prefetch_related()` |
| Unindexed queries | Add indexes: `models.Index(fields=['email'])` |
| Large result sets | Add pagination: `paginate_by = 50` |
| Blocking operation | Offload to Celery task |
| Memory leak | Restart service: `docker-compose restart web` |
| Database connections exhausted | Increase pool size in settings |

### 3.2 Database Slow

**Check slow queries:**
```sql
-- Log slow queries
SET log_statement = 'all';
SET log_min_duration_statement = 1000;  -- 1 second

-- View slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Analyze query
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'test@test.com';
```

**Optimization:**
```python
# ❌ SLOW - N+1 query
users = User.objects.all()
for user in users:
    print(user.profile.bio)  # Each user = 1 query

# ✅ FAST - Use select_related
users = User.objects.select_related('profile').all()
for user in users:
    print(user.profile.bio)  # 1 query total
```

---

## 4. Security Incident Response

### 4.1 Suspected Breach

**If unauthorized access suspected:**

1. **Immediate steps:**
   - Notify security specialist
   - Check access logs: `tail -f /var/log/auth.log`
   - Check for new users: `SELECT * FROM auth_user WHERE date_joined > NOW() - INTERVAL '1 hour';`
   - Change database password

2. **Investigation:**
   - Review git commits for suspicious changes
   - Check for data exfiltration
   - Scan for malware: `sudo rkhunter --check`

3. **Remediation:**
   - Rotate all credentials
   - Reset SSH keys
   - Force password reset for all users
   - Review security logs
   - Deploy fix immediately

4. **Communication:**
   - Notify affected users
   - Post mortem within 24 hours
   - Document incident response

### 4.2 Code Injection / XSS

**If code injection suspected:**

```bash
# Check commit history
git log --oneline -20

# Scan for suspicious code patterns
grep -r "eval\|exec\|system\|shell" apps/ --include="*.py"
grep -r "innerHTML\|dangerouslySetInnerHTML" --include="*.js"

# Run security scanner
bandit -r apps/

# Check for command injection
grep -r "os.system\|subprocess" apps/ --include="*.py"
```

---

## 5. Escalation Policy

**If issue not resolved within time:**

| Time | Action |
|------|--------|
| 5 min | Notify supervisor |
| 15 min | Escalate to senior dev |
| 30 min | Escalate to all available devs |
| 1 hour | Consider rollback |
| 2 hours | Prepare manual fix or major change |

**Rollback procedure:**
```bash
# If deployed version has critical bug
git log --oneline -5

# Checkout previous working version
git checkout [previous_commit]

# Run migrations backward if needed
python manage.py migrate [app_name] [migration_number]

# Deploy rolled-back version
docker-compose build
docker-compose up -d
```

---

## 6. Post-Incident Review (After Fix)

**Within 24 hours of critical issue:**

1. **Document what happened**
   - Timeline of issue
   - Root cause
   - How it was discovered
   - Resolution steps

2. **Analyze prevention**
   - Why wasn't it caught in testing?
   - What monitoring missed it?
   - What process improvement needed?

3. **Implement prevention**
   - Add test case
   - Add monitoring alert
   - Update documentation
   - Deploy prevention

4. **Share learnings**
   - Team meeting to discuss
   - Update runbook
   - Training if needed

---

## 7. Monitoring & Alerting Setup

**Services to monitor:**

```bash
# Web service health check
curl -f http://localhost:8000/health/ || alert

# Database connectivity
pg_isready -h localhost -p 5432 || alert

# Disk space
df -h / | grep -E "9[0-9]|100" && alert

# Error rate (from Sentry)
# Alert if >100 errors in 5 minutes

# Response time
# Alert if avg >1000ms

# Memory usage
# Alert if >85% used
```

---

**Remember: Stay calm, communicate clearly, follow procedures. Most issues have simple fixes.**

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** All Team Members