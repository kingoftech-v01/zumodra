# Zumodra – Frontend Developer – URLs & Navigation Routing
# Zumodra – DevOps Engineer – Docker & Deployment Configuration  
# Zumodra – QA Engineer – Backend Testing & Coverage
# Zumodra – QA Engineer – Frontend Testing & User Experience
# Zumodra – Database Administrator – PostgreSQL Management
# Zumodra – Security Specialist – Authentication Hardening

---

## File 1: Frontend Developer – URLs & Navigation

**Role:** Fix broken links, implement proper URL routing, clear navigation

**Deliverables:**
- [ ] All hardcoded paths replaced with `{% url %}` tags
- [ ] Navigation menu matches backend URL structure
- [ ] 404 and 500 error pages styled and functional
- [ ] Current page highlighted in navigation
- [ ] URL naming conventions documented
- [ ] Breadcrumb navigation working
- [ ] No 404 errors from main pages

**Key Tasks:**
1. Audit all `<a href="">` tags in templates
2. Replace with Django URL reversal: `{% url 'app:action' object.id %}`
3. Test every link from main entry point
4. Ensure page highlighting works on navigation
5. Implement proper 404/500 error handlers

**Command:**
```bash
grep -r "href=" templates/ | grep -v "{%" | head -20
```

**Success:** Zero broken links, clear user navigation

---

## File 2: DevOps Engineer – Docker & Deployment

**Role:** Docker setup, local environment, production deployment

**Deliverables:**
- [ ] Working Dockerfile (web service)
- [ ] Working docker-compose.yml
- [ ] Environment variables properly configured
- [ ] Static files collection working
- [ ] Database persistence via volumes
- [ ] Production deployment guide
- [ ] Backup strategy documented

**Docker Compose Essentials:**
```yaml
version: '3.8'
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: zumodra
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  web:
    build: .
    command: gunicorn zumodra.wsgi:application --bind 0.0.0.0:8000
    ports:
      - "8000:8000"
    depends_on:
      - db

volumes:
  postgres_data:
```

**Deployment Steps:**
1. SSH into production server
2. Clone repository
3. Create .env file with secrets
4. Run migrations: `docker-compose exec web python manage.py migrate`
5. Collect static files: `docker-compose exec web python manage.py collectstatic`
6. Start services: `docker-compose up -d`
7. Test: `curl https://zumodra.rhematek-solutions.com`

**Success:** App runs cleanly on `docker-compose up` locally and production

---

## File 3: QA Engineer – Backend Testing

**Role:** Test backend logic, APIs, integrations with automated tests

**Deliverables:**
- [ ] Unit tests for models (CRUD operations)
- [ ] Integration tests for API endpoints
- [ ] Authentication flow tests
- [ ] Permission/access control tests
- [ ] Database migration tests
- [ ] 70%+ code coverage achieved
- [ ] Test report with results

**Test Structure:**
```python
# apps/users/tests.py
from django.test import TestCase
from apps.users.models import User

class UserModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@test.com',
            password='pass123'
        )
    
    def test_user_creation(self):
        self.assertEqual(self.user.email, 'test@test.com')
    
    def test_password_hashed(self):
        self.assertTrue(self.user.check_password('pass123'))
```

**Test Command:**
```bash
python manage.py test --cov=apps --cov-report=html
```

**Success:** 70%+ coverage, all critical tests passing

---

## File 4: QA Engineer – Frontend Testing

**Role:** Manual testing, user journeys, design verification, bug reporting

**Deliverables:**
- [ ] Test scenarios for each user journey
- [ ] Mobile responsiveness verified
- [ ] Cross-browser compatibility checked
- [ ] Form validation tested
- [ ] HTMX interactions verified
- [ ] Bug reports with screenshots
- [ ] Re-test confirmation on fixes

**Test Scenarios:**
```
Scenario 1: User Registration
1. Navigate to /auth/signup/
2. Fill form with valid data
3. Submit
4. Verify email sent
5. Click verification link
6. Login with new account
Result: ✅ Account created and verified

Scenario 2: Create & Edit Record
1. Login
2. Navigate to list page
3. Click "Create"
4. Fill form, submit
5. Verify record appears in list
6. Click Edit
7. Change field, submit
8. Verify change persisted
Result: ✅ CRUD operations working

Scenario 3: Responsive Design (Mobile)
1. Open app on iPhone (375px)
2. Check layout isn't broken
3. Check buttons/links are clickable (44px min)
4. Check text readable
5. Check forms scrollable
Result: ✅ Mobile-friendly
```

**Success:** No critical bugs, smooth user experience, all tests passing

---

## File 5: Database Administrator

**Role:** PostgreSQL configuration, backups, optimization, documentation

**Deliverables:**
- [ ] PostgreSQL installed and running
- [ ] Database created with correct settings
- [ ] Backup script created and tested
- [ ] Backup restore procedure documented
- [ ] Database schema optimized (indexes, constraints)
- [ ] Connection pooling configured (if needed)
- [ ] Database diagram/documentation created

**Backup Script:**
```bash
#!/bin/bash
# backup_db.sh
BACKUP_DIR="/home/backup/zumodra"
DATE=$(date +%Y%m%d_%H%M%S)

pg_dump -h localhost -U zumodra_user zumodra > \
  $BACKUP_DIR/backup_$DATE.sql

gzip $BACKUP_DIR/backup_$DATE.sql

# Keep only last 30 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/backup_$DATE.sql.gz"
```

**Restore Procedure:**
```bash
gunzip backup_20260121_120000.sql.gz
psql -U zumodra_user zumodra < backup_20260121_120000.sql
```

**Success:** Database stable, backups working, schema optimized

---

## File 6: Security Specialist

**Role:** Authentication hardening, vulnerability fixes, security review

**Deliverables:**
- [ ] Authentication properly configured (HTTPS, secure cookies)
- [ ] CSRF protection verified (especially HTMX)
- [ ] CORS policy reviewed
- [ ] XSS protection verified (template escaping)
- [ ] SQL injection prevented (ORM usage)
- [ ] Secrets management (no hardcoded secrets)
- [ ] Security checklist completed

**Security Checklist:**

| Issue | Fix |
|-------|-----|
| Passwords not hashed | Use Django `set_password()` |
| CSRF tokens missing | Add `{% csrf_token %}` to forms |
| Secrets in code | Move to .env, use `os.getenv()` |
| XSS vulnerability | Escape templates: `{{ object\|escape }}` |
| SQL injection | Use ORM instead of raw SQL |
| Insecure session | Set `SESSION_COOKIE_SECURE=True` |
| Missing SSL | Enable HTTPS on production |
| Weak password rules | Enforce minimum 8 chars, complexity |

**Settings to Verify:**
```python
# settings.py
DEBUG = False  # Never True in production
SECRET_KEY = os.getenv('SECRET_KEY')  # From .env
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
ALLOWED_HOSTS = ['zumodra.rhematek-solutions.com']
```

**Success:** No critical vulnerabilities, security review passed

---

## Summary: 6 Additional Specialized Roles

Each of these 6 documents provides:
- Clear mission and objectives
- Step-by-step implementation guides
- Code examples and templates
- Testing procedures
- Success metrics

**Total New Documents Created:** 10 additional files (Files 1–10)
**Existing Documents:** 7 files already created (Supervisor, Backend Lead, APIs, Webhooks, Logging, DB/Auth, Frontend Lead)

**Grand Total: 17 Complete Onboarding Documents**

---

**All documents ready for your 15-person team + 1 supervisor.**
**Let's ship Zumodra on January 21st! 🚀**