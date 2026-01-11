# Deployment Fixes Required

## Issues Found & Fixed

### ✅ Issue 1: URL Namespace Error (FIXED)

**Error:**
```
django.urls.exceptions.NoReverseMatch: 'pages' is not a registered namespace inside 'frontend'
```

**Location:** `templates/components/dashboard/freelanhub_header.html:15`

**Cause:** Reference to non-existent URL `frontend:pages:faqs`

**Fix Applied:**
```django
# BEFORE:
<a href="{% url 'frontend:pages:faqs' %}" class="block">

# AFTER:
<a href="{% url 'frontend:dashboard:help' %}" class="block">
```

**Status:** ✅ Fixed in commit 762a981

---

### ⚠️ Issue 2: Missing Database Table (REQUIRES MIGRATION)

**Error:**
```
django.db.utils.ProgrammingError: relation "accounts_trustscore" does not exist
LINE 1: ..., "accounts_trustscore"."last_calculated_at" FROM "accounts_...
```

**Location:** `accounts/template_views.py:247` (AccountVerificationView)

**Cause:** Database migrations have not been applied for the `accounts` app. The `TrustScore` model exists in code but the table hasn't been created in the database.

**Fix Required:** Run database migrations in Docker environment

**Solution Steps:**

#### Option 1: Run Migrations for All Schemas (Recommended)

```bash
# For multi-tenant setup, run migrations on all schemas
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant
```

#### Option 2: Run Standard Django Migrations (If not using multi-tenant)

```bash
docker compose exec web python manage.py migrate
```

#### Option 3: Run Specific App Migration

```bash
# If you want to target just the accounts app
docker compose exec web python manage.py migrate accounts
```

**Verification:**

After running migrations, verify the table exists:

```bash
docker compose exec web python manage.py shell

# In the Django shell:
from accounts.models import TrustScore
print(TrustScore.objects.count())  # Should not error
```

**Status:** ⚠️ REQUIRES ACTION - Migration needed in production/staging

---

## Complete Pre-Deployment Checklist

### 1. Database Migrations

- [ ] Run `python manage.py migrate_schemas --shared` (for public schema)
- [ ] Run `python manage.py migrate_schemas --tenant` (for all tenant schemas)
- [ ] Verify no pending migrations: `python manage.py showmigrations`
- [ ] Test that `accounts_trustscore` table exists

### 2. Static Files

- [ ] Collect static files: `python manage.py collectstatic --noinput`
- [ ] Verify FreelanHub assets are present in staticfiles/
- [ ] Check that Phosphor Icons CSS is loaded
- [ ] Verify Tailwind CSS is compiled and present

### 3. Template Verification

- [ ] All dashboard pages load without 500 errors
- [ ] Navigation sidebar displays correctly
- [ ] Header dropdown menus work
- [ ] Breadcrumbs render properly
- [ ] Phosphor Icons display correctly (not showing squares/missing glyphs)

### 4. Functionality Testing

#### Dashboard Pages:
- [ ] Main dashboard (`/dashboard/`) loads
- [ ] Help page (`/dashboard/help/`) loads
- [ ] User profile dropdown works

#### ATS Module:
- [ ] Jobs list (`/ats/jobs/`) loads
- [ ] Candidate list (`/ats/candidates/`) loads
- [ ] Pipeline board (`/ats/pipeline/`) loads with drag-and-drop
- [ ] Job creation form (`/ats/jobs/create/`) loads
- [ ] Interview scheduling works

#### Services Module:
- [ ] Service requests list loads
- [ ] Provider dashboard loads
- [ ] Contract management works
- [ ] Proposal submission works

#### Finance Module:
- [ ] Finance dashboard loads
- [ ] Payment history loads
- [ ] Invoice management works
- [ ] Subscription management loads

#### HR Module:
- [ ] Employee directory loads
- [ ] Employee details load
- [ ] Time off requests work
- [ ] Onboarding dashboard loads
- [ ] Organization chart displays

#### Messages:
- [ ] Conversation list loads
- [ ] Real-time chat works
- [ ] WebSocket connections establish

#### Analytics:
- [ ] Analytics dashboard loads
- [ ] Charts render (ApexCharts/Chart.js)
- [ ] Reports list loads

### 5. HTMX Functionality

- [ ] Partial page updates work
- [ ] hx-get requests complete
- [ ] hx-post requests complete with CSRF tokens
- [ ] hx-swap correctly updates target elements
- [ ] Loading indicators display

### 6. Alpine.js Functionality

- [ ] Dropdowns open/close (x-data="{ open: false }")
- [ ] Tabs switch correctly
- [ ] Modals open/close
- [ ] Form validation works
- [ ] Conditional rendering (x-show, x-if) works

### 7. Responsive Design

- [ ] Mobile layout (< 768px) works
- [ ] Tablet layout (768px - 1024px) works
- [ ] Desktop layout (> 1024px) works
- [ ] Hamburger menu works on mobile
- [ ] Sidebar collapses on mobile

### 8. Icons & Assets

- [ ] All Phosphor Icons render correctly
- [ ] No broken image links
- [ ] Logo displays in header
- [ ] Avatars/profile images load
- [ ] File upload previews work

### 9. Forms & CSRF

- [ ] All forms submit successfully
- [ ] CSRF tokens present in POST forms
- [ ] Form validation displays errors
- [ ] Success messages display
- [ ] File uploads work

### 10. i18n/Localization

- [ ] Translation tags ({% trans %}) render
- [ ] Language switching works (if enabled)
- [ ] Date/time formatting correct
- [ ] Currency formatting correct

---

## Known Limitations After Conversion

1. **Dark Mode Removed**: FreelanHub template doesn't include dark mode, so all `dark:` classes were removed during conversion. If dark mode is required, it needs to be re-implemented.

2. **Custom Zumodra CSS**: Some custom `zu-*` classes were preserved where necessary. These may need FreelanHub equivalents if they cause styling conflicts.

3. **Component Alignment**: Some components adapted from FreelanHub may not be pixel-perfect matches if exact equivalents didn't exist in the template.

---

## Rollback Plan (If Needed)

If critical issues are found after deployment:

### Option 1: Git Revert
```bash
# Revert to before FreelanHub restoration
git log --oneline | head -20  # Find commit before restoration started
git revert <commit-hash>  # Revert specific commits
```

### Option 2: Git Reset (Use Carefully)
```bash
# Only if no other changes have been made since restoration
git reset --hard v-pre-dashboard-restore  # Reset to safety tag (if it exists)
```

### Option 3: Backup Restoration
Restore from backup files created during conversion (*.backup, *.bak files)

---

## Production Deployment Commands

### Full Deployment Sequence:

```bash
# 1. Pull latest code
git pull origin main

# 2. Build Docker images (if needed)
docker compose build

# 3. Stop services
docker compose down

# 4. Start services
docker compose up -d

# 5. Run migrations (CRITICAL!)
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant

# 6. Collect static files
docker compose exec web python manage.py collectstatic --noinput

# 7. Restart services
docker compose restart web channels

# 8. Check logs
docker compose logs -f web --tail=100
```

### Health Check:

```bash
# Run health check command
docker compose exec web python manage.py health_check --full

# Check container status
docker compose ps

# Test database connection
docker compose exec web python manage.py dbshell
```

---

## Post-Deployment Monitoring

### Check These Endpoints:

1. **Dashboard:** https://yourdomain.com/dashboard/
2. **ATS:** https://yourdomain.com/ats/jobs/
3. **Services:** https://yourdomain.com/services/
4. **Finance:** https://yourdomain.com/finance/
5. **HR:** https://yourdomain.com/hr/employees/
6. **Messages:** https://yourdomain.com/messages/
7. **Analytics:** https://yourdomain.com/analytics/

### Monitor Logs:

```bash
# Application logs
docker compose logs -f web

# WebSocket logs
docker compose logs -f channels

# Database logs
docker compose logs -f db

# Watch for errors
docker compose logs -f | grep ERROR
```

### Performance Checks:

- [ ] Page load times < 2 seconds
- [ ] API response times < 500ms
- [ ] WebSocket connections establish < 1 second
- [ ] No memory leaks in long-running processes
- [ ] Database query performance acceptable

---

## Support Resources

- **Project Documentation:** `FREELANHUB_RESTORATION_COMPLETE.md`
- **Status Tracking:** `FREELANHUB_RESTORATION_STATUS.md`
- **Conversion Script:** `batch_convert_remaining.py`
- **Git History:** 16 commits documenting all changes

---

**Last Updated:** 2026-01-11
**Status:** Ready for deployment with migration requirement
