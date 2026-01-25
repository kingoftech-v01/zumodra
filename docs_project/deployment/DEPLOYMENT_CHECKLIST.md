# 🚀 Bidirectional Sync - Deployment Checklist

## ✅ What's Been Completed

### Phase 1 & 2: Job Sync Infrastructure
- ✅ [core/sync/base.py](core/sync/base.py) - Base sync service (480 lines)
- ✅ [core/sync/job_sync.py](core/sync/job_sync.py) - Job sync logic (188 lines)
- ✅ [tenants/models.py](tenants/models.py) - Added PublicJobCatalog model (26 fields, 6 indexes)
- ✅ [ats/signals.py](ats/signals.py) - Job sync signals (post_save, post_delete)
- ✅ [ats/tasks.py](ats/tasks.py) - 3 Celery tasks (sync, remove, bulk_sync)
- ✅ [main/views.py](main/views.py) - Fixed careers view to use PublicJobCatalog
- ✅ [templates/careers/browse_jobs.html](templates/careers/browse_jobs.html) - Updated template fields

### Phase 3: Provider Sync
- ✅ [core/sync/provider_sync.py](core/sync/provider_sync.py) - Provider sync logic (321 lines)
- ✅ [tenants/models.py](tenants/models.py) - Added PublicProviderCatalog model (21 fields, 5 indexes)
- ✅ [services/signals.py](services/signals.py) - Provider sync signals
- ✅ [services/tasks.py](services/tasks.py) - 3 Celery tasks for providers
- ✅ [services/views.py](services/views.py) - Fixed browse_providers to use PublicProviderCatalog
- ✅ [templates/services/browse_providers.html](templates/services/browse_providers.html) - Updated template with badges

### Phase 5: Management & Documentation
- ✅ [core/management/commands/sync_public_catalogs.py](core/management/commands/sync_public_catalogs.py) - Bulk sync command
- ✅ [tenants/migrations/0002_add_public_job_provider_catalogs.py](tenants/migrations/0002_add_public_job_provider_catalogs.py) - Migration file (15KB)
- ✅ [BIDIRECTIONAL_SYNC_IMPLEMENTATION.md](BIDIRECTIONAL_SYNC_IMPLEMENTATION.md) - Full implementation guide
- ✅ [TEMPLATE_UPDATES.md](TEMPLATE_UPDATES.md) - Template field mapping reference

## 📋 Deployment Steps

### Step 1: Nuclear Cleanup (You Execute This)

```bash
# Stop all containers
docker compose down -v

# Remove all volumes (clean slate)
docker volume prune -f

# Start fresh
docker compose up -d
```

### Step 2: Monitor Migration (Automatic)

The migrations will run automatically via entrypoint.sh. Watch the logs:

```bash
# Watch migration progress
docker compose logs -f web | grep -E "migrate_schemas|PublicJobCatalog|PublicProviderCatalog"
```

**Expected output:**
```
[INFO] Step 1/4: Migrating shared schema (public)...
[INFO] Running migration tenants.0002_add_public_job_provider_catalogs...
[INFO] Shared schema migrations completed successfully!
[INFO] Step 2/4: Migrating existing tenant schemas...
```

### Step 3: Verify Tables Created

```bash
# Check public schema tables
docker compose exec db psql -U postgres -d zumodra -c "\dt public.tenants_*"
```

**Expected output:**
```
 public | tenants_publicjobcatalog      | table | postgres
 public | tenants_publicprovidercatalog | table | postgres
 public | tenants_tenant                | table | postgres
```

### Step 4: Populate Catalogs

Choose one method:

**Option A: Async (Recommended for large datasets)**
```bash
docker compose exec web python manage.py sync_public_catalogs --async
```

**Option B: Synchronous (Shows progress)**
```bash
docker compose exec web python manage.py sync_public_catalogs
```

**Expected output:**
```
======================================================================
  Sync Public Catalogs
======================================================================
Mode: ASYNC
Catalog: all
Tenants: 2

[1/2] Processing: Demo Company (democompany)
  Jobs: 15 eligible
    ➤ Queued async task for 15 jobs
  Providers: 8 eligible
    ➤ Queued async task for 8 providers

[2/2] Processing: Freelancer Hub (freelancerhub)
  Jobs: 5 eligible
    ➤ Queued async task for 5 jobs
  Providers: 12 eligible
    ➤ Queued async task for 12 providers

======================================================================
  Summary
======================================================================
Tenants processed: 2
Duration: 2.34s

Jobs:
  ✓ Synced:  20
  ⊘ Skipped: 0
  ✗ Errors:  0
Providers:
  ✓ Synced:  20
  ⊘ Skipped: 0
  ✗ Errors:  0

======================================================================
✓ Done!
```

### Step 5: Test Pages

```bash
# Test careers page (should work now - was crashing before)
curl -I http://localhost:8002/careers/

# Expected: HTTP/1.1 200 OK

# Test browse providers
curl -I http://localhost:8002/browse-freelancers/

# Expected: HTTP/1.1 200 OK
```

### Step 6: Visual Testing

Open in browser and verify:

**Careers Page** (`http://localhost:8002/careers/`)
- [ ] Page loads without errors
- [ ] Jobs from all tenants visible
- [ ] Job titles, company names display correctly
- [ ] Location, job type, salary visible
- [ ] Skills show as tags
- [ ] "Posted X ago" shows correct time
- [ ] Search filter works
- [ ] Category filter works
- [ ] Pagination works
- [ ] "View Details & Apply" links work

**Browse Freelancers** (`http://localhost:8002/browse-freelancers/`)
- [ ] Page loads without errors
- [ ] Providers from all tenants visible
- [ ] Display names, avatars show
- [ ] Completed jobs count displays
- [ ] Ratings and reviews visible
- [ ] Verified badge shows (if applicable)
- [ ] Location badge shows
- [ ] Available badge shows (if accepting projects)
- [ ] Search filter works
- [ ] Pagination works
- [ ] "View Profile" links work

### Step 7: Test Bidirectional Sync

**Test Job Sync:**
```bash
# 1. Create a job in tenant schema with published_on_career_page=True
# 2. Check it appears in PublicJobCatalog
docker compose exec web python manage.py shell << EOF
from tenants.models import PublicJobCatalog
print(f"Jobs in catalog: {PublicJobCatalog.objects.count()}")
EOF

# 3. Update job to published_on_career_page=False
# 4. Verify it's removed from catalog
```

**Test Provider Sync:**
```bash
# 1. Create provider with marketplace_enabled=True
# 2. Check it appears in PublicProviderCatalog
docker compose exec web python manage.py shell << EOF
from tenants.models import PublicProviderCatalog
print(f"Providers in catalog: {PublicProviderCatalog.objects.count()}")
EOF

# 3. Update provider to marketplace_enabled=False
# 4. Verify it's removed from catalog
```

### Step 8: Monitor Celery Tasks

```bash
# Check Celery is processing sync tasks
docker compose logs -f celery | grep -E "sync_job_to_catalog|sync_provider_to_catalog"
```

**Expected output:**
```
[INFO] Task ats.sync_job_to_catalog[abc-123] succeeded
[INFO] Task services.sync_provider_to_catalog[def-456] succeeded
```

## 🔍 Verification Commands

### Check Catalog Counts
```bash
docker compose exec web python manage.py shell << EOF
from tenants.models import PublicJobCatalog, PublicProviderCatalog
from ats.models import JobPosting
from services.models import ServiceProvider
from tenants.models import Tenant
from tenants.context import tenant_context

for tenant in Tenant.objects.exclude(schema_name='public'):
    with tenant_context(tenant):
        eligible_jobs = JobPosting.objects.filter(
            published_on_career_page=True,
            is_internal_only=False,
            status='open'
        ).count()

        eligible_providers = ServiceProvider.objects.filter(
            marketplace_enabled=True,
            is_active=True
        ).count()

    catalog_jobs = PublicJobCatalog.objects.filter(tenant=tenant).count()
    catalog_providers = PublicProviderCatalog.objects.filter(tenant=tenant).count()

    print(f"\n{tenant.name}:")
    print(f"  Jobs: {eligible_jobs} eligible → {catalog_jobs} in catalog")
    print(f"  Providers: {eligible_providers} eligible → {catalog_providers} in catalog")
EOF
```

### Check Recent Sync Activity
```bash
docker compose exec web python manage.py shell << EOF
from tenants.models import PublicJobCatalog, PublicProviderCatalog
from django.utils import timezone
from datetime import timedelta

recent = timezone.now() - timedelta(hours=1)

recent_jobs = PublicJobCatalog.objects.filter(synced_at__gte=recent).count()
recent_providers = PublicProviderCatalog.objects.filter(synced_at__gte=recent).count()

print(f"Synced in last hour:")
print(f"  Jobs: {recent_jobs}")
print(f"  Providers: {recent_providers}")
EOF
```

### Check Database Indexes
```bash
docker compose exec db psql -U postgres -d zumodra << EOF
-- Job catalog indexes
SELECT indexname FROM pg_indexes
WHERE tablename = 'tenants_publicjobcatalog'
ORDER BY indexname;

-- Provider catalog indexes
SELECT indexname FROM pg_indexes
WHERE tablename = 'tenants_publicprovidercatalog'
ORDER BY indexname;
EOF
```

**Expected: 6 indexes for jobs, 5 indexes for providers**

## 🐛 Troubleshooting

### Issue: Migration fails

```bash
# Check migration status
docker compose exec web python manage.py showmigrations tenants

# If 0002 is not applied, run manually
docker compose exec web python manage.py migrate_schemas --shared
```

### Issue: Catalog is empty after sync

```bash
# Check if source data exists
docker compose exec web python manage.py shell << EOF
from ats.models import JobPosting
from tenants.context import tenant_context
from tenants.models import Tenant

for tenant in Tenant.objects.exclude(schema_name='public'):
    with tenant_context(tenant):
        published_jobs = JobPosting.objects.filter(
            published_on_career_page=True,
            is_internal_only=False,
            status='open'
        ).count()
        print(f"{tenant.name}: {published_jobs} published jobs")
EOF

# If jobs exist but catalog empty, run sync again
docker compose exec web python manage.py sync_public_catalogs
```

### Issue: Page still crashes

```bash
# Check exact error
docker compose logs web | tail -50

# Common issues:
# 1. Migration not applied → run migrate_schemas --shared
# 2. View still using old model → check main/views.py line 22 uses PublicJobCatalog
# 3. Template using old fields → check template uses published_at not created_at
```

### Issue: Celery tasks not running

```bash
# Check Celery is running
docker compose ps celery

# Check RabbitMQ connection
docker compose logs celery | grep "Connected to amqp"

# Restart Celery if needed
docker compose restart celery
```

## 📊 Success Criteria

| Metric | Target | Check Command |
|--------|--------|---------------|
| Migrations applied | ✓ 0002 | `docker compose exec web python manage.py showmigrations tenants` |
| Tables created | 2 new tables | `docker compose exec db psql -U postgres -d zumodra -c "\dt public.tenants_public*"` |
| Indexes created | 11 total (6+5) | See "Check Database Indexes" above |
| Jobs synced | >0 if data exists | `docker compose exec web python manage.py shell -c "from tenants.models import PublicJobCatalog; print(PublicJobCatalog.objects.count())"` |
| Providers synced | >0 if data exists | `docker compose exec web python manage.py shell -c "from tenants.models import PublicProviderCatalog; print(PublicProviderCatalog.objects.count())"` |
| Careers page | 200 OK | `curl -I http://localhost:8002/careers/` |
| Providers page | 200 OK | `curl -I http://localhost:8002/browse-freelancers/` |
| Celery tasks | Succeeding | `docker compose logs celery \| grep "succeeded"` |

## 📚 Additional Resources

- [BIDIRECTIONAL_SYNC_IMPLEMENTATION.md](BIDIRECTIONAL_SYNC_IMPLEMENTATION.md) - Full technical documentation
- [TEMPLATE_UPDATES.md](TEMPLATE_UPDATES.md) - Template field mapping reference
- `/home/king/.claude/plans/parallel-petting-ladybug.md` - Original implementation plan

## 🎯 Next Steps After Deployment

1. **Monitor Performance**
   - Watch Celery task queue size
   - Monitor database query performance on catalog tables
   - Check page load times for /careers/ and /browse-freelancers/

2. **Set Up Monitoring** (Optional - Phase 6)
   - Add Celery task metrics to monitoring dashboard
   - Set up alerts for sync failures
   - Track catalog vs source data discrepancies

3. **Future Enhancements** (Phase 4 & 6)
   - Convert existing service sync to async Celery
   - Add automated cleanup tasks for stale entries
   - Implement integrity verification scheduled task
   - Create admin dashboard for catalog statistics

## ✅ Final Checklist

Before marking deployment complete, verify:

- [ ] Nuclear cleanup completed
- [ ] Migrations ran successfully
- [ ] PublicJobCatalog table exists with 6 indexes
- [ ] PublicProviderCatalog table exists with 5 indexes
- [ ] Bulk sync completed without errors
- [ ] `/careers/` page loads (200 OK)
- [ ] `/browse-freelancers/` page loads (200 OK)
- [ ] Jobs visible on careers page
- [ ] Providers visible on browse page
- [ ] Search filters work
- [ ] Pagination works
- [ ] Detail links work
- [ ] Celery tasks running
- [ ] No errors in logs

---

**Status**: Ready for deployment! 🚀

Execute Step 1 (nuclear cleanup) and monitor the automatic deployment process.
