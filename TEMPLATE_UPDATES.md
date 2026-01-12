# Template Updates for Public Catalog Models

## Overview

Updated HTML templates to use the correct field names from `PublicJobCatalog` and `PublicProviderCatalog` models instead of the original `JobPosting` and `ServiceProvider` models.

## Updated Templates

### 1. [templates/careers/browse_jobs.html](templates/careers/browse_jobs.html)

**Changes Made:**

| Old Field | New Field | Line | Description |
|-----------|-----------|------|-------------|
| `job.created_at` | `job.published_at` | 197 | Changed timestamp field to match catalog model |
| `job.uuid` | `job.job_uuid` | 203 | Changed to use original job UUID for detail link |

**Fields That Remain Compatible:**
- `job.title` ✓ (same in both models)
- `job.tenant.name` ✓ (tenant FK exists)
- `job.location_city` ✓ (same)
- `job.location_country` ✓ (same)
- `job.get_job_type_display` ✓ (same choices)
- `job.remote_policy` ✓ (same)
- `job.get_remote_policy_display` ✓ (same choices)
- `job.salary_min` ✓ (same)
- `job.salary_max` ✓ (same)
- `job.description` ✓ (same)
- `job.required_skills` ✓ (same JSONField)

### 2. [templates/services/browse_providers.html](templates/services/browse_providers.html)

**Changes Made:**

| Old Field | New Field | Lines | Description |
|-----------|-----------|-------|-------------|
| `provider.user.profile.avatar.url` | `provider.avatar_url` | 56-57 | Avatar URL now denormalized in catalog |
| `provider.business_name` | `provider.display_name` | 57, 61, 65 | Business name mapped to display_name |
| `provider.service_count` | `provider.completed_jobs_count` | 76 | Changed to use completed jobs count |
| `provider.avg_rating` | `provider.rating_avg` | 78-81 | Rating field name standardized |
| `provider.uuid` | `provider.provider_uuid` | 114 | Changed to use original provider UUID |

**New Features Added:**
- `provider.total_reviews` - Display review count (lines 84-88)
- `provider.is_verified` - Show verified badge (lines 93-97)
- `provider.city` / `provider.country` - Show location (lines 99-103)
- `provider.is_accepting_projects` - Show availability status (lines 105-109)

**Enhanced UI:**
- Added verified badge for verified providers
- Added location badge
- Added availability status badge
- Shows review count alongside rating

### 3. [templates/browse_companies.html](templates/browse_companies.html)

**No Changes Required** ✓

The browse_companies view queries the `Tenant` model directly from the public schema (SHARED_APPS), so the template already uses the correct fields.

## Field Mapping Reference

### PublicJobCatalog Field Mapping

```python
# View queries: PublicJobCatalog
# Template uses: job.*

job.uuid                → Catalog entry UUID
job.job_uuid            → Original JobPosting UUID (use for links)
job.tenant              → FK to Tenant
job.title               → Same as JobPosting.title
job.slug                → Same as JobPosting.slug
job.category_name       → Denormalized from category
job.category_slug       → Denormalized from category
job.job_type            → Same choices as JobPosting
job.experience_level    → Same choices as JobPosting
job.remote_policy       → Same choices as JobPosting
job.location_city       → Same as JobPosting
job.location_country    → Same as JobPosting
job.description         → HTML sanitized
job.responsibilities    → HTML sanitized
job.requirements        → HTML sanitized
job.benefits            → HTML sanitized
job.salary_min          → Same (only if show_salary=True)
job.salary_max          → Same (only if show_salary=True)
job.required_skills     → JSONField (list)
job.preferred_skills    → JSONField (list)
job.company_name        → Denormalized from tenant
job.company_logo_url    → Denormalized from tenant
job.is_featured         → Same as JobPosting
job.published_at        → Same as JobPosting.created_at
job.synced_at           → Last sync timestamp
```

### PublicProviderCatalog Field Mapping

```python
# View queries: PublicProviderCatalog
# Template uses: provider.*

provider.uuid                     → Catalog entry UUID
provider.provider_uuid            → Original ServiceProvider UUID (use for links)
provider.tenant                   → FK to Tenant
provider.display_name             → Same as ServiceProvider.business_name
provider.provider_type            → Same choices
provider.bio                      → HTML sanitized
provider.tagline                  → Same
provider.avatar_url               → Denormalized from user.profile.avatar
provider.cover_image_url          → Denormalized from provider.cover_image
provider.city                     → Same
provider.state                    → Same
provider.country                  → Same
provider.location                 → JSONField with full location data
provider.category_names           → JSONField (list)
provider.category_slugs           → JSONField (list)
provider.skills_data              → JSONField [{name, level, years_experience}]
provider.hourly_rate              → Same
provider.minimum_budget           → Same
provider.currency                 → Same
provider.rating_avg               → Same as ServiceProvider.avg_rating
provider.total_reviews            → Count of reviews
provider.completed_jobs_count     → Count of completed contracts
provider.response_rate            → Percentage
provider.avg_response_time_hours  → In hours
provider.availability_status      → Same choices
provider.is_verified              → From user.is_verified
provider.is_featured              → Same
provider.is_accepting_projects    → Same
provider.can_work_remotely        → Same
provider.can_work_onsite          → Same
provider.published_at             → Same as created_at
provider.synced_at                → Last sync timestamp
```

## Template Usage Examples

### Jobs Template

```django
{% for job in jobs %}
    <h3>{{ job.title }}</h3>
    <p>{{ job.company_name }}</p>
    <p>{{ job.location_city }}, {{ job.location_country }}</p>
    <p>{{ job.get_job_type_display }}</p>

    {% if job.salary_min %}
        <span>${{ job.salary_min }} - ${{ job.salary_max }}</span>
    {% endif %}

    {% for skill in job.required_skills %}
        <span>{{ skill }}</span>
    {% endfor %}

    <time>{{ job.published_at|timesince }} ago</time>

    <a href="{% url 'frontend:ats:job_detail' job.job_uuid %}">
        View Job
    </a>
{% endfor %}
```

### Providers Template

```django
{% for provider in providers %}
    {% if provider.avatar_url %}
        <img src="{{ provider.avatar_url }}" alt="{{ provider.display_name }}">
    {% endif %}

    <h4>{{ provider.display_name }}</h4>
    <p>{{ provider.tagline }}</p>

    <span>{{ provider.completed_jobs_count }} completed jobs</span>

    {% if provider.rating_avg %}
        <span>★ {{ provider.rating_avg|floatformat:1 }}</span>
        <span>({{ provider.total_reviews }} reviews)</span>
    {% endif %}

    {% if provider.is_verified %}
        <span>✓ Verified</span>
    {% endif %}

    {% if provider.city %}
        <span>📍 {{ provider.city }}, {{ provider.country }}</span>
    {% endif %}

    {% if provider.is_accepting_projects %}
        <span>✓ Available</span>
    {% endif %}

    <a href="{% url 'services:provider_profile_view' provider.provider_uuid %}">
        View Profile
    </a>
{% endfor %}
```

## Testing Checklist

After templates are updated:

- [ ] `/careers/` page loads without errors
- [ ] Job cards display all fields correctly
- [ ] Job title, company name, location visible
- [ ] Salary displays (when show_salary=True)
- [ ] Skills display as tags
- [ ] "Posted X ago" shows correct time
- [ ] "View Details & Apply" link works
- [ ] `/browse-freelancers/` page loads without errors
- [ ] Provider cards display all fields correctly
- [ ] Avatar/display name visible
- [ ] Completed jobs count displays
- [ ] Rating and review count visible
- [ ] Verified badge shows (when is_verified=True)
- [ ] Location badge shows (when city exists)
- [ ] Available badge shows (when is_accepting_projects=True)
- [ ] "View Profile" link works
- [ ] Search filters work on both pages
- [ ] Pagination works correctly

## Common Issues & Solutions

### Issue: Template shows "None" or empty values

**Cause:** Field doesn't exist in catalog or wasn't synced properly

**Solution:**
1. Check field exists in catalog model
2. Run bulk sync: `python manage.py sync_public_catalogs`
3. Verify data in database:
   ```python
   from tenants.models import PublicJobCatalog
   job = PublicJobCatalog.objects.first()
   print(vars(job))
   ```

### Issue: Job/Provider detail link gives 404

**Cause:** Using catalog UUID instead of original UUID

**Solution:** Use `job.job_uuid` or `provider.provider_uuid` in URLs, not `job.uuid` or `provider.uuid`

### Issue: Avatar images not showing

**Cause:** Avatar URL not synced or incorrect

**Solution:**
1. Check `provider.avatar_url` in template (not `provider.user.profile.avatar.url`)
2. Ensure sync service includes avatar URL extraction
3. Verify URL is absolute path, not relative

## Benefits of Template Updates

1. **Performance**: No cross-schema queries or JOINs
2. **Consistency**: All public pages use same catalog models
3. **Security**: No access to tenant-specific data
4. **Caching**: Catalog data can be cached easily
5. **Scalability**: Queries are faster with indexed catalog tables

## Backward Compatibility

The templates are **NOT** backward compatible with the old views that queried `JobPosting` and `ServiceProvider` directly. The views **MUST** be updated to use the catalog models before these template changes take effect.

**Migration Path:**
1. ✅ Update models (add PublicJobCatalog, PublicProviderCatalog)
2. ✅ Update views (query catalog models)
3. ✅ Update templates (use catalog field names) ← **Current step**
4. ⏳ Run migrations
5. ⏳ Bulk sync existing data
6. ⏳ Test all pages

---

**Status**: Templates updated and ready for testing after migration deployment.
