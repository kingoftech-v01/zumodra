# Filter Implementation Guide - FreelanHub Integration

## Overview

This guide documents the implementation of FreelanHub-based filter components for all 6 browse pages.

## ✅ Completed

### Companies Filter
- **File**: `templates/careers/components/_filter_companies.html`
- **Based on**: `freelanhub_reference/Main/freelanhub-html/employers-default.html` (lines 1923-2017)
- **Filters**:
  - Search (text input)
  - Location (dropdown with search)
  - Category/Industry (dropdown with search)
  - Radius (slider, 1-100km)
  - Company Size (dropdown)

## 🔧 Remaining Work

### 1. Jobs Filter Component

**File to create**: `templates/careers/components/_filter_jobs.html`
**Based on**: `freelanhub_reference/Main/freelanhub-html/jobs-default.html` (lines 2106-2321)

**Required Filters**:
1. **Search** - text input for "Skill, Industry"
2. **Location** - dropdown with search (Africa, Americas, Antarctica, Asia, Europe, Oceania, Australia and New Zealand)
3. **Category** - dropdown with search (Accounting & Consulting, Admin Support, Customer Service, Design & Creative, Data Science & Analytics, Engineering & Architecture, IT & Networking)
4. **Job Types** - dropdown (Freelance, Full Time, Internship, On-site, Part Time, Remote, Temporary)
5. **Filter by Salary** - dual range slider (min/max with number inputs, $0-$3000)
6. **Filter by Hourly** - two number inputs (min/max with $ prefix)
7. **Radius** - single range slider (1-100km)
8. **Industry** - dropdown (Development, Management, Finance, Html & Css, Seo, Banking, Design Graphics)
9. **Career Level** - dropdown (Manager, Officer, Student, Executive, Others)
10. **Experience Level** - checkboxes (Entry Level, Intermediate, Expert)
11. **Job Alert Section** (separate form):
    - Title input
    - Email frequency dropdown (Daily, Weekly, Fortnightly, Monthly, Biannually, Annually)
    - "Save Candidate Alert" button

**Form Structure**:
```html
<div class="modal">
    <div class="sidebar min-[390px]:w-[348px] w-[80vw] h-full bg-white">
        <div class="block_filter full-height py-4 px-6">
            <form method="get" action="">
                <!-- All filters here -->
                <button type="submit" class="button-main w-full mt-6 text-center">Find Jobs</button>
            </form>
            <form class="md:mt-10 mt-7" method="post" action="">
                <h6 class="heading6">Job Alert</h6>
                <!-- Job alert fields -->
                <button type="submit" class="button-main w-full mt-6 text-center">Save Candidate Alert</button>
            </form>
        </div>
    </div>
</div>
```

### 2. Projects Filter Component

**File to create**: `templates/careers/components/_filter_projects.html`
**Based on**: `freelanhub_reference/Main/freelanhub-html/project-default.html` (lines 1990-2162)

**Required Filters**:
1. **Search** - text input for "Job title, key words or company"
2. **Category** - dropdown with search (Accounting & Consulting, Admin Support, Customer Service, Design & Creative, Data Science & Analytics, Engineering & Architecture, IT & Networking)
3. **Experience Level** - checkboxes (Entry Level, Intermediate, Expert)
4. **Filter by Fixed-Price** - dual range slider (min/max with number inputs, $0-$3000)
5. **Filter by Hourly** - two number inputs (min/max with $ prefix)
6. **Client Location** - dropdown with search (Africa, Americas, Antarctica, Asia, Europe, Oceania, Australia and New Zealand)
7. **Client Timezone** - dropdown with search:
   - (UTC-11:00) Midway Island
   - (UTC-10:00) Hawaii
   - (UTC-08:00) Alaska
   - (UTC-07:00) Pacific Time
   - (UTC-07:00) Arizona
   - (UTC-06:00) Mountain Time
   - (UTC-05:00) Eastern Time
8. **English Level** - dropdown (Basic, Conversational, Fluent, Native Or Bilingual, Professional)

**Form Structure**:
```html
<div class="modal">
    <div class="sidebar min-[390px]:w-[348px] w-[80vw] h-full bg-white">
        <form method="get" action="" class="h-full">
            <div class="block_filter h-full py-4 px-6">
                <!-- All filters here -->
            </div>
            <div class="block_btn absolute right-0 bottom-0 left-0 z-[1] bg-white h-[68px] py-2.5 px-6">
                <button type="submit" class="button-main w-full text-center">Find Projects</button>
            </div>
        </form>
    </div>
</div>
```

### 3. Update Browse Templates

Replace the current filter sidebar includes in all 6 templates:

**Companies Templates**:
```django
{# OLD #}
{% include "careers/components/_filter_sidebar.html" with ... %}

{# NEW #}
{% include "careers/components/_filter_companies.html" %}
```

**Jobs Templates**:
```django
{# NEW #}
{% include "careers/components/_filter_jobs.html" %}
```

**Projects Templates**:
```django
{# NEW #}
{% include "careers/components/_filter_projects.html" %}
```

### 4. Update Views with Filter Data

**careers/template_views.py** - Add context data to all browse views:

```python
# BrowseCompaniesView / BrowseCompaniesMapView
def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)

    # Get unique locations from database
    context['locations'] = Tenant.objects.filter(
        status='active'
    ).values_list('city', flat=True).distinct().order_by('city')

    # Get unique industries
    context['industries'] = Tenant.objects.filter(
        status='active'
    ).values_list('industry', flat=True).distinct().order_by('industry')

    # Capture filter values
    context['selected_location'] = self.request.GET.get('location', '')
    context['selected_industry'] = self.request.GET.get('industry', '')
    context['selected_size'] = self.request.GET.get('company_size', '')
    context['radius'] = self.request.GET.get('radius', '100')
    context['search'] = self.request.GET.get('search', '')

    return context
```

```python
# BrowseJobsView / BrowseJobsMapView
def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)

    # Get unique locations, categories, industries
    context['locations'] = JobPosting.objects.filter(
        status='open'
    ).values_list('location_city', flat=True).distinct().order_by('location_city')

    context['categories'] = JobPosting.objects.filter(
        status='open'
    ).values_list('category', flat=True).distinct().order_by('category')

    context['industries'] = JobPosting.objects.filter(
        status='open'
    ).values_list('industry', flat=True).distinct().order_by('industry')

    # Capture filter values
    context['selected_location'] = self.request.GET.get('location', '')
    context['selected_category'] = self.request.GET.get('category', '')
    context['selected_job_type'] = self.request.GET.get('job_type', '')
    context['selected_industry'] = self.request.GET.get('industry', '')
    context['selected_career_level'] = self.request.GET.get('career_level', '')
    context['selected_experience'] = self.request.GET.getlist('experience')
    context['salary_min'] = self.request.GET.get('salary_min', '0')
    context['salary_max'] = self.request.GET.get('salary_max', '300000')
    context['hourly_min'] = self.request.GET.get('hourly_min', '')
    context['hourly_max'] = self.request.GET.get('hourly_max', '')
    context['radius'] = self.request.GET.get('radius', '100')
    context['search'] = self.request.GET.get('search', '')

    return context
```

```python
# BrowseProjectsView / BrowseProjectsMapView
def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)

    # Get unique categories and locations from services
    context['categories'] = ServiceCategory.objects.values_list(
        'name', flat=True
    ).distinct().order_by('name')

    context['locations'] = ['Africa', 'Americas', 'Antarctica', 'Asia', 'Europe', 'Oceania', 'Australia and New Zealand']

    context['timezones'] = [
        '(UTC-11:00) Midway Island',
        '(UTC-10:00) Hawaii',
        '(UTC-08:00) Alaska',
        '(UTC-07:00) Pacific Time',
        '(UTC-07:00) Arizona',
        '(UTC-06:00) Mountain Time',
        '(UTC-05:00) Eastern Time',
    ]

    context['english_levels'] = ['Basic', 'Conversational', 'Fluent', 'Native Or Bilingual', 'Professional']

    # Capture filter values
    context['selected_category'] = self.request.GET.get('category', '')
    context['selected_location'] = self.request.GET.get('location', '')
    context['selected_timezone'] = self.request.GET.get('timezone', '')
    context['selected_english_level'] = self.request.GET.get('english_level', '')
    context['selected_experience'] = self.request.GET.getlist('experience')
    context['price_min'] = self.request.GET.get('price_min', '0')
    context['price_max'] = self.request.GET.get('price_max', '3000')
    context['hourly_min'] = self.request.GET.get('hourly_min', '')
    context['hourly_max'] = self.request.GET.get('hourly_max', '')
    context['search'] = self.request.GET.get('search', '')

    return context
```

### 5. Apply Filters to Querysets

Update `get_queryset()` methods in all browse views to actually filter based on query parameters:

```python
def get_queryset(self):
    queryset = super().get_queryset()

    # Search
    search = self.request.GET.get('search', '')
    if search:
        queryset = queryset.filter(
            Q(name__icontains=search) | Q(industry__icontains=search)
        )

    # Location
    location = self.request.GET.get('location', '')
    if location:
        queryset = queryset.filter(city__icontains=location)

    # Industry
    industry = self.request.GET.get('industry', '')
    if industry:
        queryset = queryset.filter(industry__icontains=industry)

    # Company Size
    company_size = self.request.GET.get('company_size', '')
    if company_size:
        # Parse size range (e.g., "1-5 employees" -> filter by employee_count)
        # This requires an employee_count field on Tenant model
        pass

    # Radius filtering requires geolocation (already implemented via geocoding)
    radius = self.request.GET.get('radius', '')
    user_lat = self.request.GET.get('lat', '')
    user_lng = self.request.GET.get('lng', '')
    if radius and user_lat and user_lng:
        from django.contrib.gis.geos import Point
        from django.contrib.gis.measure import D
        from django.contrib.gis.db.models.functions import Distance

        user_location = Point(float(user_lng), float(user_lat), srid=4326)
        queryset = queryset.annotate(
            distance=Distance('location_coordinates', user_location)
        ).filter(distance__lte=D(km=float(radius))).order_by('distance')

    return queryset
```

## Key Implementation Notes

1. **Dropdown Sync**: Each dropdown needs JavaScript to sync the selected value with a hidden input field that gets submitted with the form.

2. **Range Sliders**: Use the existing FreelanHub JavaScript for dual-range sliders. The progress bar updates dynamically.

3. **Checkboxes**: For multi-select filters like "Experience Level", use `getlist()` in the view.

4. **Form Submission**: All filters submit via GET to preserve state in URL for sharing/bookmarking.

5. **Filter Preservation**: When paginating or changing views, all current filters must be preserved in the URL.

6. **Search with Dropdowns**: Dropdowns like Location and Category include an internal search input to filter the list of options.

## Testing Checklist

- [ ] Companies filter: All 5 fields work and filter results
- [ ] Jobs filter: All 11 fields work and filter results
- [ ] Projects filter: All 8 fields work and filter results
- [ ] Filters persist across pagination
- [ ] Filters persist when switching grid/map view
- [ ] Multiple filters work together (AND logic)
- [ ] Clear all filters button resets everything
- [ ] Radius filter works with geolocation
- [ ] Search input filters results
- [ ] Job alert form submits successfully (jobs only)

## Migration Path

1. Create `_filter_jobs.html` and `_filter_projects.html`
2. Update all 6 browse templates to use new filter components
3. Update all browse views with context data
4. Update querysets to apply filters
5. Test each filter individually
6. Test filter combinations
7. Remove old `_filter_sidebar.html` component

---

**Status**: In Progress
**Last Updated**: 2026-01-12
