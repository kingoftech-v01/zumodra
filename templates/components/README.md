# Zumodra Unified Component Library

A comprehensive, modular component system for the Zumodra platform, combining dashboard components with marketplace/freelance UI elements.

## Template Architecture

### Base Templates

All public pages extend `base.html`, which automatically includes the canonical header and footer.

| Template | Use Case |
|----------|----------|
| `base.html` | **Canonical** public website base (includes header/footer) |
| `base/dashboard_base.html` | Authenticated dashboard pages |
| `base/base_auth.html` | Login/signup pages |

### Public Page Templates

All public pages follow this pattern:

```django
{% extends "base.html" %}
{% load static i18n %}

{% block title %}{% trans "Page Title" %} - Zumodra{% endblock %}
{% block meta_description %}{% trans "SEO description here" %}{% endblock %}

{% block content %}
    <!-- Page content here -->
{% endblock content %}
```

### Available Public Pages

| Template | Purpose |
|----------|---------|
| `index.html` | Homepage with hero, features, testimonials |
| `about-us.html` | Company story and team |
| `services.html` | Platform services overview |
| `pricing.html` | Subscription plans (Starter, Pro, Business, Enterprise) |
| `faqs.html` | Frequently asked questions with accordion |
| `contact.html` | Contact form and information |
| `become-seller.html` | Freelancer onboarding page |
| `become-buyer.html` | Employer/client onboarding page |
| `privacy-policy.html` | Privacy policy legal page |
| `term-of-use.html` | Terms of use legal page |

---

## Component Architecture

```
templates/components/
├── Dashboard Components
│   ├── header.html              # Dashboard top bar
│   ├── sidebar.html             # Dashboard navigation
│   ├── notification_dropdown.html
│   ├── modal.html / modals.html
│   ├── toast.html
│   ├── data_table.html
│   ├── pagination.html
│   ├── stats_card.html
│   ├── chart_container.html
│   ├── buttons.html
│   ├── cards.html
│   ├── alerts.html
│   ├── loading.html
│   ├── trust_badge.html
│   ├── cv_selector.html
│   ├── theme-toggle.html
│   └── skip-link.html
│
├── Public Website Components
│   ├── public_header.html       # Canonical public site navigation
│   └── public_footer.html       # Canonical public site footer
│
└── marketplace/                 # Marketplace components
    ├── layout/
    │   └── mobile_menu.html     # Mobile navigation drawer
    │
    ├── cards/
    │   ├── job_card.html        # Job listing cards
    │   ├── service_card.html    # Freelance service cards
    │   ├── candidate_card.html  # Candidate/freelancer cards
    │   ├── employer_card.html   # Employer/company cards
    │   ├── project_card.html    # Project listing cards
    │   └── blog_card.html       # Blog post cards
    │
    ├── sections/
    │   ├── breadcrumb.html      # Page header with search
    │   ├── testimonials.html    # Customer testimonials slider
    │   ├── counter_stats.html   # Statistics/metrics display
    │   └── cta_banner.html      # Call-to-action banners
    │
    ├── forms/
    │   └── filter_sidebar.html  # Listing page filter sidebar
    │
    └── common/
        ├── rating.html          # Star ratings display
        ├── wishlist_button.html # Save/bookmark buttons
        └── scroll_to_top.html   # Scroll to top button
```

## Quick Start

### Creating a New Public Page

```django
{% comment %}
=============================================================================
   ZUMODRA PAGE NAME
   =============================================================================

   File: templates/page-name.html
   Purpose: Description of the page

   Extends: base.html (canonical public base template)

   Author: Rhematek Solutions
   Last Updated: YYYY-MM-DD
   =============================================================================
{% endcomment %}

{% extends "base.html" %}
{% load static i18n %}

{% block title %}{% trans "Page Title" %} - Zumodra{% endblock %}
{% block meta_description %}{% trans "SEO description" %}{% endblock %}

{% block content %}
    <section class="your-section">
        <div class="container">
            <h1 class="heading1">{% trans "Your Heading" %}</h1>
        </div>
    </section>
{% endblock content %}
```

### Including Components

```django
{# Public header (automatically included by base.html) #}
{% include "components/public_header.html" %}

{# Marketplace job card #}
{% include "components/marketplace/cards/job_card.html" with job=job %}

{# Rating component #}
{% include "components/marketplace/common/rating.html" with value=4.5 count=123 %}
```

---

## Marketplace Components

### Card Components

All card components support `layout="grid"` (default) or `layout="list"`.

#### Job Card
```django
{% include "components/marketplace/cards/job_card.html" with job=job %}
{% include "components/marketplace/cards/job_card.html" with job=job layout="list" %}
```

**Required fields on job object:**
- `title`, `company.name`, `company.logo`, `location`
- `salary_min`, `salary_max`, `salary_period`
- `tags.all`, `created_at`, `is_remote`

#### Service Card
```django
{% include "components/marketplace/cards/service_card.html" with service=service %}
```

**Required fields:**
- `title`, `thumbnail`, `category.name`
- `provider.get_full_name`, `provider.profile_picture`
- `rating`, `review_count`, `starting_price`

#### Candidate Card
```django
{% include "components/marketplace/cards/candidate_card.html" with candidate=candidate %}
```

**Required fields:**
- `get_full_name`, `profile_picture`, `headline`
- `location`, `rating`, `review_count`
- `skills.all`, `hourly_rate`, `completed_projects`

#### Employer Card
```django
{% include "components/marketplace/cards/employer_card.html" with employer=employer %}
```

#### Project Card
```django
{% include "components/marketplace/cards/project_card.html" with project=project %}
```

#### Blog Card
```django
{% include "components/marketplace/cards/blog_card.html" with post=post %}
```

---

### Section Components

#### Breadcrumb
```django
{# Simple breadcrumb #}
{% include "components/marketplace/sections/breadcrumb.html" with title="Find Jobs" %}

{# With search form #}
{% include "components/marketplace/sections/breadcrumb.html" with title="Find Jobs" show_search=True subtitle="Find your dream job" %}

{# With custom breadcrumb items #}
{% include "components/marketplace/sections/breadcrumb.html" with title="Job Details" breadcrumb_items=breadcrumb_items %}
```

#### Testimonials
```django
{# Slider (default) #}
{% include "components/marketplace/sections/testimonials.html" %}

{# Grid layout #}
{% include "components/marketplace/sections/testimonials.html" with testimonials=testimonials layout="grid" %}
```

#### Counter Stats
```django
{# Default 4-column layout #}
{% include "components/marketplace/sections/counter_stats.html" %}

{# With icons (for dashboards) #}
{% include "components/marketplace/sections/counter_stats.html" with stats=stats layout="icons" %}
```

#### CTA Banner
```django
{# With background image #}
{% include "components/marketplace/sections/cta_banner.html" with title="Start Your Journey" button_text="Get Started" %}

{# Gradient background #}
{% include "components/marketplace/sections/cta_banner.html" with title="Ready?" layout="gradient" %}

{# Centered text #}
{% include "components/marketplace/sections/cta_banner.html" with title="Join Us" layout="centered" %}
```

---

### Form Components

#### Filter Sidebar
```django
{% include "components/marketplace/forms/filter_sidebar.html" %}
{% include "components/marketplace/forms/filter_sidebar.html" with filter_type="services" %}
```

Filter types: `jobs`, `candidates`, `services`, `employers`, `projects`

---

### Common Components

#### Rating
```django
{# Default #}
{% include "components/marketplace/common/rating.html" with value=4.5 %}

{# With count #}
{% include "components/marketplace/common/rating.html" with value=4.5 count=482 %}

{# Compact (for cards) #}
{% include "components/marketplace/common/rating.html" with value=4.5 count=482 layout="compact" %}

{# Interactive (for forms) #}
{% include "components/marketplace/common/rating.html" with layout="interactive" %}

{# Large (for detail pages) #}
{% include "components/marketplace/common/rating.html" with value=4.8 count=1968 layout="large" %}
```

#### Wishlist Button
```django
{# Default (absolute positioned for cards) #}
{% include "components/marketplace/common/wishlist_button.html" with item=job item_type="job" %}

{# Bordered #}
{% include "components/marketplace/common/wishlist_button.html" with item=service item_type="service" layout="border" %}

{# Large (for detail pages) #}
{% include "components/marketplace/common/wishlist_button.html" with item=candidate item_type="candidate" layout="large" %}

{# With text #}
{% include "components/marketplace/common/wishlist_button.html" with item=employer item_type="employer" layout="text" %}
```

#### Scroll to Top
```django
{% include "components/marketplace/common/scroll_to_top.html" %}
```

---

## Example: Job Listing Page

```django
{% extends "base/public_base.html" %}
{% load i18n %}

{% block content %}
{# Breadcrumb with search #}
{% include "components/marketplace/sections/breadcrumb.html" with title="Find Jobs" show_search=True subtitle="Discover your dream career" %}

<div class="container py-10">
    <div class="flex gap-8">
        {# Filter Sidebar #}
        {% include "components/marketplace/forms/filter_sidebar.html" with filter_type="jobs" %}

        {# Job Listings #}
        <div class="flex-grow" id="listing-results">
            <div class="flex items-center justify-between mb-6">
                <p class="text-secondary">{{ jobs.count }} {% trans 'jobs found' %}</p>
                <select class="border border-line rounded-lg px-3 py-2">
                    <option>{% trans 'Most Recent' %}</option>
                    <option>{% trans 'Highest Salary' %}</option>
                </select>
            </div>

            <ul class="grid md:grid-cols-2 gap-6">
                {% for job in jobs %}
                {% include "components/marketplace/cards/job_card.html" with job=job %}
                {% endfor %}
            </ul>

            {% include "components/pagination.html" with page_obj=jobs %}
        </div>
    </div>
</div>

{# CTA Banner #}
{% include "components/marketplace/sections/cta_banner.html" with title="Looking to Hire?" button_text="Post a Job" layout="gradient" %}

{# Scroll to Top #}
{% include "components/marketplace/common/scroll_to_top.html" %}
{% endblock %}
```

---

## Technical Details

### Dependencies

- **Tailwind CSS**: Utility classes for styling
- **Alpine.js**: Reactive components (dropdowns, toggles)
- **HTMX**: Dynamic updates without page reload
- **Phosphor Icons**: Icon library (ph, ph-fill, ph-bold prefixes)
- **Swiper.js**: Carousel/slider functionality

### CSS Classes

Custom classes used across components:
- `.heading1` - `.heading6`: Heading typography
- `.body1`, `.body2`: Body text
- `.caption1`, `.caption2`: Small text
- `.text-button`, `.text-button-sm`: Button text
- `.button-main`: Primary button style
- `.tag`: Tag/badge style
- `.bg-surface`: Light background
- `.bg-feature`: Dark feature background
- `.text-primary`, `.text-secondary`: Text colors
- `.border-line`: Border color

### i18n Support

All components use Django's i18n system:
```django
{% load i18n %}
{% trans "Button Text" %}
```

### Dark Mode

Components support dark mode via Tailwind's dark variant:
```html
class="bg-white dark:bg-gray-800 text-black dark:text-white"
```

---

## Component Statistics

| Category | Files | Description |
|----------|-------|-------------|
| Dashboard | 16 | Headers, sidebar, modals, tables, etc. |
| Public | 2 | Canonical public_header.html & public_footer.html |
| Public Pages | 10 | Homepage, about, services, pricing, FAQs, contact, etc. |
| Marketplace Cards | 6 | Job, service, candidate, employer, project, blog |
| Marketplace Sections | 4 | Breadcrumb, testimonials, counter, CTA |
| Marketplace Forms | 1 | Filter sidebar |
| Marketplace Common | 3 | Rating, wishlist, scroll-to-top |
| **Total** | **42** | Complete UI component library |

---

## i18n Implementation

All templates use Django's internationalization system:

```django
{% load i18n %}

{# Simple text #}
{% trans "Button Text" %}

{# Text with variables #}
{% blocktrans with name=user.name %}Hello, {{ name }}{% endblocktrans %}
```

To extract translation strings:
```bash
python manage.py makemessages -l fr -l es -l de
```

---

## Archived Templates

Deprecated header/footer variants have been moved to `templates/_archive/`:
- `contact1.html`, `contact2.html` (replaced by `contact.html`)
- `header.html`, `header2.html`, `header_public.html` (replaced by `public_header.html`)
- `footer.html` (replaced by `public_footer.html`)

---

## Migration from FreelanceHub Template

The marketplace components were extracted and adapted from the FreelanceHub HTML template:
- Converted static HTML to Django templates
- Added i18n support for all text ({% trans %} tags)
- Integrated HTMX for dynamic updates
- Added Alpine.js for interactive elements
- Unified styling with Zumodra's Tailwind configuration
- Added dark mode support where applicable
- Standardized on `base.html` as canonical public template

---

## Author

**Rhematek Solutions**
Last Updated: 2026-01-03
