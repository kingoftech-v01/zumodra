# FreelanHub Reusable Section Components

These are reusable section components extracted from various FreelanHub homepage variants that can be included in any template.

## Usage

Include these sections in your templates using:

```django
{% include 'components/sections/categories_grid.html' %}
{% include 'components/sections/categories_grid.html' with categories=custom_categories %}
```

## Available Components

### 1. categories_grid.html
**Source:** freelancer2.html
**Description:** Browse by category grid with icon cards
**Props:**
- `categories` (optional) - List of category objects with `name`, `slug`, `icon_class`

### 2. stats_counter.html
**Source:** freelancer2.html
**Description:** Animated statistics counter section
**Props:**
- `total_jobs` - Number of jobs
- `total_freelancers` - Number of freelancers
- `total_companies` - Number of companies
- `total_services` - Number of services

### 3. hero_category_dropdown.html
**Source:** index.html (FreelanHub original)
**Description:** Hero section with category dropdown search
**Props:** None (uses default categories)

### 4. testimonials_slider.html
**Source:** freelancer4.html
**Description:** Client testimonial carousel/slider
**Props:**
- `testimonials` (optional) - List of testimonial objects

### 5. how_it_works.html
**Source:** freelancer5.html
**Description:** Step-by-step process section (1-2-3 steps)
**Props:** None (static content, customize as needed)

### 6. featured_companies.html
**Source:** freelancer6.html
**Description:** Company logo showcase/grid
**Props:**
- `companies` (optional) - List of company objects with logos

### 7. blog_preview.html
**Source:** freelancer7.html
**Description:** Latest blog posts preview section
**Props:**
- `blog_posts` (optional) - List of recent blog post objects

### 8. top_providers.html
**Source:** freelancer2.html
**Description:** Featured freelancer/provider cards with ratings
**Props:**
- `top_providers` (optional) - List of top-rated provider objects

## Examples

```django
{# Homepage example #}
{% extends "base/freelanhub_base.html" %}
{% load static i18n %}

{% block content %}

{# Hero section #}
{% include 'components/sections/hero_category_dropdown.html' %}

{# Statistics #}
{% include 'components/sections/stats_counter.html' with total_jobs=stats.total_jobs total_freelancers=stats.total_freelancers %}

{# Categories #}
{% include 'components/sections/categories_grid.html' with categories=service_categories %}

{# Testimonials #}
{% include 'components/sections/testimonials_slider.html' with testimonials=client_testimonials %}

{# How it works #}
{% include 'components/sections/how_it_works.html' %}

{% endblock %}
```

## Creating New Sections

To create a new reusable section:

1. Find the section in the original FreelanHub HTML files
2. Extract the complete section HTML (including the `<section>` wrapper)
3. Replace hardcoded text with `{% trans %}` tags for i18n
4. Replace hardcoded links with `{% url %}` tags
5. Replace static data with Django template variables and loops
6. Add CSRF tokens to any forms
7. Document the props in this README

## Notes

- All sections maintain exact FreelanHub CSS classes and structure
- All text is wrapped in `{% trans %}` tags for internationalization
- All links use Django `{% url %}` tags for proper routing
- Sections can be mixed and matched on any page
- Props are optional - sections have sensible defaults
