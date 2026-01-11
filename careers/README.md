# Careers App

## Overview

Public-facing career pages for tenant job postings, allowing candidates to browse jobs and submit applications without authentication.

## Key Features

- **Career Pages**: Public job board per tenant
- **Job Listings**: SEO-optimized job pages
- **Application Forms**: Public application submission
- **Company Branding**: Tenant-specific branding
- **Job Search**: Filter and search jobs
- **Social Sharing**: Share job postings
- **Mobile Responsive**: Mobile-friendly design

## URL Structure

```
# Career page URLs
/{tenant_slug}/careers/
/{tenant_slug}/careers/jobs/
/{tenant_slug}/careers/jobs/{job_id}/
/{tenant_slug}/careers/apply/{job_id}/
```

## Views

| View | Description | URL Pattern |
|------|-------------|-------------|
| `CareersHomeView` | Tenant career page | `/careers/` |
| `JobListingView` | Public job listings | `/careers/jobs/` |
| `JobDetailView` | Job description | `/careers/jobs/{id}/` |
| `ApplicationFormView` | Apply for job | `/careers/apply/{id}/` |
| `ApplicationSubmitView` | Submit application | POST `/careers/apply/{id}/` |

## Templates

Located in `templates/careers/`:

- `careers_home.html` - Career page landing
- `job_listings.html` - Job board
- `job_detail.html` - Job description page
- `application_form.html` - Application form
- `application_success.html` - Thank you page

## Features

### Job Board
- Grid/list view toggle
- Filter by department, location, type
- Search functionality
- Sort by date posted
- Pagination

### Job Details
- Full job description
- Requirements and qualifications
- Company information
- Benefits
- Application CTA
- Social share buttons

### Application Form
- Personal information
- Contact details
- Resume upload
- Cover letter (optional)
- Additional questions
- GDPR consent

### SEO Optimization
- Schema.org JobPosting markup
- Meta tags optimization
- Sitemap inclusion
- Social media cards
- Canonical URLs

## Integration Points

- **ATS**: Fetches published jobs
- **Accounts**: Creates candidate records
- **Tenants**: Branding and domain mapping
- **Notifications**: Application confirmation emails

## Configuration

Per-tenant settings:

```python
CareerPageSettings:
    - enabled: bool
    - custom_domain: str
    - branding_logo: file
    - primary_color: str
    - description: text
    - social_links: json
    - analytics_code: str
```

## Future Improvements

### High Priority

1. **Career Page Builder**
   - Drag-and-drop editor
   - Section templates
   - Custom blocks
   - Preview mode

2. **Advanced Filtering**
   - Remote/hybrid/onsite
   - Salary range
   - Experience level
   - Full-time/part-time/contract

3. **Job Alerts**
   - Email job alerts
   - Subscribe to categories
   - Save searches
   - Custom notifications

4. **Video Job Descriptions**
   - Embed video in job posts
   - Company culture videos
   - Team introductions
   - Office tours

5. **Employee Referrals**
   - Referral program
   - Referral tracking
   - Referral bonuses
   - Employee advocacy

### Medium Priority

6. **Multi-Language**: Job posts in multiple languages
7. **Job Widgets**: Embeddable job widgets for company websites
8. **Talent Community**: Join talent pool without applying
9. **Application Tracking**: Track application status (public)
10. **Company Reviews**: Employee reviews integration

### Low Priority

11. **Chatbot**: AI-powered application assistant
12. **Video Applications**: Submit video cover letters
13. **Gamification**: Candidate engagement games
14. **Virtual Tours**: 360° office tours

## SEO Strategy

### On-Page SEO
- Optimized titles and meta descriptions
- Structured data (JobPosting schema)
- Clean URLs
- Fast page load
- Mobile optimization

### Job Distribution
- Auto-post to Google Jobs
- Share to LinkedIn
- Share to Indeed
- Share to Glassdoor
- RSS feed

### Analytics
- Google Analytics integration
- Job view tracking
- Application source tracking
- Conversion funnel

## Performance

- Static page caching
- CDN for assets
- Lazy loading images
- Minified CSS/JS
- Database query optimization

## Security

- Rate limiting on applications
- CAPTCHA for spam prevention
- File upload validation
- XSS protection
- CSRF protection

## Accessibility

- WCAG 2.1 AA compliance
- Screen reader support
- Keyboard navigation
- Alt text for images
- Color contrast compliance

## Testing

```
tests/
├── test_careers_views.py
├── test_job_listings.py
├── test_application_form.py
├── test_seo.py
└── test_careers_integration.py
```

## Analytics Tracking

Track these metrics:
- Page views per job
- Application rate
- Time on page
- Source of traffic
- Application completion rate
- Mobile vs desktop

## Contributing

When adding career page features:
1. Maintain SEO best practices
2. Ensure mobile responsiveness
3. Test application submission flow
4. Verify schema.org markup
5. Check accessibility compliance

---

**Status:** Production
**Public-Facing:** Yes
**SEO Priority:** Critical
