# Newsletter

## Overview

The Newsletter app provides comprehensive email newsletter management for Zumodra tenants. It handles subscriber management, message creation, campaign scheduling, and automated delivery. The app includes Mailchimp integration for advanced email marketing capabilities, double opt-in subscription workflows, and detailed campaign tracking.

## Key Features

### Completed Features

- **Newsletter Management**: Create and manage multiple newsletters per tenant
- **Subscription Management**: Double opt-in, subscribe/unsubscribe workflows, activation codes
- **Message Composition**: Rich article-based messages with images, links, and attachments
- **Campaign Scheduling**: Queue-based submission system with scheduled publishing
- **Email Templates**: HTML and text email support with customizable templates
- **Archive System**: Public archive of past newsletter submissions
- **Mailchimp Integration**: Automatic sync of subscriptions to Mailchimp lists
- **Subscriber Import**: Bulk CSV/email import functionality
- **Unsubscribe Management**: One-click unsubscribe with List-Unsubscribe headers
- **Dynamic Subscriptions**: Pluggable subscription generator system
- **Admin Interface**: Full Django admin with preview, submit, and import tools

### In Development

- Enhanced test coverage (see TODO.md)
- Advanced campaign analytics
- A/B testing for subject lines
- Segment-based targeting
- Campaign performance dashboard

## Architecture

### Models

Located in `newsletter/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **Newsletter** | Newsletter configuration | title, slug, email, sender, send_html, enable_unsubscribe |
| **Subscription** | Newsletter subscriptions | user, email_field, name_field, newsletter, subscribed, unsubscribed, activation_code |
| **Message** | Newsletter messages | title, slug, newsletter, date_create, date_modify |
| **Article** | Message content sections | title, text, url, image, sortorder, message |
| **Attachment** | File attachments | file, message |
| **Submission** | Scheduled sends | message, newsletter, publish_date, prepared, sent, sending, subscriptions |
| **SubscriptionGenerator** | Abstract base class | Dynamic subscription list generation |

### Views

#### Frontend Views (`newsletter/views.py`)

**Newsletter Views:**
- `NewsletterListView` - List available newsletters with formset for logged-in users
- `NewsletterDetailView` - Newsletter details page

**Subscription Views:**
- `SubscribeRequestView` - Subscribe to newsletter (with activation email)
- `UnsubscribeRequestView` - Unsubscribe from newsletter
- `UpdateRequestView` - Update subscription preferences
- `UpdateSubscriptionView` - Activate subscription with code
- `SubscribeUserView` - Subscribe logged-in users
- `UnsubscribeUserView` - Unsubscribe logged-in users
- `GeneralSubscribeView` - Footer/widget subscribe form

**Archive Views:**
- `SubmissionArchiveIndexView` - Archive index page
- `SubmissionArchiveDetailView` - View individual newsletter in archive

**Utility Views:**
- `ActionTemplateView` - Generic action confirmation pages
- `ActionFormView` - Generic action form handling

#### API Views (`newsletter/api/viewsets.py`)

RESTful API endpoints using Django REST Framework:

```
/api/v1/newsletter/newsletters/
/api/v1/newsletter/subscriptions/
/api/v1/newsletter/messages/
/api/v1/newsletter/articles/
/api/v1/newsletter/submissions/
/api/v1/newsletter/stats/
```

### URL Structure

#### Frontend URLs (`newsletter:*`)

```python
# General
newsletter:subscribe                              # Footer subscribe form
newsletter:newsletter_list                        # List newsletters
newsletter:newsletter_detail (newsletter_slug)    # Newsletter details

# Subscribe/Unsubscribe
newsletter:newsletter_subscribe_request (newsletter_slug)
newsletter:newsletter_subscribe_confirm (newsletter_slug)
newsletter:newsletter_unsubscribe_request (newsletter_slug)
newsletter:newsletter_unsubscribe_confirm (newsletter_slug)
newsletter:newsletter_update_request (newsletter_slug)

# Activation
newsletter:newsletter_update_activate (newsletter_slug, email, action, activation_code)
newsletter:newsletter_update (newsletter_slug, email, action)
newsletter:newsletter_activation_email_sent (newsletter_slug, action)
newsletter:newsletter_action_activated (newsletter_slug, action)

# Archive
newsletter:newsletter_archive (newsletter_slug)
newsletter:newsletter_archive_detail (newsletter_slug, year, month, day, slug)
```

#### API URLs (`newsletter-api:*`)

```python
newsletter-api:newsletter-list
newsletter-api:newsletter-detail (pk)
newsletter-api:newsletter-subscribers (pk)
newsletter-api:newsletter-messages (pk)
newsletter-api:subscription-list
newsletter-api:subscription-detail (pk)
newsletter-api:subscription-confirm (pk)
newsletter-api:subscription-unsubscribe (pk)
newsletter-api:subscription-public_subscribe
newsletter-api:article-list
newsletter-api:article-detail (pk)
newsletter-api:message-list
newsletter-api:message-detail (pk)
newsletter-api:message-articles (pk)
newsletter-api:message-create_submission (pk)
newsletter-api:submission-list
newsletter-api:submission-detail (pk)
newsletter-api:submission-prepare (pk)
newsletter-api:submission-send (pk)
newsletter-api:submission-submit_queue
newsletter-api:stats
```

### Templates

Located in `newsletter/templates/newsletter/`:

**Main Templates:**
- `newsletter_list.html` - Newsletter directory
- `newsletter_detail.html` - Newsletter info page
- `subscribe_form.html` - General subscribe form
- `subscription_subscribe.html` - Subscribe request page
- `subscription_unsubscribe.html` - Unsubscribe request page
- `subscription_update.html` - Update subscription page
- `subscription_activate.html` - Activation confirmation page
- `subscription_subscribe_email_sent.html` - Confirmation page
- `subscription_subscribe_activated.html` - Success page
- `subscription_subscribe_user.html` - Logged-in user subscribe
- `subscription_unsubscribe_user.html` - Logged-in user unsubscribe

**Email Templates (`newsletter/templates/newsletter/message/`):**
- `subscribe_subject.txt` - Subscribe email subject
- `subscribe.txt` - Subscribe email text version
- `subscribe.html` - Subscribe email HTML version
- `unsubscribe_subject.txt` - Unsubscribe email subject
- `unsubscribe.txt` - Unsubscribe email text version
- `unsubscribe.html` - Unsubscribe email HTML version
- `update_subject.txt` - Update email subject
- `update.txt` - Update email text version
- `update.html` - Update email HTML version
- `message_subject.txt` - Newsletter message subject
- `message.txt` - Newsletter message text version
- `message.html` - Newsletter message HTML version

**Admin Templates:**
- `admin/newsletter/message/preview.html` - Message preview
- `admin/newsletter/subscription/importform.html` - CSV import form
- `admin/newsletter/subscription/confirmimportform.html` - Import confirmation

### Forms

Located in `newsletter/forms.py`:

| Form | Purpose | Key Fields |
|------|---------|------------|
| **SubscribeRequestForm** | New subscriptions | email_field, name_field |
| **UnsubscribeRequestForm** | Unsubscribe requests | email_field |
| **UpdateRequestForm** | Update requests | email_field |
| **UpdateForm** | Activation with code | email_field, user_activation_code |
| **UserUpdateForm** | Logged-in user updates | subscribed |

## Integration Points

### With Other Apps

- **Accounts**: User authentication, subscription linking to user accounts
- **Tenants**: Multi-tenant isolation, tenant-specific newsletters
- **Notifications**: Email delivery infrastructure
- **Marketing**: Campaign tracking, analytics integration
- **Dashboard**: Newsletter statistics and quick subscribe widget

### External Services

- **Mailchimp**: Audience sync, campaign management, advanced analytics
- **Email**: Django email backend (SendGrid/SMTP) for newsletter delivery
- **Storage**: S3/local storage for article images and attachments
- **Celery**: Asynchronous subscription sync and bulk operations

## Security & Permissions

### Role-Based Access

| Role | Permissions |
|------|-------------|
| **Public** | Subscribe, unsubscribe, view visible newsletters |
| **Authenticated Users** | Manage own subscriptions, quick subscribe/unsubscribe |
| **Staff/Admin** | Full newsletter management, subscriber import, send campaigns |

### GDPR Compliance

- Double opt-in confirmation required (configurable)
- Activation code-based subscription verification
- One-click unsubscribe with List-Unsubscribe headers
- IP address logging for subscription audit trail
- Data export capability for subscriber information
- Subscription deletion on user account deletion

### Tenant Isolation

- All newsletters scoped to tenant site(s)
- Subscriptions isolated by newsletter
- Submissions cannot cross tenant boundaries
- Archive access restricted by newsletter visibility

## Mailchimp Integration

### Configuration

```python
# settings.py or .env
MAILCHIMP_API_KEY = 'your-api-key'
MAILCHIMP_SERVER_PREFIX = 'us1'  # Your datacenter
MAILCHIMP_LIST_ID = 'your-list-id'
```

### Features

Located in `newsletter/mailchimp_service.py`:

- **Automatic Sync**: Subscriptions auto-sync to Mailchimp on save (via Celery)
- **Add Subscriber**: `add_subscriber(email, first_name, last_name, merge_fields, tags)`
- **Update Subscriber**: `update_subscriber(email, first_name, last_name, merge_fields)`
- **Unsubscribe**: `unsubscribe(email)` - Updates Mailchimp status
- **Get Info**: `get_subscriber_info(email)` - Retrieve subscriber data
- **Bulk Sync**: `bulk_sync_subscriptions_to_mailchimp()` - Sync all subscriptions

### Celery Tasks

Located in `newsletter/tasks.py`:

```python
# Sync single subscription
sync_subscription_to_mailchimp.delay(subscription_id)

# Add email directly
add_email_to_mailchimp.delay(email, first_name, last_name)

# Bulk sync all
bulk_sync_subscriptions_to_mailchimp.delay()
```

## Database Considerations

### Indexes

Key indexes for performance:
- Newsletter: `slug` (unique)
- Subscription: `(user, email_field, newsletter)` (unique together)
- Subscription: `email_field`, `subscribed`, `unsubscribed`
- Message: `(slug, newsletter)` (unique together)
- Submission: `publish_date`, `prepared`, `sent`, `sending`
- Article: `(message, sortorder)` (unique together)

### Relationships

```
Newsletter (1) ←→ (N) Subscription
Newsletter (1) ←→ (N) Message
Newsletter (1) ←→ (N) Submission
Newsletter (N) ←→ (N) Site

Message (1) ←→ (N) Article
Message (1) ←→ (N) Attachment
Message (1) ←→ (N) Submission

Submission (N) ←→ (N) Subscription
Submission (N) ←→ (1) Site

User (1) ←→ (N) Subscription (optional)
```

## Email Workflow

### Subscribe Flow

1. User submits email on subscribe form
2. System checks if email already subscribed
3. Creates/updates Subscription with `subscribed=False`
4. Generates unique `activation_code`
5. Sends activation email with confirmation link
6. User clicks link to activate
7. Subscription updated to `subscribed=True`
8. Synced to Mailchimp (if configured)

### Unsubscribe Flow

1. User clicks unsubscribe link in email or form
2. System finds Subscription by email
3. Updates `unsubscribed=True`, `subscribed=False`
4. Records `unsubscribe_date`
5. Synced to Mailchimp (if configured)
6. User receives confirmation

### Message Submission Flow

1. Admin creates Message with Articles
2. Admin creates Submission from Message
3. Submission queued with `prepared=True`
4. Celery beat or manual trigger calls `Submission.submit_queue()`
5. System iterates subscriptions (including dynamic)
6. Renders message template for each subscriber
7. Sends email with personalized content
8. Marks Submission as `sent=True`

## Dynamic Subscription Generator

### Custom Generator Example

```python
from newsletter.models import SubscriptionGenerator, Newsletter

class EmployeeSubscriptionGenerator(SubscriptionGenerator):
    """Generate subscriptions for all active employees."""

    def generate_subscriptions(self, newsletter: Newsletter) -> list[tuple[str, str]]:
        from hr_core.models import Employee

        employees = Employee.objects.filter(status='active')
        return [
            (employee.get_full_name(), employee.work_email)
            for employee in employees
        ]

# Usage in admin
newsletter = Newsletter.objects.create(
    title="Employee Newsletter",
    subscription_generator_class="myapp.generators.EmployeeSubscriptionGenerator"
)
```

## Future Improvements

### High Priority (TODO.md)

1. **Test Coverage Improvements**
   - TODO-NEWSLETTER-TEST-001: Add test for `get_initial()` else branch
   - TODO-NEWSLETTER-TEST-002: Add test for `send_message()` exception handler
   - Target 90%+ coverage for production reliability

2. **Campaign Analytics**
   - Open rate tracking (pixel-based)
   - Click-through rate tracking
   - Bounce rate monitoring
   - Unsubscribe rate analytics
   - Per-campaign performance dashboard

3. **Subscriber Segmentation**
   - Tag-based subscriber groups
   - Behavioral segmentation
   - Custom field filters
   - Dynamic segments
   - Segment-specific campaigns

### Medium Priority

4. **A/B Testing**
   - Subject line testing
   - Content variation testing
   - Send time optimization
   - Winner auto-selection
   - Statistical significance calculation

5. **Email Builder**
   - Drag-and-drop email designer
   - Pre-built templates library
   - Template versioning
   - Mobile preview
   - Spam score checker

6. **Automation Workflows**
   - Welcome series automation
   - Drip campaigns
   - Re-engagement campaigns
   - Birthday/anniversary emails
   - Behavior-triggered emails

7. **Advanced Scheduling**
   - Send time optimization per subscriber
   - Timezone-aware sending
   - Throttling/rate limiting
   - Smart retry logic
   - Delivery window configuration

### Low Priority

8. **RSS-to-Email**
   - Auto-generate newsletters from RSS feeds
   - Scheduled RSS digest
   - Content curation tools

9. **Social Sharing**
   - Share newsletter to social media
   - Social proof widget
   - Referral tracking

10. **Mobile App Integration**
    - Push notification opt-in
    - In-app newsletter archive
    - Mobile-optimized templates

## Testing

### Current Test Coverage

Per `newsletter/TODO.md`:
- Core functionality covered
- Two test coverage gaps identified
- Integration tests needed for Mailchimp sync

### Test Structure

```
tests/
├── test_newsletter_models.py     # Model tests
├── test_newsletter_views.py      # View tests
├── test_newsletter_api.py        # API tests
├── test_newsletter_forms.py      # Form validation tests
├── test_newsletter_mailchimp.py  # Mailchimp integration tests
└── test_newsletter_workflows.py  # End-to-end workflows
```

### Key Test Scenarios

- Subscribe/unsubscribe workflows
- Double opt-in activation
- Email delivery and templating
- Submission queue processing
- Archive access and permissions
- Mailchimp sync operations
- Dynamic subscription generation
- Bulk subscriber import
- Admin actions (preview, submit)

### Running Tests

```bash
# Run all newsletter tests
pytest newsletter/tests/

# Run with coverage
pytest --cov=newsletter newsletter/tests/

# Run specific test file
pytest newsletter/tests/test_newsletter_views.py

# Run marked tests
pytest -m newsletter
```

## Performance Optimization

### Current Optimizations

- `select_related()` for newsletter foreign keys
- `prefetch_related()` for subscription many-to-many
- Cached template rendering
- Batch email sending with configurable delays
- Database indexes on frequent queries
- Newsletter list caching (10 minutes)
- Stats caching (5 minutes)

### Planned Optimizations

- Redis caching for subscriber counts
- Elasticsearch for subscriber search
- Background jobs for all email sending
- CDN for newsletter images
- Database query optimization for large lists
- Subscription webhook batching

## Settings

Located in `newsletter/settings.py`:

```python
# Email confirmation settings
CONFIRM_EMAIL_SUBSCRIBE = True   # Require activation for subscribe
CONFIRM_EMAIL_UNSUBSCRIBE = False # Direct unsubscribe
CONFIRM_EMAIL_UPDATE = True       # Require activation for updates

# HTTPS for newsletter links
USE_HTTPS = True

# Rich text editor widget
RICHTEXT_WIDGET = None  # Or ImperaviWidget, CKEditorWidget, etc.

# Thumbnail library
THUMBNAIL = 'sorl-thumbnail'  # Or 'easy-thumbnails'
THUMBNAIL_TEMPLATE = '<img src="{{thumbnail.url}}" width="{{thumbnail.width}}" height="{{thumbnail.height}}" />'

# Batch sending configuration
NEWSLETTER_EMAIL_DELAY = 0.1      # Seconds between emails
NEWSLETTER_BATCH_SIZE = 100       # Emails per batch
NEWSLETTER_BATCH_DELAY = 5        # Seconds between batches
```

## Migration Notes

When modifying models:

```bash
# Create migrations
python manage.py makemigrations newsletter

# Apply to shared schema (newsletter uses shared tables)
python manage.py migrate_schemas --shared

# If tenant-specific newsletters in future
python manage.py migrate_schemas --tenant
```

## Admin Interface

### Newsletter Admin

- Create/edit newsletters
- Configure sender information
- Enable/disable HTML emails
- Toggle unsubscribe links
- Site association

### Subscription Admin

- View all subscriptions
- Bulk subscribe/unsubscribe actions
- Import subscribers (CSV/text)
- Search by name/email
- Filter by status/newsletter
- Export subscriber lists

### Message Admin

- Create messages with articles
- Add attachments
- Preview HTML/text versions
- Submit to create Submission
- View subscriber count

### Submission Admin

- View submission queue
- Submit prepared submissions
- Monitor send status
- Filter by sent/prepared
- View publish date/time

## API Authentication

### Public Endpoints

- `POST /api/v1/newsletter/subscriptions/public_subscribe/` - Subscribe without auth

### Admin Endpoints (IsAdminUser)

- All other endpoints require staff authentication
- JWT tokens recommended for API access

## Contributing

When adding features to the Newsletter app:

1. Follow existing patterns in `views.py` and `api/viewsets.py`
2. Add URL patterns to `urls.py` and `api/urls.py`
3. Create/update templates in `newsletter/templates/newsletter/`
4. Update email templates in `newsletter/templates/newsletter/message/`
5. Write tests for new functionality
6. Update TODO.md with any new items
7. Update this README with changes
8. Ensure GDPR compliance is maintained

## Support

For questions or issues related to the Newsletter app:
- Check `newsletter/TODO.md` for known issues
- Review `views.py` for view implementations
- Consult `models.py` for data model details
- Check `mailchimp_service.py` for integration examples
- Consult the main [CLAUDE.md](../CLAUDE.md) for project guidelines

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production (with test coverage improvements needed)
