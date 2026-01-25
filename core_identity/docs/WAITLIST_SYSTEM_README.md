# Waitlist System Documentation

**Version:** 1.0
**Status:** Production Ready
**Location:** `core_identity` app

## Overview

The Waitlist System is a global (platform-wide) pre-launch feature that allows users to create full accounts immediately while restricting platform access until a configured launch date. This creates anticipation, tracks early interest, and ensures a smooth launch experience.

### Key Features

- **Full Account Creation** - Users create complete accounts immediately (not just email collection)
- **Beautiful Countdown Page** - Shows days/hours/minutes until launch with live updates
- **Sequential Positioning** - Users see their position in the waitlist for gamification
- **Automatic Access Grant** - Users automatically gain access on launch date
- **Admin Controls** - Simple configuration via Django admin
- **One-Command Launch** - Launch platform with a single management command
- **Email Notifications** - Automated launch notification emails to all waitlist users

## Architecture

### Database Models

#### PlatformLaunch (Singleton)

Located in: `core_identity/models.py`

```python
class PlatformLaunch(models.Model):
    """Global platform launch configuration - SINGLETON MODEL."""

    launch_date = models.DateTimeField(...)  # When platform launches
    is_launched = models.BooleanField(...)    # Manual override
    waitlist_enabled = models.BooleanField(...)  # Enable/disable waitlist
    waitlist_message = models.TextField(...)  # Countdown page message
```

**Important:** Only one PlatformLaunch record exists (pk=1). Use `PlatformLaunch.get_config()` to access.

#### CustomUser Fields

Extended fields in `CustomUser` model:

```python
is_waitlisted = models.BooleanField(default=True)  # User on waitlist?
waitlist_joined_at = models.DateTimeField(...)     # When joined
waitlist_position = models.PositiveIntegerField(...)  # Position number
```

### Middleware

#### WaitlistEnforcementMiddleware

Located in: `core_identity/middleware.py`

**Functionality:**
- Intercepts all requests from authenticated users
- Checks if user is waitlisted and platform hasn't launched
- Redirects waitlisted users to countdown page
- Auto-grants access if platform has launched
- Exempts certain paths (admin, static, logout, etc.)

**Exempt Paths:**
- `/accounts/waitlist/countdown/`
- `/accounts/logout/`
- `/accounts/password/`
- `/static/`, `/media/`
- `/api/v1/waitlist/status/`
- `/admin/` (admins always have access)
- `/.well-known/`, `/health/`

### Views

#### WaitlistCountdownView

Located in: `core_identity/views/waitlist.py`

**URL:** `/accounts/waitlist/countdown/`

Displays countdown page with:
- Launch date
- Time remaining (days, hours, minutes)
- User's waitlist position
- Total waitlist users
- Custom message
- Progress bar

#### WaitlistStatusAPIView

Located in: `core_identity/views/waitlist.py`

**URL:** `/api/v1/waitlist/status/`

JSON API endpoint that returns:
```json
{
    "is_waitlisted": true,
    "is_launched": false,
    "waitlist_enabled": true,
    "time_until_launch": {
        "days": 7,
        "hours": 3,
        "minutes": 42
    },
    "launch_date": "2026-02-01T00:00:00Z",
    "waitlist_position": 42
}
```

Used by countdown page JavaScript for live updates every 60 seconds.

### Signup Flow

#### ZumodraAccountAdapter Integration

Located in: `core_identity/adapter.py`

When a user signs up:

1. Account is created fully (email, password, profile)
2. System checks `PlatformLaunch.get_config()`
3. If waitlist enabled and not launched:
   - `is_waitlisted = True`
   - `waitlist_joined_at = now()`
   - `waitlist_position = max_position + 1`
4. If launched or waitlist disabled:
   - `is_waitlisted = False`
   - User gets immediate access
5. Audit log entry is created

**Position Assignment:**
```python
max_position = CustomUser.objects.filter(
    is_waitlisted=True
).aggregate(Max('waitlist_position'))['waitlist_position__max']
user.waitlist_position = (max_position or 0) + 1
```

## Usage

### Initial Setup

1. **Run Migration:**
```bash
python manage.py migrate core_identity
```

2. **Configure Launch Date:**

Navigate to Django admin:
- URL: `/admin/core_identity/platformlaunch/`
- Set `launch_date` to your desired launch date/time
- Set `waitlist_enabled = True`
- Customize `waitlist_message` if desired
- Save

3. **Add Middleware:**

In `settings.py`, add to `MIDDLEWARE` list (after authentication middleware):

```python
MIDDLEWARE = [
    # ... existing middleware ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'core_identity.middleware.WaitlistEnforcementMiddleware',  # ADD THIS
    # ... remaining middleware ...
]
```

4. **Configure URLs:**

In `core_identity/urls.py`:

```python
from core_identity.views.waitlist import WaitlistCountdownView, WaitlistStatusAPIView

urlpatterns = [
    # ... existing urls ...
    path('waitlist/countdown/', WaitlistCountdownView.as_view(), name='waitlist_countdown'),
    path('api/v1/waitlist/status/', WaitlistStatusAPIView.as_view(), name='waitlist_status_api'),
]
```

### Pre-Launch Operations

#### Check Waitlist Status

```bash
python manage.py shell
```

```python
from core_identity.models import PlatformLaunch, CustomUser

# Get configuration
config = PlatformLaunch.get_config()
print(f"Launch Date: {config.launch_date}")
print(f"Is Launched: {config.is_platform_launched}")
print(f"Days Until Launch: {config.days_until_launch}")

# Get waitlist metrics
total_waitlisted = CustomUser.objects.filter(is_waitlisted=True).count()
print(f"Total Waitlisted Users: {total_waitlisted}")

# Get signup rate
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count

# Last 7 days
last_week = timezone.now() - timedelta(days=7)
recent_signups = CustomUser.objects.filter(
    is_waitlisted=True,
    waitlist_joined_at__gte=last_week
).count()
print(f"Signups in Last 7 Days: {recent_signups}")
print(f"Daily Average: {recent_signups / 7:.1f}")
```

#### Grant Early Access to Specific Users

Via Django Admin:
1. Go to `/admin/core_identity/customuser/`
2. Filter by `is_waitlisted = True`
3. Select users to grant access
4. Choose action: "Grant platform access"
5. Click "Go"

Or via shell:

```python
from core_identity.models import CustomUser

# Grant access to specific users
users_to_activate = CustomUser.objects.filter(
    email__in=['vip@example.com', 'beta@example.com']
)
users_to_activate.update(is_waitlisted=False)
```

#### Export Waitlist Data

```python
import csv
from core_identity.models import CustomUser

waitlist_users = CustomUser.objects.filter(is_waitlisted=True).order_by('waitlist_position')

with open('waitlist_export.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Position', 'Email', 'Name', 'Joined At'])

    for user in waitlist_users:
        writer.writerow([
            user.waitlist_position,
            user.email,
            f"{user.first_name} {user.last_name}",
            user.waitlist_joined_at.strftime('%Y-%m-%d %H:%M:%S')
        ])

print(f"Exported {waitlist_users.count()} users to waitlist_export.csv")
```

### Launch Day

#### Preview Launch (Dry Run)

```bash
python manage.py launch_platform --dry-run
```

Output:
```
======================================================================
PLATFORM LAUNCH SCRIPT
======================================================================

Found 247 waitlisted users

Sample of waitlisted users:
  - user1@example.com (Position: 1, Joined: 2026-01-15 10:23:45)
  - user2@example.com (Position: 2, Joined: 2026-01-15 11:12:33)
  ...

DRY RUN - No changes will be made

Actions that would be performed:
  1. Set platform as launched (is_launched=True)
  2. Update 247 users (is_waitlisted=False)
  3. Send 247 notification emails
```

#### Execute Launch

```bash
python manage.py launch_platform
```

Interactive confirmation:
```
======================================================================
PLATFORM LAUNCH SCRIPT
======================================================================

Found 247 waitlisted users

WARNING: This action will:
  - Launch the platform publicly
  - Grant access to 247 waitlisted users
  - Send 247 launch notification emails

Are you sure you want to proceed? [yes/N]: yes

======================================================================
Launching platform...
✓ Platform launched!
Granting access to waitlisted users...
✓ Updated 247 users
Sending notification emails...
  Sent 10 emails...
  Sent 20 emails...
  ...
✓ Sent 247 emails successfully

======================================================================
PLATFORM LAUNCH COMPLETE
======================================================================
Launch time: 2026-02-01 00:00:15
Users granted access: 247
Emails sent: 247
```

#### Skip Email Notifications (Testing)

```bash
python manage.py launch_platform --no-email
```

#### Manual Launch via Admin

Alternative to management command:

1. Go to `/admin/core_identity/platformlaunch/`
2. Set `is_launched = True`
3. Save

Users will automatically gain access via middleware. Emails must be sent separately.

### Post-Launch Operations

#### Verify All Users Have Access

```python
from core_identity.models import CustomUser

# Should be 0
still_waitlisted = CustomUser.objects.filter(is_waitlisted=True).count()
print(f"Users still waitlisted: {still_waitlisted}")

# Should be all users
active_users = CustomUser.objects.filter(is_waitlisted=False).count()
print(f"Active users: {active_users}")
```

#### Disable Waitlist System

If you want to disable entirely after launch:

```python
from core_identity.models import PlatformLaunch

config = PlatformLaunch.get_config()
config.waitlist_enabled = False
config.save()
```

Or via admin:
1. Go to `/admin/core_identity/platformlaunch/`
2. Set `waitlist_enabled = False`
3. Save

## Template Customization

### Countdown Page Template

Located at: `templates/core_identity/waitlist_countdown.html`

**Context Variables:**
- `launch_date` - DateTime object
- `time_until_launch` - Dict with `days`, `hours`, `minutes`
- `waitlist_message` - Custom message from config
- `waitlist_position` - User's position (integer)
- `waitlist_joined_at` - When user joined
- `total_waitlist_users` - Total count
- `progress_percentage` - Position as percentage (0-100)

**Customization Examples:**

Change gradient colors:
```css
.gradient-bg {
    background: linear-gradient(135deg, #YOUR_COLOR_1 0%, #YOUR_COLOR_2 100%);
}
```

Update stat cards:
```css
.stat-card {
    background: linear-gradient(135deg, #YOUR_COLOR_1 0%, #YOUR_COLOR_2 100%);
}
```

Modify countdown update interval:
```javascript
// In <script> section at bottom
setInterval(function() {
    // ... fetch logic ...
}, 30000); // Change from 60000 (1 min) to 30000 (30 sec)
```

### Email Templates

Located at:
- HTML: `templates/emails/platform_launched.html`
- Plain text: `templates/emails/platform_launched.txt`

**Context Variables:**
- `user` - CustomUser object
- `login_url` - Full URL to login page
- `dashboard_url` - Full URL to dashboard
- `unsubscribe_url` - Full URL to email preferences
- `current_year` - Current year (integer)

**Customization:**

Update company name:
```html
<!-- Find and replace "Zumodra" with your brand -->
<h1>🎉 YourBrand is Live!</h1>
```

Change gradient colors:
```css
.header {
    background: linear-gradient(135deg, #YOUR_COLOR_1 0%, #YOUR_COLOR_2 100%);
}
```

Modify CTA button:
```html
<a href="{{ login_url }}" class="cta-button">Your Custom Text</a>
```

## API Reference

### PlatformLaunch Model

**Class Methods:**

```python
PlatformLaunch.get_config()
```
Returns the singleton PlatformLaunch instance (pk=1). Creates if doesn't exist.

**Properties:**

```python
config.is_platform_launched
```
Returns `True` if:
- `is_launched = True` (manual override), OR
- `launch_date` has passed

```python
config.days_until_launch
```
Returns integer days remaining. Returns `0` if launched or None if no date set.

```python
config.time_until_launch
```
Returns dict:
```python
{
    'days': 7,
    'hours': 3,
    'minutes': 42
}
```

### CustomUser Model

**Waitlist Fields:**

```python
user.is_waitlisted  # Boolean
user.waitlist_joined_at  # DateTime or None
user.waitlist_position  # Integer or None
```

**Querying Waitlisted Users:**

```python
from core_identity.models import CustomUser

# All waitlisted users
waitlisted = CustomUser.objects.filter(is_waitlisted=True)

# Ordered by position
waitlisted = CustomUser.objects.filter(is_waitlisted=True).order_by('waitlist_position')

# Joined in last 7 days
from datetime import timedelta
from django.utils import timezone

last_week = timezone.now() - timedelta(days=7)
recent = CustomUser.objects.filter(
    is_waitlisted=True,
    waitlist_joined_at__gte=last_week
)

# By position range
top_100 = CustomUser.objects.filter(
    is_waitlisted=True,
    waitlist_position__lte=100
)
```

## Testing

### Running Tests

```bash
# Run all waitlist tests
python manage.py test core_identity.tests.test_waitlist_integration

# Run specific test class
python manage.py test core_identity.tests.test_waitlist_integration.WaitlistSystemIntegrationTest

# Run specific test method
python manage.py test core_identity.tests.test_waitlist_integration.WaitlistSystemIntegrationTest.test_new_user_added_to_waitlist
```

### Test Coverage

The test suite covers:
- ✅ PlatformLaunch singleton pattern
- ✅ Sequential waitlist position assignment
- ✅ New user waitlist logic
- ✅ Platform launch detection (manual and date-based)
- ✅ Time calculation accuracy
- ✅ Middleware enforcement
- ✅ User exemptions (superuser, unauthenticated)
- ✅ Path exemptions
- ✅ Auto-grant access on launch
- ✅ Countdown page display
- ✅ API endpoint responses
- ✅ Launch command functionality

### Manual Testing Checklist

Pre-Launch:
- [ ] New signup creates waitlisted user
- [ ] Sequential position assignment works
- [ ] Countdown page displays correctly
- [ ] Live countdown updates every minute
- [ ] Waitlist position shows correctly
- [ ] Progress bar displays
- [ ] Logout works from countdown page
- [ ] Admin can view waitlist users
- [ ] Admin bulk actions work (grant access)
- [ ] Dry-run command shows preview

Launch:
- [ ] Launch command executes successfully
- [ ] All users granted access
- [ ] Emails sent to all users
- [ ] Users can log in immediately
- [ ] Countdown page redirects to dashboard
- [ ] Middleware stops blocking access
- [ ] Admin shows launch status

## Troubleshooting

### Issue: Users not being waitlisted on signup

**Cause:** Waitlist disabled or platform already launched

**Solution:**
```python
from core_identity.models import PlatformLaunch
from django.utils import timezone
from datetime import timedelta

config = PlatformLaunch.get_config()
config.waitlist_enabled = True
config.is_launched = False
config.launch_date = timezone.now() + timedelta(days=30)
config.save()
```

### Issue: Countdown page not updating

**Cause:** JavaScript not loading or API endpoint not working

**Solution:**
1. Check browser console for JavaScript errors
2. Test API endpoint directly: `/api/v1/waitlist/status/`
3. Verify user is authenticated
4. Check CORS settings if API on different domain

### Issue: Email sending fails

**Cause:** Email backend not configured

**Solution:**

In `settings.py`:
```python
# For testing (console)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# For production (example with SendGrid)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.sendgrid.net'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'apikey'
EMAIL_HOST_PASSWORD = 'your-sendgrid-api-key'
DEFAULT_FROM_EMAIL = 'noreply@yourdomain.com'
```

### Issue: Migration fails

**Cause:** CustomUser already has is_waitlisted field from old migration

**Solution:**
```bash
# Check existing migrations
python manage.py showmigrations core_identity

# If conflict, fake the migration
python manage.py migrate core_identity <migration_number> --fake

# Then run new migrations
python manage.py migrate
```

### Issue: Middleware redirects in infinite loop

**Cause:** Countdown page path not in EXEMPT_PATHS

**Solution:**

In `core_identity/middleware.py`, verify:
```python
EXEMPT_PATHS = [
    '/accounts/waitlist/countdown/',  # MUST be here
    '/api/v1/waitlist/status/',  # MUST be here
    # ... other paths ...
]
```

## Performance Considerations

### Database Queries

**Optimized Queries:**

```python
# GOOD: Use select_related for user lookups
waitlisted = CustomUser.objects.filter(is_waitlisted=True).select_related('profile')

# GOOD: Use aggregate for max position
max_pos = CustomUser.objects.filter(
    is_waitlisted=True
).aggregate(Max('waitlist_position'))

# BAD: Don't query all users to count
# users = CustomUser.objects.filter(is_waitlisted=True)
# count = len(users)  # Loads all users into memory!

# GOOD: Use count()
count = CustomUser.objects.filter(is_waitlisted=True).count()
```

### Caching

Consider caching for high traffic:

```python
from django.core.cache import cache

# Cache launch config (5 minutes)
def get_launch_config():
    config = cache.get('platform_launch_config')
    if not config:
        config = PlatformLaunch.get_config()
        cache.set('platform_launch_config', config, 300)  # 5 min
    return config

# Invalidate on save
from django.db.models.signals import post_save

@receiver(post_save, sender=PlatformLaunch)
def invalidate_launch_cache(sender, instance, **kwargs):
    cache.delete('platform_launch_config')
```

### Middleware Performance

Middleware runs on every request. To minimize impact:

1. Early returns for exempt paths (no DB queries)
2. Single query for launch config
3. User waitlist status from session/auth (no extra query)
4. Auto-update only when needed

## Security Considerations

### Superuser Access

Superusers (admins) always have access, regardless of waitlist status. This allows:
- Admin panel access
- Platform configuration
- Emergency fixes

To test waitlist as admin, create a non-superuser account.

### Data Privacy

User email addresses are stored for launch notifications. Ensure:
- GDPR compliance (user consent)
- Email unsubscribe option
- Privacy policy disclosure

### Rate Limiting

Consider rate limiting the countdown page and API to prevent abuse:

```python
# In urls.py
from django.views.decorators.cache import cache_page

urlpatterns = [
    # Cache API response for 1 minute
    path('api/v1/waitlist/status/',
         cache_page(60)(WaitlistStatusAPIView.as_view()),
         name='waitlist_status_api'),
]
```

## FAQ

**Q: Can I have multiple launch dates for different features?**

A: No, this is a single platform-wide launch. For feature flags, use a feature flag system like django-waffle.

**Q: Can I customize the countdown design?**

A: Yes, see Template Customization section. All CSS is inline for easy modification.

**Q: What happens to waitlist data after launch?**

A: Data remains in database for analytics. Users keep `waitlist_position` and `waitlist_joined_at` fields but `is_waitlisted` becomes False.

**Q: Can I re-enable waitlist after launch?**

A: Yes, set `waitlist_enabled = True` and `is_launched = False`. New signups will be waitlisted, but existing users retain access.

**Q: How do I test without affecting production?**

A: Use separate environments (staging/dev) or use the `--dry-run` flag for launch command.

**Q: Can I customize email sending (batch size, delay)?**

A: Yes, modify `_send_launch_emails()` in `launch_platform.py` command. Consider using Celery for large batches.

**Q: What if I need to rollback a launch?**

A: Set `is_launched = False` in admin. Users will be redirected to countdown again (their access is checked on each request).

## Support

For issues or questions:
- Check this documentation
- Review test files for examples
- Check Django logs for errors
- Contact development team

## Changelog

### Version 1.0 (2026-01-24)
- Initial release
- PlatformLaunch singleton model
- WaitlistEnforcementMiddleware
- Countdown page with live updates
- API status endpoint
- Launch management command
- Email notification system
- Comprehensive test suite
- Admin integration
