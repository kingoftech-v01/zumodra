# Admin Honeypot App

## Overview

The Admin Honeypot app provides a security layer that creates a fake admin login interface at `/admin/` to detect, log, and deter unauthorized access attempts. The real Django admin panel is protected at a different URL (`/admin-panel/`), while attackers and bots attempting to access the standard admin URL are tracked and logged.

This security pattern is based on the principle of deception - by presenting what appears to be the real admin interface, the system can identify potential attackers before they discover the actual admin panel, providing valuable security intelligence and early warning of intrusion attempts.

## Key Features

### Security Features

- **Fake Admin Login Page**: Realistic Django admin interface at `/admin/`
- **Real Admin Protection**: Actual admin panel relocated to `/admin-panel/`
- **Intrusion Detection**: Automatic logging of all access attempts
- **Failed Login Tracking**: Records username, IP, session, user agent, and timestamp
- **Email Alerts**: Optional admin notifications on intrusion attempts
- **Integration with django-axes**: Works alongside brute force protection
- **Read-only Audit Trail**: Logged attempts cannot be deleted via admin interface

### Logging Capabilities

- IP address tracking with filtering support
- Session key tracking for correlation
- User agent fingerprinting
- Request path logging
- Timestamp recording for pattern analysis
- Clickable filters in admin interface for investigation

## Architecture

### Models

Located in `admin_honeypot/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **LoginAttempt** | Intrusion attempt records | username, ip_address, session_key, user_agent, timestamp, path |

**LoginAttempt Model Details:**

```python
class LoginAttempt(models.Model):
    username = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(protocol='both', blank=True, null=True)
    session_key = models.CharField(max_length=50, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.TextField(blank=True, null=True)
```

### Views

Located in `admin_honeypot/views.py`:

| View | Description | Template |
|------|-------------|----------|
| **AdminHoneypot** | Fake admin login page | `admin_honeypot/login.html` |

**View Behavior:**

- Presents authentic-looking Django admin login form
- All form submissions are rejected (form_valid calls form_invalid)
- Every submission creates a LoginAttempt record
- Triggers honeypot signal for email notifications
- Maintains session and redirects to mimic real admin behavior

### Admin Interface

Located in `admin_honeypot/admin.py`:

**LoginAttemptAdmin Features:**

- List display with clickable IP, session, and path filters
- Date-based filtering
- Search by username, IP address, user agent, path
- Read-only fields (audit trail protection)
- Delete actions disabled (permanent record)
- Add permission disabled (only system can create records)

### Signals

Located in `admin_honeypot/signals.py` and `admin_honeypot/listeners.py`:

**Honeypot Signal:**

- Triggered on every login attempt
- Passes LoginAttempt instance and request
- Connected to `notify_admins` listener if `ADMIN_HONEYPOT_EMAIL_ADMINS=True`

**Admin Notification:**

- Sends email to `ADMINS` setting
- Includes attempt details (username, IP, user agent, timestamp)
- Provides direct link to LoginAttempt detail in real admin panel
- Can be disabled via `ADMIN_HONEYPOT_EMAIL_ADMINS=False`

### URL Structure

Located in `admin_honeypot/urls.py`:

```python
# Honeypot URLs (fake admin)
admin_honeypot:login   # /admin/login/
admin_honeypot:index   # /admin/* (catch-all)
```

**URL Integration:**

In `zumodra/urls.py` and `zumodra/urls_public.py`:

```python
# Fake admin honeypot (i18n-prefixed)
path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot'))

# Real admin panel (protected location)
path('admin-panel/', admin.site.urls)
```

### Forms

Located in `admin_honeypot/forms.py`:

**HoneypotLoginForm:**

- Extends Django's `AdminAuthenticationForm`
- Overrides `clean()` to always raise validation error
- Provides authentic admin interface appearance
- Never validates credentials (always fails)

## Integration Points

### With Security Infrastructure

- **django-axes**: Brute force protection runs independently on real admin
- **Security Monitoring**: LoginAttempts provide attack intelligence
- **Audit Logging**: Immutable intrusion attempt records
- **Email Alerts**: Integration with Django mail system

### With Admin Panel

- **Real Admin**: Located at `/admin-panel/` (configurable)
- **LoginAttempt Management**: View/search attempts in real admin
- **Security Dashboard**: Can integrate with security app for analytics

### With Multi-Tenant System

- Works in both public schema and tenant schemas
- Logs attempts across all tenant contexts
- Centralized intrusion detection

## Security & Permissions

### Access Control

- **Public Access**: Honeypot is intentionally accessible to everyone
- **No Authentication Required**: Part of the deception mechanism
- **Read-Only Audit Trail**: LoginAttempts cannot be modified/deleted
- **Admin-Only Visibility**: Only staff can view LoginAttempt records

### Security Features

1. **Deception-Based Defense**: Wastes attacker time on fake target
2. **Early Warning System**: Identifies intrusion attempts before real attack
3. **Pattern Detection**: User agent and IP tracking for bot identification
4. **Persistent Logging**: Immutable audit trail for forensics
5. **Alert System**: Real-time email notifications to administrators

### Privacy & Compliance

- Logs publicly accessible endpoint (no expectation of privacy)
- IP addresses logged for security purposes (legitimate interest)
- User agents logged for bot detection
- No personal data beyond submitted username
- Consider GDPR/privacy policy disclosure of security logging

## Configuration

### Settings

Located in `zumodra/settings_security.py` or project settings:

```python
# Enable/disable email notifications (default: True)
ADMIN_HONEYPOT_EMAIL_ADMINS = True

# Configure admin emails (required for notifications)
ADMINS = [
    ('Admin Name', 'admin@example.com'),
]

# Configure email backend (required for notifications)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
```

### URL Configuration

To change honeypot or real admin URLs, edit `zumodra/urls.py`:

```python
# Change fake admin URL (default: /admin/)
path('fake-admin/', include('admin_honeypot.urls', namespace='admin_honeypot'))

# Change real admin URL (default: /admin-panel/)
path('secret-control-panel/', admin.site.urls)
```

**Security Note:** Keep real admin URL secret and never use common patterns.

## Future Improvements

### High Priority

1. **Enhanced Logging**
   - Geolocation tracking (IP to country/city)
   - Request headers logging (Accept-Language, Referer)
   - Cookie/session analysis
   - Timing pattern analysis
   - Attack signature detection

2. **Alert System Enhancements**
   - Slack/Teams integration
   - SMS alerts for critical threats
   - Webhook notifications
   - Configurable alert thresholds
   - Alert rate limiting (prevent notification spam)

3. **IP Reputation Integration**
   - Check IPs against threat intelligence feeds
   - Automatic blocking of known malicious IPs
   - Integration with AbuseIPDB, IPQualityScore
   - Whitelist/blacklist management
   - Country-based blocking

4. **Analytics Dashboard**
   - Visual attack patterns (charts/graphs)
   - Top attacking IPs
   - Attack frequency over time
   - Common usernames attempted
   - Bot vs. human detection
   - Export reports (PDF/CSV)

5. **Active Response**
   - Automatic IP blocking after N attempts
   - Integration with fail2ban
   - Dynamic firewall rule updates
   - Rate limiting on honeypot endpoint
   - CAPTCHA challenges for suspicious activity

### Medium Priority

6. **Advanced Deception**
   - Multiple fake admin panels (version fingerprinting)
   - Fake success responses (delay detection)
   - Honeytokens (fake credentials that alert on use)
   - Fake admin session cookies
   - Realistic error messages

7. **Pattern Analysis**
   - Machine learning for attack detection
   - Anomaly detection
   - Attack campaign correlation
   - Bot signature identification
   - Automated threat classification

8. **Integration Enhancements**
   - SIEM integration (Splunk, ELK)
   - Security information sharing (STIX/TAXII)
   - Incident response workflows
   - Automated security reports
   - Integration with WAF (Web Application Firewall)

9. **Forensics Features**
   - Full HTTP request logging
   - Network packet capture integration
   - Attack timeline reconstruction
   - Evidence preservation
   - Chain of custody documentation

10. **Performance Optimization**
    - Async logging to prevent blocking
    - Database indexing optimization
    - Log rotation and archival
    - Compressed storage for old records
    - Efficient query patterns

### Low Priority

11. **Customization**
    - Custom honeypot templates
    - Multiple honeypot variants
    - Dynamic honeypot generation
    - Configurable response delays
    - Custom error messages

12. **Advanced Analytics**
    - Attack attribution
    - Threat actor profiling
    - Campaign tracking
    - Predictive threat modeling
    - Risk scoring

## Testing

### Test Coverage

Target: 90%+ coverage for security-critical code

### Test Structure

```
tests/
├── test_honeypot.py          # Honeypot view tests
├── test_logging.py           # LoginAttempt creation tests
├── test_signals.py           # Signal/notification tests
├── test_admin.py             # Admin interface tests
└── test_security.py          # Security behavior tests
```

### Key Test Scenarios

**Functional Tests:**
- Access honeypot login page (GET)
- Submit credentials (POST)
- LoginAttempt record creation
- Signal triggering
- Email notification sending
- Admin interface display
- Filter/search functionality

**Security Tests:**
- No successful authentication possible
- All attempts logged regardless of input
- IP address capture accuracy
- User agent logging
- Session tracking
- Path logging

**Edge Cases:**
- Empty username/password
- SQL injection attempts in username
- XSS attempts in username
- Very long inputs
- Special characters
- Multiple rapid attempts
- Different browsers/clients

### Example Test

```python
@pytest.mark.security
def test_honeypot_logs_attempt(client):
    """Verify honeypot logs all login attempts."""
    initial_count = LoginAttempt.objects.count()

    response = client.post('/admin/login/', {
        'username': 'admin',
        'password': 'password123',
    })

    assert LoginAttempt.objects.count() == initial_count + 1
    attempt = LoginAttempt.objects.latest('timestamp')
    assert attempt.username == 'admin'
    assert attempt.ip_address is not None
    assert response.status_code == 200  # Returns to login page
```

## Performance Considerations

### Current Implementation

- Synchronous logging (blocks request)
- Database write on every attempt
- Email sent synchronously (if enabled)
- Session creation overhead

### Optimization Strategies

1. **Async Logging**: Use Celery for LoginAttempt creation
2. **Batch Notifications**: Aggregate emails (hourly/daily digest)
3. **Caching**: Rate limit checks via Redis
4. **Indexing**: Database indexes on ip_address, timestamp
5. **Archival**: Move old records to cold storage

### Scaling Considerations

- Under high attack volume, honeypot can impact performance
- Consider rate limiting at nginx/CDN level
- Use async workers for email notifications
- Implement log rotation and archival
- Monitor database growth

## Security Considerations

### Operational Security

1. **Never disclose real admin URL** in documentation, emails, or support
2. **Rotate real admin URL periodically** if under sustained attack
3. **Monitor honeypot activity** for attack pattern changes
4. **Correlate with other security logs** (nginx, firewall, IDS)
5. **Review failed attempts regularly** for legitimate users

### Attack Scenarios

**Automated Scanners:**
- Most web scanners check `/admin/` by default
- Honeypot wastes scanner time and resources
- Provides fingerprint of scanning tools

**Credential Stuffing:**
- Attackers try known username/password pairs
- Honeypot logs attempted credentials
- Real admin remains undiscovered

**Brute Force:**
- Attackers attempt to guess credentials
- Honeypot absorbs attack without risk
- Real admin protected by django-axes

**Zero-Day Exploits:**
- Exploits targeting Django admin vulnerabilities
- Honeypot safely absorbs exploit attempts
- Real admin may remain vulnerable but hidden

### Defense in Depth

Admin Honeypot is ONE layer of security. Also implement:

1. **Strong Authentication**: Complex passwords, 2FA mandatory
2. **IP Whitelisting**: Restrict real admin to known IPs
3. **VPN Requirement**: Require VPN for admin access
4. **Rate Limiting**: Limit login attempts on real admin
5. **Monitoring**: Alert on suspicious real admin activity
6. **Regular Updates**: Keep Django and dependencies patched
7. **WAF Protection**: Web Application Firewall rules
8. **Network Segmentation**: Isolate admin network

## Deployment

### Installation

The app is already installed and configured in Zumodra. For reference:

```python
# settings.py
INSTALLED_APPS = [
    # ...
    'admin_honeypot',
    # ...
]

# settings_security.py
ADMIN_HONEYPOT_EMAIL_ADMINS = True
```

### Database Migration

```bash
# Apply honeypot migrations
python manage.py migrate_schemas --shared  # Public schema
python manage.py migrate_schemas --tenant  # Tenant schemas
```

### Verification

```bash
# Test honeypot is accessible
curl -I https://yourdomain.com/admin/

# Test real admin is accessible (should be secret)
curl -I https://yourdomain.com/admin-panel/

# Check LoginAttempt records are created
python manage.py shell
>>> from admin_honeypot.models import LoginAttempt
>>> LoginAttempt.objects.count()
```

### Monitoring

**Check honeypot activity:**

```python
# Django shell
from admin_honeypot.models import LoginAttempt
from django.utils import timezone
from datetime import timedelta

# Last 24 hours
recent = timezone.now() - timedelta(hours=24)
attempts = LoginAttempt.objects.filter(timestamp__gte=recent)
print(f"Attempts in last 24h: {attempts.count()}")

# Most common attacking IPs
from django.db.models import Count
top_ips = LoginAttempt.objects.values('ip_address').annotate(
    count=Count('ip_address')
).order_by('-count')[:10]
```

**View in admin panel:**

1. Navigate to real admin: `https://yourdomain.com/admin-panel/`
2. Click "Admin honeypot" → "Login attempts"
3. Use filters for IP, date, session
4. Export data for analysis

## Compliance & Legal

### Legal Considerations

**Deception in Security:**
- Honeypots are generally legal for defensive purposes
- Clearly a security measure, not entrapment
- No interaction with legitimate users

**Data Collection:**
- IP addresses: Legitimate security interest
- Usernames: Publicly submitted data
- User agents: Standard HTTP headers
- Ensure privacy policy discloses security logging

**Data Retention:**
- Define retention policy for LoginAttempts
- Balance forensics needs with privacy
- Consider GDPR "right to erasure" implications
- Anonymize after investigation period

**Incident Response:**
- Use logs for security investigations only
- Establish chain of custody procedures
- Coordinate with legal team for law enforcement
- Document evidence preservation

## Maintenance

### Regular Tasks

**Weekly:**
- Review honeypot activity trends
- Check for attack pattern changes
- Verify email notifications working

**Monthly:**
- Export and archive old LoginAttempts
- Analyze attack statistics
- Update IP blacklists
- Review alert thresholds

**Quarterly:**
- Security audit of real admin URL secrecy
- Test email notification system
- Update threat intelligence integrations
- Review and update documentation

### Database Maintenance

```python
# Delete old records (older than 90 days)
from admin_honeypot.models import LoginAttempt
from django.utils import timezone
from datetime import timedelta

cutoff = timezone.now() - timedelta(days=90)
old_attempts = LoginAttempt.objects.filter(timestamp__lt=cutoff)
print(f"Deleting {old_attempts.count()} old records")
old_attempts.delete()
```

**Note:** Consider archiving to CSV before deletion for long-term forensics.

## Troubleshooting

### Common Issues

**1. Email notifications not sending**

Check configuration:
```python
# settings.py
ADMIN_HONEYPOT_EMAIL_ADMINS = True
ADMINS = [('Your Name', 'your@email.com')]
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# ... SMTP settings ...
```

Test email:
```python
from django.core.mail import mail_admins
mail_admins('Test', 'Testing honeypot notifications')
```

**2. LoginAttempts not being created**

- Check database migrations applied
- Verify honeypot URLs configured correctly
- Check for errors in Django logs
- Test signal connection

**3. Real admin URL discovered**

- Immediately change admin URL
- Review access logs for leak source
- Check for accidental disclosure in documentation
- Consider additional access controls (IP whitelist, VPN)

**4. High volume of attacks impacting performance**

- Implement rate limiting at nginx/CDN level
- Move to async logging (Celery)
- Archive old LoginAttempts
- Consider IP-based blocking

## Support

For questions or issues:

- Review Django admin documentation
- Check admin_honeypot library documentation
- Consult [SECURITY.md](../docs/SECURITY.md) for security guidelines
- Review security best practices documentation

## References

- [Django Admin Honeypot (GitHub)](https://github.com/dmpayton/django-admin-honeypot)
- [OWASP Honeypot Project](https://owasp.org/www-community/Honeypots)
- [Django Security Best Practices](https://docs.djangoproject.com/en/stable/topics/security/)
- [Intrusion Detection Systems](https://en.wikipedia.org/wiki/Intrusion_detection_system)

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production (Security Feature)
