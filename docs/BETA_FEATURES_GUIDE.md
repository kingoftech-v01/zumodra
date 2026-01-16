# Beta Features Setup Guide

This guide covers setup, configuration, and usage for Zumodra's three beta features:
1. **AI Matching** - Intelligent candidate-job matching with GPT-4 explanations
2. **Background Checks** - Automated background screening via Checkr/Sterling/HireRight
3. **APNS** - Apple Push Notifications for iOS mobile app

---

## 1. AI Matching

### Overview
AI Matching uses hybrid ranking combining rule-based scoring, ML-based semantic matching, and verification scores to find the best candidates for jobs. GPT-4 generates human-readable explanations of why candidates match.

### Features
- **Resume Parser**: Extracts skills, experience, education from PDF/DOCX resumes
- **Job Analyzer**: Analyzes job descriptions to extract requirements
- **Bias Detection**: Detects gender/age bias in job descriptions
- **Hybrid Ranking**: Combines rule-based, AI, and verification scores
- **GPT-4 Explanations**: Natural language match explanations with fallback

### Configuration

#### 1. Environment Variables

```bash
# Required for GPT-4 explanations (optional - has rule-based fallback)
OPENAI_API_KEY=sk-proj-...
```

#### 2. Seed Skill Taxonomy

The AI matching system uses a comprehensive skill taxonomy:

```bash
# Load 150+ skills across 15 categories
python manage.py seed_skill_taxonomy

# Or refresh existing taxonomy
python manage.py seed_skill_taxonomy --clear
```

#### 3. Enable for Tenant

AI matching is enabled by default for all tenants. To verify:

```python
# Django shell
from tenants.models import Tenant
tenant = Tenant.objects.get(slug='your-tenant')
print(tenant.plan.feature_ai_matching)  # Should be True
```

### Usage

#### API Endpoints

**Get AI Match Score**
```http
GET /api/v1/ats/applications/{uuid}/match-score/
```

Response:
```json
{
  "overall_score": 85.5,
  "rule_score": 80.0,
  "ai_score": 90.0,
  "verification_score": 86.5,
  "match_level": "Excellent Match",
  "breakdown": {
    "skill_match": 85.0,
    "experience_match": 80.0,
    "culture_fit": 88.0,
    "location_match": 100.0,
    "salary_match": 90.0
  },
  "skills": {
    "matched": ["Python", "Django", "PostgreSQL"],
    "missing": ["Kubernetes", "AWS"]
  }
}
```

**Get GPT-4 Match Explanation**
```http
GET /api/v1/ai-matching/match-explanation/?application_id={id}
```

Response:
```json
{
  "summary": "Strong match with excellent technical skills...",
  "strengths": [
    "5+ years Python experience exceeds 3-year requirement",
    "Django expertise aligns perfectly with tech stack"
  ],
  "concerns": [
    "No Kubernetes experience mentioned",
    "Preferred AWS certification not held"
  ],
  "recommendation": "Proceed to interview",
  "confidence": "high"
}
```

#### Frontend

Match scores appear automatically on:
- Candidate list view
- Application detail page
- Pipeline Kanban board

---

## 2. Background Checks

### Overview
Automated background check integration with three major providers:
- **Checkr** (recommended)
- **Sterling**
- **HireRight**

### Features
- Multi-provider support with automatic failover
- Real-time webhook updates
- Consent tracking with IP/timestamp
- Comprehensive screening packages (Basic, Standard, Pro, Comprehensive)
- Admin interface for manual review
- Application status auto-updates

### Configuration

#### 1. Environment Variables

Choose your provider and add credentials:

```bash
# Checkr (Recommended)
CHECKR_API_KEY=your_api_key_here
CHECKR_ENVIRONMENT=sandbox  # or 'production'

# Sterling
STERLING_API_KEY=your_api_key
STERLING_CLIENT_ID=your_client_id
STERLING_ENVIRONMENT=test  # or 'production'

# HireRight
HIRERIGHT_API_KEY=your_api_key
HIRERIGHT_USERNAME=your_username
HIRERIGHT_PASSWORD=your_password
HIRERIGHT_ENVIRONMENT=staging  # or 'production'
```

#### 2. Provider Integration Setup

1. **Sign up with provider:**
   - Checkr: https://dashboard.checkr.com/signup
   - Sterling: https://www.sterlingcheck.com/contact/
   - HireRight: https://www.hireright.com/get-started/

2. **Get API credentials** from provider dashboard

3. **Configure webhook URL** in provider dashboard:
   ```
   https://your-domain.com/api/integrations/webhooks/{provider}/background-checks/
   ```

4. **Create Integration** in Django admin:
   - Go to `/admin/integrations/integration/`
   - Click "Add Integration"
   - Select provider (checkr/sterling/hireright)
   - Enter API credentials
   - Set status to "Active"

#### 3. Enable for Tenant

```python
# Django shell
from tenants.models import Tenant
tenant = Tenant.objects.get(slug='your-tenant')
tenant.plan.feature_background_checks = True
tenant.plan.save()
```

### Usage

#### API Endpoints

**Initiate Background Check**
```http
POST /api/v1/ats/applications/{uuid}/background-check/initiate/
Content-Type: application/json

{
  "package": "standard",
  "consent_given": true,
  "provider_name": "checkr"  // optional
}
```

**Get Background Check Status**
```http
GET /api/v1/ats/applications/{uuid}/background-check/status/
```

Response:
```json
{
  "id": 123,
  "status": "in_progress",
  "result": null,
  "provider": "checkr",
  "package": "standard",
  "initiated_at": "2025-01-15T10:30:00Z",
  "completed_at": null,
  "documents": [
    {
      "document_type": "ssn_verification",
      "status": "completed",
      "result": "clear"
    },
    {
      "document_type": "criminal_search",
      "status": "in_progress",
      "result": null
    }
  ]
}
```

**Get Full Report**
```http
GET /api/v1/ats/applications/{uuid}/background-check/report/
```

#### Frontend URLs

```
/frontend/ats/applications/{uuid}/background-check/initiate/
/frontend/ats/applications/{uuid}/background-check/status/
/frontend/ats/applications/{uuid}/background-check/report/
```

#### Package Options

| Package | Includes | Price Range |
|---------|----------|-------------|
| Basic | SSN verification, basic criminal | $29.99 |
| Standard | SSN, criminal, employment verification | $49.99 |
| Professional | Standard + education + references | $79.99 |
| Comprehensive | All checks + credit + MVR | $129.99 |

### Workflow

1. **Candidate applies** → Application created
2. **Move to "Background Check" stage** → Initiate check
3. **Candidate receives email** → Fills out consent form on provider site
4. **Provider runs checks** → Real-time webhook updates
5. **Check completes** → Application status auto-updates
6. **Recruiter reviews** → Makes hiring decision

### Application Status Transitions

The system automatically updates application status:

```
interviewing
  ↓ (initiate check)
background_check_in_progress
  ↓ (webhook: clear)
background_check_cleared → offer_extended
  ↓ (webhook: consider/suspended)
background_check_in_progress (manual review needed)
```

### Webhook Processing

Webhooks are processed automatically:

1. Provider sends webhook to `/api/integrations/webhooks/{provider}/background-checks/`
2. Signature verification (HMAC-SHA256)
3. Deduplication check
4. Update BackgroundCheck record
5. Send notifications to recruiter

### Admin Interface

View background checks at: `/admin/ats/backgroundcheck/`

Features:
- Filter by provider, status, result
- View full report data (JSON)
- Track consent details
- Manual status override
- Document-level details

---

## 3. APNS (Apple Push Notifications)

### Overview
Send push notifications to iOS mobile app users for real-time updates on:
- New job matches
- Application status changes
- Interview reminders
- Offer updates
- Messages

### Features
- Token-based authentication (.p8 key)
- Certificate-based authentication (.p12 cert)
- Sandbox and production environments
- Silent notifications
- Badge count management
- Notification categories (interactive buttons)

### Configuration

#### 1. Apple Developer Setup

1. **Log in to Apple Developer Portal:**
   https://developer.apple.com/account/

2. **Create App ID:**
   - Go to "Identifiers" → "App IDs"
   - Register new App ID: `com.zumodra.app`
   - Enable "Push Notifications" capability

3. **Generate APNs Auth Key (Recommended):**
   - Go to "Keys" → "All"
   - Click "+" to create new key
   - Name: "Zumodra APNS Key"
   - Enable "Apple Push Notifications service (APNs)"
   - Download `.p8` file (only available once!)
   - Note the **Key ID** (10 characters)
   - Note your **Team ID** (from Account → Membership)

   OR

4. **Generate APNs Certificate (Legacy):**
   - Go to "Certificates" → "All"
   - Click "+" to create certificate
   - Select "Apple Push Notification service SSL"
   - Follow CSR generation steps
   - Download certificate, convert to `.p12`

#### 2. Environment Variables

**Token-based auth (Recommended):**
```bash
APNS_USE_SANDBOX=True  # False for production
APNS_AUTH_KEY_PATH=/app/certs/AuthKey_ABC123XYZ.p8
APNS_AUTH_KEY_ID=ABC123XYZ9
APNS_TEAM_ID=DEF456UVW8
APNS_BUNDLE_ID=com.zumodra.app
APNS_TOPIC=com.zumodra.app
```

**Certificate-based auth:**
```bash
APNS_USE_SANDBOX=True
APNS_CERT_PATH=/app/certs/apns_cert.p12
APNS_CERT_PASSWORD=your_cert_password
APNS_BUNDLE_ID=com.zumodra.app
APNS_TOPIC=com.zumodra.app
```

#### 3. Place Certificate Files

**Docker:**
```bash
# Create certs directory
mkdir -p /path/to/project/certs

# Copy .p8 key file
cp ~/Downloads/AuthKey_ABC123XYZ.p8 certs/

# Update docker-compose.yml volumes:
services:
  web:
    volumes:
      - ./certs:/app/certs:ro
```

**Production:**
```bash
# Secure location with restricted permissions
mkdir -p /etc/zumodra/certs
cp AuthKey_ABC123XYZ.p8 /etc/zumodra/certs/
chmod 400 /etc/zumodra/certs/AuthKey_ABC123XYZ.p8
chown www-data:www-data /etc/zumodra/certs/AuthKey_ABC123XYZ.p8
```

### Usage

#### Registering Device Tokens

When user logs in on iOS app:

```http
POST /api/v1/notifications/apns/register/
Content-Type: application/json

{
  "device_token": "abc123...",
  "device_name": "John's iPhone",
  "device_model": "iPhone 14 Pro"
}
```

#### Sending Notifications (Automatic)

Notifications are sent automatically on:
- New job matches (AI matching finds good fit)
- Application status changes
- Interview scheduled/rescheduled
- Offer extended/accepted
- New messages

#### Sending Test Notification

Use management command:

```bash
python manage.py send_test_apns --user-email="user@example.com"
```

Or programmatically:

```python
from notifications.services import send_apns_notification

send_apns_notification(
    user_id=user.id,
    title="Test Notification",
    body="This is a test from Zumodra",
    data={"type": "test", "screen": "home"}
)
```

#### Notification Types

| Type | Title | Body | Action |
|------|-------|------|--------|
| job_match | New Job Match | "Software Engineer at Acme Corp..." | Opens job detail |
| application_update | Application Update | "Your application status changed..." | Opens application |
| interview_reminder | Interview Tomorrow | "Interview with John at 2pm..." | Opens interview |
| offer_received | Job Offer | "You've received an offer from..." | Opens offer |
| message_received | New Message | "Recruiter: When are you available..." | Opens chat |

### Testing

#### Sandbox Testing (Development)

1. Set `APNS_USE_SANDBOX=True`
2. Build app with development provisioning profile
3. Install on physical device (simulator doesn't support APNS)
4. Trigger notification event
5. Check device for notification

#### Production Testing

1. Set `APNS_USE_SANDBOX=False`
2. Build app with App Store/Ad Hoc profile
3. Install via TestFlight or direct distribution
4. Test all notification types

### Troubleshooting

**"Invalid device token"**
- Verify token format (64 hex characters)
- Check sandbox vs production mismatch
- Ensure app bundle ID matches

**"Invalid credentials"**
- Verify Key ID and Team ID are correct
- Check .p8 file path and permissions
- Ensure key is enabled for APNS in Developer Portal

**"Notification not received"**
- Check user has enabled notifications in iOS Settings
- Verify device token is registered
- Check Celery logs for delivery errors
- Confirm app is not in Do Not Disturb mode

**Certificate expired:**
- Certificates expire after 1 year
- Token-based auth (.p8) does not expire
- Regenerate certificate or migrate to token-based

---

## Database Migrations

After enabling features, run migrations:

```bash
# Apply to shared schema
python manage.py migrate_schemas --shared

# Apply to all tenant schemas
python manage.py migrate_schemas --tenant

# Or apply to specific tenant
python manage.py migrate_schemas --schema=tenant_slug
```

## Feature Verification

Verify all features are working:

```bash
# Check AI matching
python manage.py shell
>>> from ai_matching.models import Skill
>>> Skill.objects.count()  # Should be 150+

# Check background checks
>>> from ats.models import BackgroundCheck
>>> BackgroundCheck._meta.get_fields()  # Should include all fields

# Test APNS
python manage.py send_test_apns --user-email=test@example.com
```

## Performance Considerations

### AI Matching
- Match scores are cached in `CandidateRanking` model
- Recalculate stale scores: `python manage.py recalculate_match_scores`
- GPT-4 API calls are rate-limited (fallback to rule-based)

### Background Checks
- Webhooks are processed asynchronously via Celery
- Failed webhooks auto-retry with exponential backoff
- Provider API calls are cached for 5 minutes

### APNS
- Notifications sent via Celery queue
- Failed deliveries are retried 3 times
- Invalid tokens are automatically removed

## Security Considerations

### AI Matching
- Resume files scanned for malware
- Sensitive data (SSN, DOB) automatically redacted
- Bias detection flags problematic job descriptions

### Background Checks
- Consent required (tracked with IP/timestamp)
- Reports are encrypted at rest
- Access logged via django-auditlog
- FCRA compliance built-in

### APNS
- Device tokens encrypted in database
- Auth keys stored with restricted permissions
- TLS 1.2+ for all APNS connections
- Token rotation supported

## Support & Resources

### AI Matching
- OpenAI API Status: https://status.openai.com/
- Rate Limits: https://platform.openai.com/docs/guides/rate-limits

### Background Checks
- Checkr Docs: https://docs.checkr.com/
- Sterling API: https://developer.sterlingcheck.com/
- HireRight Support: https://www.hireright.com/support/

### APNS
- Apple Developer: https://developer.apple.com/documentation/usernotifications
- APNS Status: https://developer.apple.com/system-status/
- Best Practices: https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server

## Troubleshooting Common Issues

### "Feature not enabled for tenant"
```python
# Enable in Django admin or shell
tenant.plan.feature_ai_matching = True
tenant.plan.feature_background_checks = True
tenant.plan.save()
```

### "Provider credentials invalid"
- Verify API keys in Integration model
- Check environment variables are loaded
- Test credentials with provider's API directly

### "Migration conflicts"
```bash
# Reset migrations (development only!)
python manage.py migrate_schemas --schema=public ats zero
python manage.py migrate_schemas --schema=public ats
```

### "Celery tasks not running"
```bash
# Check Celery is running
celery -A zumodra status

# Start Celery worker
celery -A zumodra worker --loglevel=info

# Start Celery beat (scheduled tasks)
celery -A zumodra beat --loglevel=info
```

---

## Next Steps

1. **Test each feature** in development environment
2. **Configure provider integrations** (background checks, APNS)
3. **Enable for pilot tenants** gradually
4. **Monitor performance** and error logs
5. **Gather feedback** and iterate

For questions or issues, contact: support@zumodra.com
