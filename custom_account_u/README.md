# Custom Account U (Custom Account Utilities)

## Overview

The Custom Account U app provides custom user authentication extensions and account management utilities for Zumodra, built on top of django-allauth. It handles OAuth integrations, public marketplace profiles, multi-tenant profile synchronization, and KYC verification workflows through iDenfy integration.

## Key Features

### Completed Features

- **Custom User Model**: Extended AbstractUser with MFA support, anonymous mode, UUID identifiers
- **Public Marketplace Profiles**: Global profiles for freelance/marketplace identity across all tenants
- **Profile Synchronization**: Privacy-controlled field-level sync from public to tenant profiles
- **OAuth Integration**: Social authentication support via django-allauth (Google, LinkedIn, Microsoft)
- **KYC Verification**: Identity verification integration with iDenfy (KYC/KYB)
- **Face Authentication**: Biometric face matching for secure authentication
- **2FA Middleware**: Enforces mandatory 2FA when configured
- **Auth Security Middleware**: Brute force protection with IP/MAC/User-Agent tracking
- **Custom Signup Forms**: Extended registration with first_name/last_name capture
- **Account Adapter**: Custom allauth adapter for post-signup tenant assignment

### In Development

- Additional OAuth providers (GitHub, Twitter/X)
- Enhanced profile synchronization automation
- Biometric authentication expansion
- Advanced security analytics dashboard

## Architecture

### Models

Located in `custom_account_u/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **CustomUser** | Extended user model | email, mfa_enabled, anonymous_mode, c_u_uuid, cv_verified, kyc_verified |
| **PublicProfile** | Global marketplace profile | user, display_name, professional_title, avatar, bio, skills, hourly_rate, profile_visibility |
| **ProfileFieldSync** | Per-tenant sync settings | user, tenant_uuid, sync_* fields (14 toggles), auto_sync |

### Views

#### Frontend Views (`custom_account_u/views.py`)

**KYC & Verification:**
- `launch_kyc_view` - Launch KYC verification page
- `start_kyc` - Initialize iDenfy KYC process
- `start_face_auth` - Start face authentication
- `start_kyb` - Start business verification (KYB)
- `idenfy_webhook` - Handle iDenfy verification webhooks

**Public Profile Management:**
- `public_profile_view` - View/edit own public marketplace profile
- `view_other_public_profile` - View another user's profile (respects visibility)
- `public_profile_search` - Search public marketplace profiles

**Profile Sync Settings:**
- `profile_sync_settings_list` - List all sync settings across tenants
- `profile_sync_settings_edit` - Edit sync settings for specific tenant
- `trigger_manual_sync` - Manual profile sync trigger (POST only)

#### API Views (`custom_account_u/api/views.py`)

RESTful API endpoints using Django REST Framework:

```
/api/profile/public/me/              # GET/PATCH own profile
/api/profile/public/{uuid}/          # GET other user's profile
/api/profile/sync-settings/          # GET list of sync settings
/api/profile/sync-settings/tenant/{tenant_uuid}/  # GET/PATCH/DELETE tenant sync settings
```

### URL Structure

#### Frontend URLs (`custom_account_u:*`)

```python
# API endpoints
custom_account_u:publicprofile-list
custom_account_u:publicprofile-detail (uuid)
custom_account_u:publicprofile-me
custom_account_u:profilefieldsync-list
custom_account_u:profilefieldsync-by-tenant (tenant_uuid)

# KYC endpoints
custom_account_u:start_kyc
custom_account_u:idenfy_webhook

# PublicProfile views
custom_account_u:public_profile
custom_account_u:view_public_profile (profile_uuid)
custom_account_u:profile_search

# Profile Sync Settings
custom_account_u:sync_settings_list
custom_account_u:sync_settings_edit (tenant_uuid)
custom_account_u:trigger_sync (tenant_uuid)
```

### Templates

Located in `templates/custom_account_u/`:

- `public_profile.html` - Own profile edit page
- `public_profile_view.html` - View other user's profile
- `profile_search.html` - Marketplace profile search
- `sync_settings_list.html` - List all sync settings
- `sync_settings_edit.html` - Edit tenant sync settings

### Middleware

Located in `custom_account_u/middleware.py`:

- **Require2FAMiddleware**: Enforces 2FA when `TWO_FACTOR_MANDATORY=True`
- **AuthSecurityMiddleware**: Advanced brute force protection with IP/MAC/UA tracking, automatic blocking, admin notifications, and firewall integration

### Signals

Located in `custom_account_u/signals.py`:

- **create_public_profile**: Auto-creates PublicProfile when CustomUser is created
- **save_public_profile**: Updates PublicProfile display_name when user's name changes

### Adapter

Located in `custom_account_u/adapter.py`:

- **ZumodraAccountAdapter**: Custom allauth adapter handling post-signup logic:
  - Creates UserProfile automatically
  - Assigns users to default tenant based on request context
  - Custom login/signup redirect URLs
  - Priority tenant assignment: beta > demo > first active tenant

## Integration Points

### With Other Apps

- **Accounts**: CustomUser extends Django User, integrates with UserProfile and TenantUser
- **Tenants**: ProfileFieldSync manages per-tenant privacy controls
- **Services**: PublicProfile used for freelance marketplace listings
- **Dashboard**: Profile completion stats, verification badges display
- **Notifications**: Email notifications for verification status changes

### External Services

- **iDenfy**: KYC/KYB verification, face authentication, identity documents verification
- **Django Allauth**: OAuth integrations (Google, LinkedIn, Microsoft, GitHub)
- **Email**: SendGrid for verification emails
- **Storage**: S3/local storage for avatars, CVs, and documents

## Security & Permissions

### Authentication Security

- OAuth token management via django-allauth
- Secure credential storage (never hardcoded)
- HMAC-SHA256 webhook signature verification
- Brute force protection with 5-attempt limit
- 48-hour lockout for failed authentication
- IP/MAC/User-Agent tracking and blocking
- Admin notification system for security alerts
- Firewall integration for persistent attackers

### Profile Visibility Levels

| Visibility | Access Level |
|------------|-------------|
| **Public** | Anyone can view profile |
| **Tenants Only** | Only shared organization members can view |
| **Private** | Only profile owner can view |

### Data Protection

- Profile field sync is opt-in with privacy-friendly defaults
- Sensitive fields (email, phone) disabled by default
- Manual sync preferred over auto-sync
- Tenant-isolated profile data
- User controls data revelation per tenant

### KYC Security

- Webhook signature verification required
- Secure token generation for verification sessions
- Verification status tracking (APPROVED/REJECTED/PENDING)
- Audit trail for all verification events
- Encrypted storage of verification documents

## Database Considerations

### Indexes

Key indexes for performance:
- CustomUser: `mfa_enabled`, `anonymous_mode`, `c_u_uuid` (unique)
- PublicProfile: `user`, `uuid` (unique), `profile_visibility`, `available_for_work`, `created_at`
- ProfileFieldSync: `user`, `tenant_uuid`, `auto_sync`, `(user, tenant_uuid)` (unique)

### Schema Location

- CustomUser: **PUBLIC schema** (shared across all tenants)
- PublicProfile: **PUBLIC schema** (global marketplace profile)
- ProfileFieldSync: **PUBLIC schema** (cross-tenant sync settings)

### Relationships

```
CustomUser (1) ←→ (1) PublicProfile
CustomUser (1) ←→ (N) ProfileFieldSync
Tenant (1) ←→ (N) ProfileFieldSync (via tenant_uuid, not FK)
```

## Future Improvements

### High Priority

1. **Additional OAuth Providers**
   - GitHub OAuth for developer profiles
   - Twitter/X OAuth for social verification
   - Apple Sign-In for iOS users
   - Custom SAML/OIDC enterprise SSO

2. **Enhanced Profile Sync Automation**
   - Real-time sync triggers via signals
   - Conflict resolution for concurrent edits
   - Batch sync for all tenants
   - Sync history and rollback

3. **Advanced KYC Features**
   - Liveness detection improvements
   - Document OCR and data extraction
   - Multi-jurisdiction compliance
   - Age verification
   - AML (Anti-Money Laundering) checks

4. **Profile Portfolio System**
   - Portfolio project showcase
   - GitHub/GitLab integration
   - Behance/Dribbble import
   - Video introductions
   - Testimonials and reviews

### Medium Priority

5. **Skills Verification**
   - Skills assessment tests
   - Certificate upload and validation
   - LinkedIn skills endorsements import
   - Peer skill endorsements
   - Skills expiry tracking

6. **Enhanced Privacy Controls**
   - Granular field-level permissions
   - Time-limited data access
   - Data access audit log
   - Anonymous profile browsing
   - Profile view notifications

7. **Profile Analytics**
   - Profile view tracking
   - Search appearance metrics
   - Engagement analytics
   - Profile strength score
   - Optimization recommendations

8. **Marketplace Features**
   - Availability calendar
   - Rate negotiation system
   - Service packages
   - Portfolio reviews
   - Rating and review system

### Low Priority

9. **Social Features**
   - Profile sharing
   - Profile embedding
   - QR code generation
   - Digital business cards
   - Professional network graph

10. **Advanced Security**
    - WebAuthn/FIDO2 keys
    - Biometric authentication (fingerprint)
    - Security key enforcement for admins
    - Login device management
    - Suspicious activity detection

## Testing

### Test Coverage

Target: 90%+ coverage for authentication, KYC, and security-critical code

### Test Structure

```
tests/
├── test_models.py           # CustomUser, PublicProfile, ProfileFieldSync tests
├── test_api.py              # API endpoint tests
└── (future)
    ├── test_kyc.py          # KYC verification flow tests
    ├── test_oauth.py        # OAuth integration tests
    ├── test_sync.py         # Profile sync tests
    └── test_security.py     # Security middleware tests
```

### Key Test Scenarios

- User registration with allauth adapter
- PublicProfile auto-creation via signals
- Profile visibility enforcement
- Profile field sync settings management
- API permission checks
- KYC webhook signature verification
- OAuth provider integration
- 2FA enforcement
- Brute force protection

## Performance Optimization

### Current Optimizations

- select_related('user') on profile queries
- Database indexes on frequently queried fields
- Cached tenant lookups in sync settings
- Lazy loading of verification badges
- Profile completion calculated on-the-fly

### Planned Optimizations

- Redis caching for profile data
- Elasticsearch for profile search
- Background jobs for profile sync
- CDN for avatar/CV files
- Database query optimization

## Configuration

### Environment Variables

```bash
# iDenfy KYC Integration
IDENFY_API_KEY=your_api_key
IDENFY_API_SECRET=your_api_secret
IDENFY_WEBHOOK_SECRET=your_webhook_secret

# 2FA Settings
TWO_FACTOR_MANDATORY=False  # Set True to enforce 2FA

# Auth Security
AUTH_FAIL_LIMIT=5           # Failed login attempts before block
AUTH_BLOCK_DURATION=172800  # 48 hours in seconds
ATTACK_WINDOW=300           # 5 minutes for rapid attack detection

# Admin Notifications
ADMIN_EMAIL_LIST=["admin@zumodra.com"]
DEFAULT_FROM_EMAIL="noreply@zumodra.com"
SECURITY_ALERT_WEBHOOK="https://webhook.site/your-webhook-id"
```

### Django Settings

```python
# Custom User Model
AUTH_USER_MODEL = 'custom_account_u.CustomUser'

# Allauth Configuration
ACCOUNT_ADAPTER = 'custom_account_u.adapter.ZumodraAccountAdapter'
ACCOUNT_FORMS = {
    'signup': 'custom_account_u.forms.CustomSignupForm',
}

# Middleware
MIDDLEWARE = [
    # ... other middleware
    'custom_account_u.middleware.Require2FAMiddleware',
    'custom_account_u.middleware.AuthSecurityMiddleware',
]

# Allauth Settings
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'

# Social Providers (django-allauth 65.3.0+)
SOCIALACCOUNT_PROVIDERS = {
    'google': {'SCOPE': ['profile', 'email']},
    'microsoft': {'SCOPE': ['User.Read']},
    'linkedin_oauth2': {'SCOPE': ['r_liteprofile', 'r_emailaddress']},
}
```

## Migration Notes

When modifying CustomUser:

```bash
# CRITICAL: CustomUser is in PUBLIC schema
python manage.py makemigrations custom_account_u

# Apply to shared/public schema only
python manage.py migrate_schemas --shared

# Verify migration
python manage.py check
```

When modifying PublicProfile or ProfileFieldSync:

```bash
# Standard migration (public schema models)
python manage.py makemigrations custom_account_u
python manage.py migrate_schemas --shared
```

## API Examples

### Get Own Public Profile

```bash
GET /api/profile/public/me/
Authorization: Bearer <jwt_token>

Response:
{
  "uuid": "123e4567-e89b-12d3-a456-426614174000",
  "display_name": "John Doe",
  "professional_title": "Full Stack Developer",
  "bio": "Experienced developer with 5+ years...",
  "available_for_work": true,
  "hourly_rate_min": "50.00",
  "hourly_rate_max": "100.00",
  "profile_visibility": "public",
  "completion_percentage": 85,
  ...
}
```

### Update Profile Sync Settings

```bash
PATCH /api/profile/sync-settings/tenant/tenant-uuid-here/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "sync_display_name": true,
  "sync_avatar": true,
  "sync_public_email": false,
  "sync_phone": false,
  "auto_sync": false
}

Response:
{
  "uuid": "...",
  "tenant_name": "Acme Corp",
  "enabled_fields": ["display_name", "avatar", "bio", ...],
  ...
}
```

### Search Public Profiles

```bash
GET /profile/search/?q=developer&location=Toronto&available_only=on
Authorization: Bearer <jwt_token>

Returns paginated list of public profiles matching criteria
```

## Contributing

When adding features to Custom Account U:

1. Maintain OAuth provider compatibility with django-allauth
2. Add proper webhook signature verification for external services
3. Write tests for authentication flows
4. Document new OAuth providers in README
5. Ensure profile sync respects privacy settings
6. Update API documentation for new endpoints
7. Follow security best practices for credential handling

## Support

For questions or issues related to custom_account_u:
- Review django-allauth documentation for OAuth setup
- Check iDenfy API docs for KYC integration
- Consult [SECURITY.md](../docs/SECURITY.md) for security guidelines
- See [CLAUDE.md](../CLAUDE.md) for project conventions

## Common Issues

### OAuth Provider Setup

1. Register app with OAuth provider (Google/Microsoft/LinkedIn)
2. Add credentials to Django settings
3. Configure redirect URIs: `https://your-domain.com/accounts/provider/callback/`
4. Test authentication flow

### KYC Webhook Not Working

1. Verify webhook signature verification is enabled
2. Check `IDENFY_WEBHOOK_SECRET` matches iDenfy dashboard
3. Ensure webhook URL is publicly accessible
4. Review webhook logs for signature mismatches

### Profile Sync Not Working

1. Verify user has TenantUser membership
2. Check ProfileFieldSync settings for tenant
3. Confirm enabled sync fields
4. Manually trigger sync via `trigger_manual_sync` endpoint

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production
