# Accounts App

## Overview

The Accounts app manages user authentication, profiles, KYC verification, and trust scoring across the Zumodra platform. It provides the foundation for multi-tenant user management with role-based access control and progressive consent mechanisms.

## Key Features

### Completed Features

- **User Authentication**: Email/password login with mandatory 2FA
- **User Profiles**: Comprehensive user profiles with photo, bio, contact details
- **Role Management**: Multi-level roles (PDG, Supervisor, HR Manager, Recruiter, Employee, Viewer)
- **Profile Management**: User profile editing, avatar upload
- **Session Management**: Secure session handling with timeout and rotation
- **Password Management**: Reset, change password workflows
- **Two-Factor Authentication**: TOTP-based 2FA via django-two-factor-auth

### In Development

- **KYC Verification (Level 1)**: Identity verification via Sumsub/Onfido
- **Career Verification (Level 2)**: Employment and education verification
- **Trust Score System**: Multi-dimensional trust scoring
- **Badge System**: Verification badges and certifications
- **Multi-CV Management**: Multiple CV profiles per user
- **Progressive Consent**: Staged data revelation system

## Architecture

### Models

Located in `accounts/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **User** | Django custom user | email (username), first_name, last_name, is_active, date_joined |
| **Profile** | Extended user info | user, photo, bio, phone, address, date_of_birth, gender |
| **TenantUser** | Tenant membership | user, tenant, role, circusale, is_active |
| **KYCVerification** | KYC records | user, verification_level, status, provider, verified_at |
| **EmploymentHistory** | Work experience | user, company, title, start_date, end_date, verified |
| **EducationHistory** | Education records | user, institution, degree, field, start_date, end_date, verified |
| **TrustScore** | Trust metrics | user, overall_score, identity_score, career_score, platform_score |
| **Badge** | Certifications | name, description, type, icon, criteria |
| **UserBadge** | User badges | user, badge, awarded_at, expires_at |

### Views

#### Frontend Views (`accounts/views.py`)

**Authentication:**
- `LoginView` - User login
- `LogoutView` - User logout
- `RegisterView` - New user registration
- `PasswordResetView` - Password reset request
- `PasswordChangeView` - Change password

**Profile Management:**
- `ProfileView` - View/edit profile
- `ProfileUpdateView` - Update profile details
- `AvatarUploadView` - Upload profile photo
- `AccountSettingsView` - Account settings page

**KYC & Verification:**
- `KYCVerificationView` - Start KYC process
- `KYCStatusView` - Check verification status
- `EmploymentVerificationView` - Verify employment
- `EducationVerificationView` - Verify education

**2FA:**
- `TwoFactorSetupView` - Setup 2FA
- `TwoFactorVerifyView` - Verify 2FA code
- `TwoFactorDisableView` - Disable 2FA

#### API Views (`accounts/api/`)

```
/api/v1/accounts/profile/
/api/v1/accounts/kyc/
/api/v1/accounts/trust-score/
/api/v1/accounts/badges/
/api/v1/accounts/cvs/
```

### URL Structure

```python
# Authentication
accounts:login
accounts:logout
accounts:register
accounts:password_reset
accounts:password_change

# Profile
accounts:profile
accounts:profile_update
accounts:avatar_upload
accounts:settings

# KYC & Verification
accounts:kyc_verification
accounts:kyc_status
accounts:employment_verification
accounts:education_verification

# 2FA
accounts:2fa_setup
accounts:2fa_verify
accounts:2fa_disable
```

### Templates

Located in `templates_auth/`:

- `login.html` - Login page
- `register.html` - Registration page
- `password_reset.html` - Password reset
- `profile.html` - User profile page
- `profile_edit.html` - Profile editing
- `settings.html` - Account settings
- `kyc_verification.html` - KYC workflow
- `2fa_setup.html` - 2FA setup

## Integration Points

### With Other Apps

- **Tenants**: TenantUser model links users to tenants and roles
- **ATS**: Candidate profiles, recruiter profiles
- **HR Core**: Employee records
- **Services**: Provider/client profiles
- **Dashboard**: User-specific dashboards
- **Notifications**: User notification preferences

### External Services

- **Sumsub/Onfido**: KYC verification (planned)
- **Twilio Verify**: SMS 2FA (optional)
- **Email**: SendGrid for account emails
- **Storage**: S3/local for avatars and documents

## Security & Permissions

### Authentication Security

- Mandatory email verification
- Password complexity requirements
- Brute force protection (django-axes)
- Session timeout (15 minutes idle)
- 2FA mandatory for admin/HR roles
- JWT tokens for API access

### Permission Levels

| Role | Access Level |
|------|-------------|
| **PDG/CEO** | Full platform access, all tenants |
| **Supervisor** | Department-level access |
| **HR Manager** | HR operations, employee data |
| **Recruiter** | ATS access, candidate data |
| **Employee** | Personal dashboard, limited access |
| **Viewer** | Read-only access |

### Data Protection

- Password hashing with Django's PBKDF2
- Personal data encrypted at rest
- GDPR-compliant data handling
- Right to erasure support
- Data export functionality

## Future Improvements

### High Priority

1. **Complete KYC Integration**
   - Sumsub/Onfido API integration
   - Document upload and verification
   - Liveness detection
   - Identity badge system
   - Verification workflow automation

2. **Career Verification System**
   - Automated employment verification emails
   - Education verification via registrar APIs
   - LinkedIn profile verification
   - Reference checking system
   - Verification status tracking

3. **Trust Score Algorithm**
   - Multi-factor scoring:
     - Identity verification (Level 1)
     - Career verification (Level 2)
     - Platform activity and reviews
     - Dispute history
     - Completion rate
   - Transparent score breakdown
   - Score impact on search ranking

4. **Multi-CV Management**
   - Multiple CV profiles per user
   - Role-specific CVs
   - AI-powered CV suggestions
   - CV version control
   - Best CV auto-selection

5. **Progressive Data Revelation**
   - Stage-based data disclosure
   - Consent management
   - Automated data unlocking based on pipeline stage
   - Audit trail for data access

### Medium Priority

6. **Social Authentication**
   - Google OAuth
   - LinkedIn OAuth
   - Microsoft OAuth
   - GitHub OAuth (for developers)

7. **Advanced Profile Features**
   - Portfolio integration (GitHub, Behance, Dribbble)
   - Video introduction
   - Skills endorsements
   - Certifications management
   - Language proficiency

8. **Account Security Enhancements**
   - Security keys (WebAuthn)
   - Biometric authentication
   - Login history and device management
   - Suspicious activity alerts
   - Account recovery options

9. **Privacy Controls**
   - Granular privacy settings
   - Data visibility controls
   - Anonymous mode
   - Profile visibility settings
   - Search appearance preferences

10. **User Analytics**
    - Profile view tracking
    - Application success rates
    - Search appearance metrics
    - Engagement analytics

### Low Priority

11. **Gamification**
    - Achievement badges
    - Profile completion scores
    - Leaderboards
    - Rewards system

12. **Professional Network**
    - Connection requests
    - Recommendations
    - Endorsements
    - Professional groups

13. **Advanced Verification**
    - Video verification
    - Blockchain credentials
    - NFT badges
    - Verified skill tests

## Testing

### Test Coverage

Target: 95%+ coverage for authentication and security-critical code

### Test Structure

```
tests/
├── test_auth.py              # Authentication tests
├── test_profile.py           # Profile management tests
├── test_kyc.py               # KYC verification tests
├── test_permissions.py       # Permission tests
├── test_trust_score.py       # Trust score calculation tests
├── test_2fa.py               # 2FA tests
└── test_security.py          # Security tests
```

### Key Test Scenarios

- User registration and email verification
- Login with 2FA
- Password reset workflow
- Profile CRUD operations
- Permission enforcement
- Tenant isolation
- KYC verification flow
- Trust score calculation

## Performance Optimization

### Current Optimizations

- Profile data cached per session
- Permission caching
- Lazy loading of related data
- Optimized user queries with select_related

### Planned Optimizations

- Redis caching for trust scores
- Batch permission checks
- Async KYC verification
- Background trust score updates

## Security Considerations

### Critical Security Rules

1. **Never expose sensitive data in logs**
2. **Always hash passwords**
3. **Validate all user input**
4. **Enforce CSRF protection**
5. **Use HTTPS only**
6. **Implement rate limiting**
7. **Audit all authentication events**
8. **Encrypt personal data at rest**

### Compliance Requirements

- **GDPR**: Right to access, rectify, erase, port data
- **PIPEDA** (Canada): Consent management
- **CCPA** (California): Opt-out of data sale
- **eIDAS** (EU): Electronic signature compliance

## Migration Notes

When modifying user models:

```bash
# CRITICAL: User model changes affect all tenants
python manage.py makemigrations accounts

# Apply to shared schema (User model is shared)
python manage.py migrate_schemas --shared

# Verify migration
python manage.py check
```

## Contributing

When adding features to Accounts:

1. Security-critical code requires extra review
2. Always write tests for authentication flows
3. Update permission tests when adding new roles
4. Document any new security considerations
5. Ensure GDPR compliance for new data fields

## Support

For questions or issues:
- Review Django authentication documentation
- Check django-two-factor-auth docs
- Consult [SECURITY.md](../docs/SECURITY.md) for security guidelines

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production
