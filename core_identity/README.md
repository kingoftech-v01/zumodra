# Core Identity & Verification (PUBLIC Schema)

**Global user identity, marketplace profiles, and verification data shared across all tenants.**

## Overview

The `core_identity` app manages user identity and verification in the **PUBLIC schema**. This data is global across all tenants - a user's identity, KYC verification, trust score, and education credentials do not change based on which tenant they're accessing.

### Renamed from `custom_account_u`
- **Old name**: `custom_account_u`
- **New name**: `core_identity` (effective 2026-01-17)
- **Reason**: Clearer purpose - this app manages core identity and verification in PUBLIC schema

## Architecture Principles

### PUBLIC Schema Placement
All models in this app are in the PUBLIC (shared) schema because:
- **UserIdentity**: Personal identity data doesn't change per tenant
- **MarketplaceProfile**: Freelancer marketplace presence is platform-wide
- **KYCVerification**: Identity verification is global, not per-tenant
- **TrustScore**: Reputation aggregates from ALL tenant memberships
- **EducationVerification**: Degrees/credentials are universal
- **EmploymentHistory**: Work history visible across tenants for applications

### Key Concepts

1. **UserIdentity (ALWAYS created)**: Every user gets a UserIdentity automatically via signals
2. **MarketplaceProfile (OPTIONAL)**: Only created when user opts into freelance marketplace (is_active=False by default)
3. **Verification is Global**: KYC status is consistent across all tenants
4. **Trust Score Aggregation**: Platform-wide reputation from all tenant interactions

## Models

### 1. CustomUser
**Purpose**: Core user model (extends Django AbstractUser)

**Key Fields**:
- `uuid`: Global unique identifier
- `email`: Username field (unique)
- `mfa_enabled`: Whether MFA is enabled
- `mfa_grace_period_end`: When MFA becomes mandatory
- `anonymous_mode`: Privacy mode flag

**Removed Fields** (migrated to other models):
- `kyc_verified` → Use `KYCVerification.status`
- `cv_verified` → Use `EducationVerification.verified`

**Signals**:
- Auto-creates `UserIdentity` on user creation

---

### 2. UserIdentity
**Purpose**: Global personal identity (ALWAYS created for every user)

**Key Fields**:
- `display_name`: Public display name
- `avatar`: Profile picture
- `bio`: Personal bio
- `phone`: Contact phone
- `location_city`, `location_country`: Location
- `timezone`: User's timezone
- `linkedin_url`, `github_url`, `twitter_handle`, `website_url`: Social links

**Auto-Created**: Yes (via post_save signal on CustomUser)

**Example**:
```python
# Every user automatically has a UserIdentity
user = CustomUser.objects.create_user(email='marie@example.com')
user.identity.display_name  # "marie"
user.identity.bio = "Software engineer passionate about Django"
user.identity.save()
```

---

### 3. MarketplaceProfile
**Purpose**: OPTIONAL freelancer/marketplace identity

**Key Fields**:
- `is_active`: **CRITICAL** - defaults to False, user must activate
- `activated_at`: When profile was activated
- `professional_title`: Job title for marketplace
- `skills`: JSON array of skills
- `available_for_work`: Currently accepting work
- `hourly_rate_min`, `hourly_rate_max`: Rate range
- `portfolio_url`, `cv_file`: Portfolio assets
- `profile_visibility`: public, tenants_only, private
- `completed_projects`, `total_earnings`, `average_rating`: Stats

**Auto-Created**: **NO** - user must explicitly opt-in

**Activation**:
```python
# User activates marketplace profile
profile = MarketplaceProfile.objects.create(
    user=user,
    professional_title="Senior Django Developer",
    skills=["Python", "Django", "PostgreSQL"],
    is_active=False  # IMPORTANT: defaults to False
)

# User activates after filling out profile
profile.activate()  # Sets is_active=True, activated_at=now()
```

---

For complete model documentation, migration guides, API endpoints, and testing procedures, see the full README in `/home/kingoftech/zumodra/core_identity/README.md`.

---

## Changelog

### 2026-01-17: Phase 10 Refactoring
- ✅ Renamed app from `custom_account_u` to `core_identity`
- ✅ Created UserIdentity model (ALWAYS created)
- ✅ Created MarketplaceProfile model (OPTIONAL with is_active flag)
- ✅ Moved KYCVerification, TrustScore, EducationVerification, EmploymentHistory to PUBLIC schema
- ✅ Created UnifiedMFAEnforcementMiddleware (30-day grace period)
- ✅ Removed django-otp (consolidated on allauth.mfa)
- ✅ Removed iDenfy stub code (consolidated on Onfido)
- ✅ Created data migration and import update commands

---

**Last Updated**: 2026-01-17
**Author**: Zumodra Team
