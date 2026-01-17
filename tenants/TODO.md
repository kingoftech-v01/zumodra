# Tenants App TODO

**Last Updated:** 2026-01-16
**Total Items:** 1
**Status:** Production

## Overview
The tenants app provides multi-tenant isolation and management using django-tenants with schema-based separation. Handles tenant provisioning, KYC verification, and domain routing.

## High Priority

### [TODO-TENANTS-001] EIN Verification API Integration
- **Priority:** High
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Medium (4-6h)
- **File:** `tenants/views.py:1341`
- **Description:**
  Implement actual EIN (Employer Identification Number) verification API integration. Currently stubbed with placeholder logic that always returns success.
- **Context:**
  The `verify_ein_number()` function in views.py contains commented-out example code showing the intended API integration pattern. This is critical for tenant KYC compliance.
- **Acceptance Criteria:**
  - [ ] Select and integrate EIN verification service (e.g., IRS Business API, commercial provider)
  - [ ] Add API credentials to settings (EIN_VERIFICATION_API_KEY, EIN_VERIFICATION_API_URL)
  - [ ] Implement actual API call with proper error handling
  - [ ] Handle rate limiting and timeouts (10s timeout recommended)
  - [ ] Map API responses to internal status codes ('verified', 'pending', 'invalid')
  - [ ] Add retry logic for network failures
  - [ ] Update tests to mock external API calls
  - [ ] Document API provider selection in README
- **Dependencies:**
  - API key for chosen EIN verification provider
  - Budget approval for API service fees
- **Notes:**
  - Current stubbed implementation in lines 1341-1380
  - Example shows requests library usage with Bearer token auth
  - Consider caching verified EINs to reduce API calls
  - May need to handle different EIN formats (XX-XXXXXXX)

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-TENANTS-XXX]` and update the central [TODO.md](../TODO.md) index.
