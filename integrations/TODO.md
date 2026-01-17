# Integrations App TODO

**Last Updated:** 2026-01-16
**Total Items:** 3
**Status:** Production

## Overview
The integrations app provides external service connectivity including calendar sync (Google/Outlook), job board posting (LinkedIn/Indeed), OAuth flows, webhook management, and integration event logging.

## Medium Priority

### [TODO-INTEGRATIONS-001] Add Support for Additional Calendar Providers
- **Priority:** Medium
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Large (8-10h per provider)
- **File:** `integrations/services.py:535`
- **Description:**
  Extend calendar integration to support additional providers beyond Google Calendar and Microsoft Outlook.
- **Context:**
  Currently only Google Calendar and Outlook Calendar are supported. Users may request integration with other calendar systems. The `create_event()` method raises `NotImplementedError` for unsupported providers.
- **Potential Providers:**
  - Apple Calendar (iCloud)
  - Zoho Calendar
  - FastMail Calendar
  - NextCloud Calendar
  - CalDAV generic support (covers multiple providers)
- **Acceptance Criteria (per provider):**
  - [ ] Research provider's calendar API documentation
  - [ ] Add OAuth configuration for provider
  - [ ] Implement authentication flow
  - [ ] Create event creation method (`_create_{provider}_event`)
  - [ ] Create event update method (`_update_{provider}_event`)
  - [ ] Create event deletion method (`_delete_{provider}_event`)
  - [ ] Implement event sync/fetch functionality
  - [ ] Add provider to Integration.PROVIDER_CHOICES
  - [ ] Handle rate limiting per provider
  - [ ] Add error handling for provider-specific errors
  - [ ] Write integration tests with mocked API
  - [ ] Document setup in integration guide
- **Dependencies:**
  - OAuth credentials for each provider
  - API client libraries (if available)
- **Notes:**
  - Line 530-535 in services.py shows current pattern
  - CalDAV support would cover many providers at once
  - Consider user demand before prioritizing specific providers
  - Each provider has different rate limits and capabilities

## Low Priority

### [TODO-INTEGRATIONS-002] Add Support for Additional Job Board Providers
- **Priority:** Low
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Large (8-10h per provider)
- **File:** `integrations/services.py:1128`
- **Description:**
  Extend job board integration to support additional providers beyond LinkedIn and Indeed.
- **Context:**
  Currently only LinkedIn and Indeed job posting is supported. The `post_job()` method raises `NotImplementedError` for other providers.
- **Potential Providers:**
  - Glassdoor
  - ZipRecruiter
  - Monster
  - CareerBuilder
  - Dice (tech jobs)
  - AngelList/Wellfound (startups)
  - RemoteOK (remote jobs)
  - We Work Remotely
- **Acceptance Criteria (per provider):**
  - [ ] Research provider's job posting API
  - [ ] Add API authentication configuration
  - [ ] Implement job posting method (`_post_{provider}_job`)
  - [ ] Implement application sync method (`_sync_{provider}_applications`)
  - [ ] Implement job status update method
  - [ ] Map Zumodra job fields to provider's schema
  - [ ] Handle job approval workflows (if required)
  - [ ] Add provider to Integration.PROVIDER_CHOICES
  - [ ] Handle rate limiting and costs
  - [ ] Add error handling for provider-specific errors
  - [ ] Write integration tests with mocked API
  - [ ] Document pricing and setup requirements
- **Dependencies:**
  - API credentials for each provider
  - Budget for job posting fees (many charge per post)
- **Notes:**
  - Line 1123-1128 in services.py
  - Many job boards charge per posting or require subscriptions
  - Prioritize based on customer requests
  - Some providers have limited API access

### [TODO-INTEGRATIONS-003] Token Refresh Abstract Method Implementation
- **Priority:** Low
- **Category:** Architecture (By Design)
- **Status:** Not Started (Expected Behavior)
- **Effort:** N/A
- **File:** `integrations/services.py:107`
- **Description:**
  The `_do_token_refresh()` method in `BaseIntegrationService` raises `NotImplementedError`. This is intentional - subclasses must implement provider-specific token refresh logic.
- **Context:**
  OAuth token refresh logic differs by provider (different endpoints, parameters, grant types). Each integration subclass must implement its own refresh mechanism.
- **Resolution:**
  - This is working as designed - no action needed
  - Abstract method enforces subclass implementation
  - Prevents silent failures from missing token refresh
- **Possible Enhancement:**
  - [ ] Inherit from `abc.ABC` and mark with `@abstractmethod`
  - [ ] Add docstring examples showing Google/Outlook implementations
  - [ ] Create helper methods for common OAuth2 refresh patterns
  - [ ] Add type hints for return values and parameters
  - [ ] Document token refresh flow in integration guide
- **Dependencies:**
  - None
- **Notes:**
  - Line 105-107 in services.py
  - Not a bug - architectural pattern
  - Each provider's token refresh is implemented in subclass
  - Low priority since pattern is working correctly

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-INTEGRATIONS-XXX]` and update the central [TODO.md](../TODO.md) index.
