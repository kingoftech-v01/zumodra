# Zumodra API Documentation

**Version:** 1.0.0
**Base URL:** `https://api.zumodra.com/api/v1/`
**Last Updated:** December 2025

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Response Format](#response-format)
4. [Error Handling](#error-handling)
5. [Rate Limiting](#rate-limiting)
6. [Endpoints](#endpoints)
7. [Webhooks](#webhooks)

---

## Overview

The Zumodra API is a RESTful API that provides access to all platform functionality including:

- **ATS (Applicant Tracking System)** - Job postings, applications, interviews, offers
- **Marketplace** - Service listings, proposals, contracts, escrow
- **HR Core** - Employee management, time-off, onboarding
- **Accounts** - User management, KYC verification, trust scores
- **Notifications** - Real-time notifications and preferences

### Interactive Documentation

- **Swagger UI:** `/api/docs/`
- **ReDoc:** `/api/redoc/`
- **OpenAPI Schema:** `/api/schema/`

---

## Authentication

### JWT Token Authentication

Zumodra uses JWT (JSON Web Tokens) for API authentication.

#### Obtain Token

```bash
POST /api/v1/auth/token/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "your-password"
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Use Token

Include the access token in the `Authorization` header:

```bash
GET /api/v1/jobs/jobs/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

#### Refresh Token

```bash
POST /api/v1/auth/token/refresh/
Content-Type: application/json

{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Token Lifetimes

| Token Type | Lifetime | Notes |
|------------|----------|-------|
| Access Token | 1 hour | Used for API requests |
| Refresh Token | 7 days | Used to get new access tokens |

### Tenant Context

For multi-tenant operations, include the tenant header:

```bash
GET /api/v1/jobs/jobs/
Authorization: Bearer <token>
X-Tenant: tenant-slug
```

---

## Response Format

### Success Response

```json
{
    "status": "success",
    "data": {
        "id": 123,
        "title": "Senior Developer",
        "created_at": "2025-12-31T10:00:00Z"
    },
    "meta": {
        "request_id": "req_abc123"
    }
}
```

### Paginated Response

```json
{
    "count": 150,
    "next": "/api/v1/jobs/jobs/?page=2",
    "previous": null,
    "results": [
        {"id": 1, "title": "Job 1"},
        {"id": 2, "title": "Job 2"}
    ]
}
```

### Error Response

```json
{
    "status": "error",
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "Invalid input data",
        "details": {
            "email": ["This field is required."]
        }
    },
    "meta": {
        "request_id": "req_xyz789"
    }
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 204 | No Content | Successful deletion |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Invalid or missing token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 422 | Unprocessable | Business logic error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Error | Server error |

### Error Codes

| Code | Description |
|------|-------------|
| `VALIDATION_ERROR` | Input validation failed |
| `AUTHENTICATION_FAILED` | Invalid credentials |
| `TOKEN_EXPIRED` | JWT token has expired |
| `PERMISSION_DENIED` | User lacks required permission |
| `RESOURCE_NOT_FOUND` | Requested resource doesn't exist |
| `TENANT_NOT_FOUND` | Tenant doesn't exist or inactive |
| `RATE_LIMIT_EXCEEDED` | Too many requests |
| `BUSINESS_RULE_VIOLATION` | Business logic constraint failed |

---

## Rate Limiting

### Default Limits

| User Type | Limit | Period |
|-----------|-------|--------|
| Anonymous | 100 | per hour |
| Authenticated | 1,000 | per hour |
| Staff | 10,000 | per hour |

### Rate Limit Headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1704067200
```

### Handling Rate Limits

When rate limited, wait until the reset time:

```json
{
    "status": "error",
    "error": {
        "code": "RATE_LIMIT_EXCEEDED",
        "message": "Too many requests. Please wait 60 seconds.",
        "retry_after": 60
    }
}
```

---

## Endpoints

### ATS (Applicant Tracking System)

#### Jobs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/jobs/jobs/` | List all jobs |
| POST | `/api/v1/jobs/jobs/` | Create a job |
| GET | `/api/v1/jobs/jobs/{id}/` | Get job details |
| PUT | `/api/v1/jobs/jobs/{id}/` | Update job |
| DELETE | `/api/v1/jobs/jobs/{id}/` | Delete job |
| POST | `/api/v1/jobs/jobs/{id}/publish/` | Publish job |
| POST | `/api/v1/jobs/jobs/{id}/close/` | Close job |

**Create Job Example:**

```bash
POST /api/v1/jobs/jobs/
Authorization: Bearer <token>
Content-Type: application/json

{
    "title": "Senior Python Developer",
    "description": "We are looking for...",
    "department": "Engineering",
    "location": "Montreal, QC",
    "employment_type": "full_time",
    "salary_min": 80000,
    "salary_max": 120000,
    "salary_currency": "CAD",
    "pipeline_id": 1
}
```

#### Applications

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/jobs/applications/` | List applications |
| POST | `/api/v1/jobs/applications/` | Submit application |
| GET | `/api/v1/jobs/applications/{id}/` | Get application |
| POST | `/api/v1/jobs/applications/{id}/move-stage/` | Move to stage |
| POST | `/api/v1/jobs/applications/{id}/reject/` | Reject application |

#### Interviews

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/jobs/interviews/` | List interviews |
| POST | `/api/v1/jobs/interviews/` | Schedule interview |
| POST | `/api/v1/jobs/interviews/{id}/complete/` | Mark complete |
| POST | `/api/v1/jobs/interviews/{id}/feedback/` | Add feedback |

#### Offers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/jobs/offers/` | List offers |
| POST | `/api/v1/jobs/offers/` | Create offer |
| POST | `/api/v1/jobs/offers/{id}/send/` | Send offer |
| POST | `/api/v1/jobs/offers/{id}/accept/` | Accept offer |
| POST | `/api/v1/jobs/offers/{id}/decline/` | Decline offer |

---

### Marketplace

#### Services

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/marketplace/services/` | List services |
| POST | `/api/v1/marketplace/services/` | Create service |
| GET | `/api/v1/marketplace/services/{id}/` | Get service |

#### Proposals

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/marketplace/proposals/` | List proposals |
| POST | `/api/v1/marketplace/proposals/` | Create proposal |
| POST | `/api/v1/marketplace/proposals/{id}/accept/` | Accept |
| POST | `/api/v1/marketplace/proposals/{id}/decline/` | Decline |

#### Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/marketplace/contracts/` | List contracts |
| POST | `/api/v1/marketplace/contracts/` | Create contract |
| POST | `/api/v1/marketplace/contracts/{id}/fund/` | Fund escrow |
| POST | `/api/v1/marketplace/contracts/{id}/complete/` | Mark complete |
| POST | `/api/v1/marketplace/contracts/{id}/dispute/` | File dispute |

---

### Accounts & Verification

#### KYC Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/accounts/kyc/` | Get KYC status |
| POST | `/api/v1/accounts/kyc/submit/` | Submit KYC |
| GET | `/api/v1/accounts/trust-score/` | Get trust score |

#### User Profile

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/accounts/profile/` | Get profile |
| PUT | `/api/v1/accounts/profile/` | Update profile |
| GET | `/api/v1/accounts/cvs/` | List CVs |
| POST | `/api/v1/accounts/cvs/` | Create CV |

---

### Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/notifications/` | List notifications |
| POST | `/api/v1/notifications/{id}/read/` | Mark as read |
| GET | `/api/v1/notifications/preferences/` | Get preferences |
| PUT | `/api/v1/notifications/preferences/` | Update preferences |

---

### Health Checks

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health/` | Basic health |
| GET | `/health/ready/` | Readiness check |
| GET | `/health/live/` | Liveness check |

---

## Webhooks

### Configuring Webhooks

Webhooks can be configured in tenant settings to receive real-time notifications.

### Supported Events

| Event | Trigger |
|-------|---------|
| `application.created` | New job application |
| `application.status_changed` | Application status update |
| `interview.scheduled` | Interview scheduled |
| `offer.sent` | Offer sent to candidate |
| `offer.accepted` | Offer accepted |
| `contract.created` | New service contract |
| `contract.funded` | Escrow funded |
| `contract.completed` | Contract completed |
| `dispute.filed` | Dispute filed |

### Webhook Payload

```json
{
    "event": "application.created",
    "timestamp": "2025-12-31T10:00:00Z",
    "data": {
        "id": 123,
        "job_id": 456,
        "candidate_name": "John Doe"
    },
    "signature": "sha256=abc123..."
}
```

### Verifying Signatures

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

---

## SDKs & Code Examples

### Python

```python
import requests

class ZumodraClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {token}"}

    def list_jobs(self):
        response = requests.get(
            f"{self.base_url}/api/v1/jobs/jobs/",
            headers=self.headers
        )
        return response.json()

    def create_application(self, job_id, candidate_data):
        response = requests.post(
            f"{self.base_url}/api/v1/jobs/applications/",
            headers=self.headers,
            json={"job": job_id, **candidate_data}
        )
        return response.json()

# Usage
client = ZumodraClient("https://api.zumodra.com", "your-token")
jobs = client.list_jobs()
```

### JavaScript

```javascript
class ZumodraClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    }

    async listJobs() {
        const response = await fetch(
            `${this.baseUrl}/api/v1/jobs/jobs/`,
            { headers: this.headers }
        );
        return response.json();
    }

    async createApplication(jobId, candidateData) {
        const response = await fetch(
            `${this.baseUrl}/api/v1/jobs/applications/`,
            {
                method: 'POST',
                headers: this.headers,
                body: JSON.stringify({ job: jobId, ...candidateData })
            }
        );
        return response.json();
    }
}

// Usage
const client = new ZumodraClient('https://api.zumodra.com', 'your-token');
const jobs = await client.listJobs();
```

---

## Changelog

### v1.0.0 (December 2025)

- Initial API release
- ATS endpoints (jobs, applications, interviews, offers)
- Marketplace endpoints (services, proposals, contracts)
- KYC and verification endpoints
- Notification system

---

## Support

- **API Status:** https://status.zumodra.com
- **Developer Portal:** https://developers.zumodra.com
- **Support Email:** api-support@zumodra.com
