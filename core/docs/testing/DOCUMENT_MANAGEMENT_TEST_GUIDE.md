# Comprehensive Document Management System Test Guide

## Overview

This guide provides step-by-step instructions for testing the complete document management system in Zumodra, including:

1. Document upload (various file types)
2. Document categorization and tagging
3. Version control and history
4. E-signature workflow
5. Document expiration tracking
6. Access permissions and sharing
7. Document search and retrieval

## Prerequisites

### System Requirements
- Docker and Docker Compose installed
- Python 3.12+
- PostgreSQL 16+
- Redis 7+
- RabbitMQ 3.12+

### Environment Setup

1. Ensure `.env` file is configured:
```bash
cp .env.example .env
# Edit .env with necessary values
```

2. Key environment variables needed:
```
DEBUG=True
SECRET_KEY=your-secret-key
DB_NAME=zumodra
DB_USER=postgres
DB_PASSWORD=zumodra_dev_password
SITE_URL=http://localhost:8002
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0
```

### Starting the Server

```bash
# Start all services
docker compose up -d

# Verify services are healthy
docker compose ps

# View logs (if needed)
docker compose logs -f web
```

## Test Execution Checklist

### Phase 1: Service Health Check

**Test 1.1: Verify Docker Services**
```bash
# Command
docker compose ps

# Expected Output
NAME                  STATUS    PORTS
zumodra_web          Up        0.0.0.0:8002->8000/tcp
zumodra_channels     Up        0.0.0.0:8003->8001/tcp
zumodra_db           Up        127.0.0.1:5434->5432/tcp
zumodra_redis        Up        127.0.0.1:6380->6379/tcp
zumodra_rabbitmq     Up        127.0.0.1:5673->5672/tcp
zumodra_nginx        Up        0.0.0.0:8084->80/tcp
zumodra_mailhog      Up        0.0.0.0:8026->8025/tcp

# Pass Criteria: All services show "Up" status
```

**Test 1.2: Health Check Endpoint**
```bash
# Command
curl -v http://localhost:8002/health/

# Expected Response (Status: 200)
{
  "status": "healthy",
  "timestamp": "2026-01-16T00:00:00Z"
}

# Pass Criteria: Status code 200, response includes "healthy"
```

### Phase 2: Authentication Setup

**Test 2.1: User Registration**
```bash
# Using curl
curl -X POST http://localhost:8002/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testdoc@example.com",
    "password": "TestDocPassword123!",
    "password2": "TestDocPassword123!",
    "full_name": "Test Doc User"
  }'

# Expected Response (Status: 201)
{
  "id": 123,
  "email": "testdoc@example.com",
  "full_name": "Test Doc User",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}

# Pass Criteria: Status 201, token received
```

**Test 2.2: User Login**
```bash
# Using curl
curl -X POST http://localhost:8002/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testdoc@example.com",
    "password": "TestDocPassword123!"
  }'

# Expected Response (Status: 200)
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 123,
    "email": "testdoc@example.com"
  }
}

# Pass Criteria: Status 200, valid token returned
```

**Store the token for subsequent requests:**
```bash
export AUTH_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."
```

### Phase 3: Test Suite 1 - Document Upload

**Test 3.1: Upload PDF Document**
```bash
# Create a sample PDF
echo "%PDF-1.4" > sample.pdf
echo "Sample PDF content" >> sample.pdf

# Upload
curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@sample.pdf" \
  -F "title=Test PDF Document" \
  -F "category=form" \
  -F "description=Test PDF upload"

# Expected Response (Status: 201)
{
  "id": 1,
  "uuid": "12345678-1234-5678-...",
  "title": "Test PDF Document",
  "category": "form",
  "file": "http://localhost:8002/media/employee_documents/sample_abc.pdf",
  "file_type": "pdf",
  "status": "draft",
  "created_at": "2026-01-16T10:00:00Z"
}

# Pass Criteria: Status 201, document created with proper metadata
```

**Test 3.2: Upload DOCX Document**
```bash
# Create a simple DOCX (zip format with XML)
# For testing, create a minimal valid DOCX

curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@sample.docx" \
  -F "title=Test DOCX Document" \
  -F "category=contract" \
  -F "description=Test DOCX upload"

# Expected Response (Status: 201)
{
  "id": 2,
  "file_type": "docx",
  "status": "draft"
}

# Pass Criteria: Status 201, DOCX file accepted
```

**Test 3.3: Upload PNG Image**
```bash
# Create a simple PNG
# Using any image editor or ImageMagick

curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@sample.png" \
  -F "title=Test PNG Image" \
  -F "category=form" \
  -F "description=Test PNG upload"

# Expected Response (Status: 201)
{
  "id": 3,
  "file_type": "png",
  "status": "draft"
}

# Pass Criteria: Status 201, PNG accepted
```

**Test 3.4: Reject Invalid File Type**
```bash
# Try to upload an executable (should be rejected)
echo "MZ" > test.exe

curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@test.exe" \
  -F "title=Invalid File" \
  -F "category=other"

# Expected Response (Status: 400)
{
  "file": [
    "File extension 'exe' not allowed. Allowed extensions are: pdf, doc, docx, xls, xlsx, jpg, jpeg, png"
  ]
}

# Pass Criteria: Status 400, rejection message
```

**Test 3.5: Reject Oversized File**
```bash
# Create a file larger than 10MB
dd if=/dev/zero of=large_file.pdf bs=1M count=11

curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@large_file.pdf" \
  -F "title=Large File" \
  -F "category=form"

# Expected Response (Status: 400)
{
  "file": [
    "File size must be less than 10MB"
  ]
}

# Pass Criteria: Status 400, size validation error
```

### Phase 4: Test Suite 2 - Document Categorization

**Test 4.1: Test All Document Categories**
```bash
# Create documents in each category
for category in offer_letter contract nda policy form other; do
  curl -X POST http://localhost:8002/api/v1/hr/documents/ \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -F "file=@sample.pdf" \
    -F "title=Test $category" \
    -F "category=$category"
done

# Expected Response: Multiple 201 responses

# Verify categories are stored
curl http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.[] | .category' | sort | uniq

# Expected Output
"contract"
"form"
"nda"
"offer_letter"
"other"
"policy"

# Pass Criteria: All categories accepted and stored correctly
```

### Phase 5: Test Suite 3 - Document Retrieval and Search

**Test 5.1: List All Documents**
```bash
# Command
curl http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.'

# Expected Response (Status: 200)
{
  "count": 6,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 1,
      "title": "Test PDF Document",
      "category": "form",
      "status": "draft",
      "created_at": "2026-01-16T10:00:00Z"
    },
    ...
  ]
}

# Pass Criteria: Status 200, list includes all uploaded documents
```

**Test 5.2: Search Documents**
```bash
# Search by title
curl http://localhost:8002/api/v1/hr/documents/?search=PDF \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | length'

# Expected Response: 1

# Pass Criteria: Search finds matching documents
```

**Test 5.3: Retrieve Document Details**
```bash
# Get a specific document
curl http://localhost:8002/api/v1/hr/documents/1/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.'

# Expected Response (Status: 200)
{
  "id": 1,
  "uuid": "12345678-...",
  "title": "Test PDF Document",
  "category": "form",
  "description": "Test PDF upload",
  "file": "http://localhost:8002/media/...",
  "status": "draft",
  "requires_signature": false,
  "created_at": "2026-01-16T10:00:00Z"
}

# Pass Criteria: Status 200, all document fields present
```

### Phase 6: Test Suite 4 - E-Signature Workflow

**Test 6.1: Create Document Requiring Signature**
```bash
# Upload with requires_signature flag
curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@sample.pdf" \
  -F "title=Contract for Signature" \
  -F "category=contract" \
  -F "requires_signature=true"

# Expected Response (Status: 201)
{
  "id": 7,
  "status": "pending_signature",
  "requires_signature": true
}

# Store the document ID
export DOC_ID="7"

# Pass Criteria: Status 201, status is pending_signature
```

**Test 6.2: List Pending Signatures**
```bash
# Command
curl http://localhost:8002/api/v1/hr/documents/pending_signatures/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | length'

# Expected Response: >= 1

# Pass Criteria: At least one document in pending signatures
```

**Test 6.3: Sign Document**
```bash
# Sign the document
curl -X POST http://localhost:8002/api/v1/hr/documents/$DOC_ID/sign/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "signature_provider": "internal",
    "signature_data": "base64_encoded_signature"
  }'

# Expected Response (Status: 200)
{
  "id": 7,
  "status": "signed",
  "signed_at": "2026-01-16T11:00:00Z"
}

# Pass Criteria: Status 200, status changed to signed
```

**Test 6.4: Verify Signed Document Not in Pending**
```bash
# Command
curl http://localhost:8002/api/v1/hr/documents/pending_signatures/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | map(.id) | index(7)'

# Expected Response: null (document not found)

# Pass Criteria: Signed documents not in pending list
```

### Phase 7: Test Suite 5 - Document Expiration

**Test 7.1: Set Document Expiration**
```bash
# Create document with expiration date
EXPIRY_DATE=$(date -d "+30 days" +"%Y-%m-%d")

curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@sample.pdf" \
  -F "title=Expiring Document" \
  -F "category=policy" \
  -F "expires_at=$EXPIRY_DATE"

# Expected Response (Status: 201)
{
  "id": 8,
  "expires_at": "2026-02-15"
}

# Pass Criteria: Status 201, expiration date set
```

**Test 7.2: Check Expiration Field**
```bash
# Retrieve the document
curl http://localhost:8002/api/v1/hr/documents/8/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.expires_at'

# Expected Response
"2026-02-15"

# Pass Criteria: Expiration date is present and correct
```

**Test 7.3: Document Status on Expiration (Manual)**
```bash
# Note: This requires setting system date to after expiration date
# For now, verify the expires_at field is stored

# To test expiration logic:
# 1. Set up a document with expires_at in the past
# 2. Query the document
# 3. Verify status shows as "expired"

# This would require either:
# - Advancing system time (in development environment)
# - Creating a document and waiting (not practical)
# - Checking the model's expiration check logic

# Pass Criteria: Documents with past expiration dates are marked as expired
```

### Phase 8: Test Suite 6 - Access Permissions

**Test 8.1: Verify Document Owner Can Access**
```bash
# Upload document as testdoc@example.com
curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -F "file=@sample.pdf" \
  -F "title=My Private Document" \
  -F "category=form"

# Expected Response (Status: 201)
{
  "id": 9,
  "title": "My Private Document"
}

# Owner should be able to access
curl http://localhost:8002/api/v1/hr/documents/9/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.title'

# Expected Response
"My Private Document"

# Pass Criteria: Status 200, document accessible
```

**Test 8.2: Test User's Own Documents**
```bash
# Get current user's documents
curl http://localhost:8002/api/v1/hr/documents/my_documents/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | length'

# Expected Response: >= 1

# Pass Criteria: User can access their own documents
```

**Test 8.3: Verify Document Count by Category**
```bash
# Command
curl "http://localhost:8002/api/v1/hr/documents/?category=contract" \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.count'

# Expected Response: >= 1

# Pass Criteria: Filtering by category works and returns documents
```

### Phase 9: Test Suite 7 - Document Templates

**Test 9.1: List Document Templates**
```bash
# Command
curl http://localhost:8002/api/v1/hr/document-templates/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | length'

# Expected Response: >= 0 (may have pre-created templates)

# Pass Criteria: Status 200, templates list returned
```

**Test 9.2: View Template Details**
```bash
# Get first template (if exists)
curl http://localhost:8002/api/v1/hr/document-templates/1/ \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.'

# Expected Response (Status: 200)
{
  "id": 1,
  "name": "Offer Letter",
  "category": "offer_letter",
  "requires_signature": true,
  "placeholders": ["employee_name", "position", "salary"],
  "version": "1.0"
}

# Pass Criteria: Status 200, template details present
```

### Phase 10: Test Suite 8 - Document Filtering and Metadata

**Test 10.1: Filter by Category**
```bash
# Command
curl "http://localhost:8002/api/v1/hr/documents/?category=form" \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | .[0].category'

# Expected Response
"form"

# Pass Criteria: All results have matching category
```

**Test 10.2: Filter by Status**
```bash
# Command
curl "http://localhost:8002/api/v1/hr/documents/?status=draft" \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | .[0].status'

# Expected Response
"draft"

# Pass Criteria: All results have matching status
```

**Test 10.3: Filter by Multiple Criteria**
```bash
# Command
curl "http://localhost:8002/api/v1/hr/documents/?category=contract&status=signed" \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results | length'

# Expected Response: >= 0

# Pass Criteria: Filtering by multiple criteria works
```

**Test 10.4: Document Ordering**
```bash
# Order by creation date (newest first)
curl "http://localhost:8002/api/v1/hr/documents/?ordering=-created_at" \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.results[0:2] | .[0].created_at as $first | .[1].created_at as $second | ($first > $second)'

# Expected Response: true

# Pass Criteria: Documents ordered correctly
```

### Phase 11: Additional API Tests

**Test 11.1: Pagination**
```bash
# Get documents with pagination
curl "http://localhost:8002/api/v1/hr/documents/?page=1&page_size=5" \
  -H "Authorization: Bearer $AUTH_TOKEN" | jq '.count'

# Expected Response: number of total documents

# Pass Criteria: Pagination parameters work
```

**Test 11.2: Document Update**
```bash
# Update document metadata
curl -X PATCH http://localhost:8002/api/v1/hr/documents/1/ \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Updated Document Title",
    "description": "Updated description"
  }'

# Expected Response (Status: 200)
{
  "id": 1,
  "title": "Updated Document Title",
  "description": "Updated description"
}

# Pass Criteria: Status 200, metadata updated
```

**Test 11.3: Document Deletion**
```bash
# Delete a document
curl -X DELETE http://localhost:8002/api/v1/hr/documents/1/ \
  -H "Authorization: Bearer $AUTH_TOKEN"

# Expected Response (Status: 204 or 200)

# Verify deletion
curl http://localhost:8002/api/v1/hr/documents/1/ \
  -H "Authorization: Bearer $AUTH_TOKEN"

# Expected Response (Status: 404)
{
  "detail": "Not found."
}

# Pass Criteria: Document deleted successfully
```

## Automated Test Execution

Run the comprehensive test script:

```bash
# Make executable
chmod +x test_document_management_comprehensive.py

# Run tests
python test_document_management_comprehensive.py

# View results
cat tests_comprehensive/reports/document_management_test_report.json
```

## Troubleshooting

### Issue: Connection Refused
```
Error: Connection refused to localhost:8002
```
**Solution:**
- Verify Docker services: `docker compose ps`
- Check web service logs: `docker compose logs web`
- Ensure services are healthy: `docker compose up -d`

### Issue: 401 Unauthorized
```
Error: {
  "detail": "Authentication credentials were not provided."
}
```
**Solution:**
- Verify AUTH_TOKEN is set: `echo $AUTH_TOKEN`
- Re-authenticate: Follow Test 2.1 and 2.2
- Check token header: `Authorization: Bearer <TOKEN>`

### Issue: 403 Forbidden
```
Error: {
  "detail": "Permission denied."
}
```
**Solution:**
- Verify user role: Ensure user is HR Manager or Staff
- Check tenant permission: User must be in same tenant
- Review permission in admin: `http://localhost:8084/admin/`

### Issue: File Upload Fails
```
Error: {
  "file": ["This field is required."]
}
```
**Solution:**
- Use multipart/form-data encoding
- Include `Content-Type: application/json` headers
- Verify file field name is "file"

## Test Report Summary Template

After running tests, save results to:
`tests_comprehensive/reports/document_management_test_report.json`

Example report structure:
```json
{
  "total_tests": 30,
  "passed": 28,
  "failed": 2,
  "success_rate": "93.3%",
  "timestamp": "2026-01-16T10:00:00Z",
  "errors": [
    {
      "test": "Test 9.2",
      "error": "Template endpoint not implemented"
    }
  ],
  "test_suites": {
    "upload": { "passed": 5, "failed": 0 },
    "categorization": { "passed": 6, "failed": 0 },
    "retrieval": { "passed": 3, "failed": 0 },
    "esignature": { "passed": 4, "failed": 1 },
    "expiration": { "passed": 3, "failed": 0 },
    "permissions": { "passed": 3, "failed": 1 },
    "templates": { "passed": 2, "failed": 0 },
    "filtering": { "passed": 4, "failed": 0 }
  }
}
```

## Conclusion

This comprehensive test guide covers all major document management system features. Each test includes:
- Clear test objective
- Execution commands
- Expected responses
- Pass/fail criteria

Run all tests and document results for quality assurance.
