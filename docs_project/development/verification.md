# Verification System Documentation

## Overview

Zumodra implements a three-level verification system:

### User-Level Verification (Global)
- **CV Verification**: Professional credentials verification
- **KYC Verification**: Identity verification (Know Your Customer)

### Tenant-Level Verification
- **EIN Verification**: Business/employer identification number verification

## User Verification

### CV Verification

Users can submit their CV/resume for verification by administrators.

**Supported Formats:**
- PDF (.pdf)
- Microsoft Word (.doc, .docx)
- Maximum file size: 5MB

**API Endpoint:**
```
POST /api/accounts/verify/cv/
```

**Request (multipart/form-data):**
```
cv_file: <file>
```

**Response:**
```json
{
  "status": "submitted",
  "message": "CV submitted for verification."
}
```

**Workflow:**
1. User uploads CV via API or web interface
2. Admin reviews CV in admin panel
3. Admin marks `cv_verified=True` and sets `cv_verified_at` timestamp
4. User receives verified badge in profile

### KYC Verification

Users submit identity documents for Know Your Customer compliance.

**Supported Document Types:**
- Passport
- Driver's License
- National ID

**Supported File Formats:**
- PDF (.pdf)
- JPEG (.jpg, .jpeg)
- PNG (.png)
- Maximum file size: 5MB

**API Endpoint:**
```
POST /api/accounts/verify/kyc/
```

**Request (multipart/form-data):**
```json
{
  "document_type": "passport",
  "document_file": <file>,
  "document_number": "AB123456"
}
```

**Response:**
```json
{
  "status": "submitted",
  "message": "KYC documents submitted for review.",
  "document_type": "passport"
}
```

**Workflow:**
1. User uploads identity document
2. System validates file type and size
3. Admin reviews document in verification dashboard
4. Admin marks `kyc_verified=True` and sets `kyc_verified_at` timestamp
5. User receives verified badge

## Tenant Verification

### EIN Verification

Companies/organizations can verify their business registration number.

**Format Requirements:**
- US EIN format: `XX-XXXXXXX` (e.g., `12-3456789`)
- 9 digits total, separated by hyphen after 2nd digit

**API Endpoint:**
```
POST /api/tenants/verify/ein/
```

**Request:**
```json
{
  "ein_number": "12-3456789"
}
```

**Response:**
```json
{
  "status": "submitted",
  "message": "EIN submitted for verification.",
  "ein_number": "12-3456789"
}
```

**Workflow:**
1. Tenant owner/admin submits EIN
2. System validates format
3. (Optional) External API call for verification
4. Admin reviews and marks `ein_verified=True`
5. Tenant receives verified business badge

## Verification Status

### Get All Verification Status

**API Endpoint:**
```
GET /api/accounts/verify/status/
```

**Response:**
```json
{
  "cv_verified": true,
  "cv_verified_at": "2026-01-09T10:00:00Z",
  "kyc_verified": false,
  "kyc_verified_at": null,
  "ein_verified": true,
  "ein_verified_at": "2026-01-09T15:30:00Z"
}
```

**Notes:**
- `ein_verified` fields only included if user is part of a tenant
- Timestamps are in ISO 8601 format (UTC)

### Get Submitted Documents

**API Endpoint:**
```
GET /api/accounts/verify/documents/
```

**Response:**
```json
{
  "kyc_documents": [],
  "cv_documents": [],
  "message": "Document listing feature will be available soon."
}
```

**Note:** This endpoint is a placeholder for future document management.

## EIN Verification Status

**API Endpoint:**
```
GET /api/tenants/verify/ein/status/
```

**Response:**
```json
{
  "ein_number": "12-3456789",
  "ein_verified": true,
  "ein_verified_at": "2026-01-09T15:30:00Z"
}
```

**Requirements:**
- User must be authenticated
- User must be part of a tenant

## UI Components

### Verification Badges Component

Display verification status with color-coded badges.

**Usage:**
```django
{% include 'components/verification_badges.html' with user_obj=user %}
{% include 'components/verification_badges.html' with tenant_obj=tenant %}
```

**Features:**
- Green badge for verified
- Gray badge for pending
- Tooltips showing verification date
- SVG icons for visual appeal

### CV Verification Component

Drag-and-drop CV upload interface.

**Usage:**
```django
{% include 'components/cv_verification.html' %}
```

**Features:**
- File upload with validation
- Shows current verification status
- HTMX-powered for seamless UX
- Displays "What happens after upload" info

### EIN Verification Form Component

Business number verification form.

**Usage:**
```django
{% include 'components/ein_verification_form.html' with tenant=request.tenant %}
```

**Features:**
- Format validation (XX-XXXXXXX)
- Shows verification status
- "Why verify?" section with benefits
- HTMX-powered submission

## Admin Workflow

### Approving CV Verification

1. Navigate to Django Admin → Custom Account U → Custom Users
2. Select user
3. Scroll to verification fields
4. Check "Cv verified" checkbox
5. "Cv verified at" will auto-populate with current timestamp
6. Click "Save"

### Approving KYC Verification

1. Navigate to Django Admin → Accounts → KYC Verification
2. Review submitted documents
3. For user's record in Custom Users:
   - Check "Kyc verified" checkbox
   - "Kyc verified at" will auto-populate
4. Click "Save"

### Approving EIN Verification

1. Navigate to Django Admin → Tenants → Tenants
2. Select tenant
3. Verify EIN number matches business registration
4. Check "Ein verified" checkbox
5. "Ein verified at" will auto-populate
6. Click "Save"

## Security Considerations

### File Upload Validation

All file uploads are validated for:
- **File size**: Maximum 5MB
- **File type**: Only allowed MIME types accepted
- **Virus scanning**: (Implement with ClamAV if needed)

### Data Privacy

- KYC documents contain sensitive personal information
- Store documents securely with encryption at rest
- Implement access controls (only admins can view)
- Comply with GDPR/privacy regulations
- Implement data retention policies

### API Security

- All verification endpoints require authentication
- EIN endpoints additionally require tenant membership
- Rate limiting applied to prevent abuse
- CSRF protection enabled for form submissions

## Error Handling

### Invalid File Type
```json
{
  "cv_file": [
    "Unsupported file type. Use PDF, DOC, or DOCX."
  ]
}
```

### File Too Large
```json
{
  "document_file": [
    "File size exceeds 5MB limit."
  ]
}
```

### Invalid EIN Format
```json
{
  "ein_number": [
    "Invalid EIN format. Expected format: XX-XXXXXXX (e.g., 12-3456789)"
  ]
}
```

### Not Part of Tenant
```json
{
  "error": "You must be part of a tenant to verify EIN."
}
```

## Integration Examples

### Frontend (JavaScript)

**Submit CV:**
```javascript
const formData = new FormData();
formData.append('cv_file', fileInput.files[0]);

const response = await fetch('/api/accounts/verify/cv/', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
  },
  body: formData
});

const data = await response.json();
console.log(data.message);
```

**Get Verification Status:**
```javascript
const response = await fetch('/api/accounts/verify/status/', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
  }
});

const status = await response.json();
if (status.cv_verified) {
  showVerifiedBadge();
}
```

### Backend (Python)

**Check if user is verified:**
```python
from custom_account_u.models import CustomUser

user = CustomUser.objects.get(email='user@example.com')
if user.cv_verified and user.kyc_verified:
    print("User is fully verified")
```

**Manually verify user:**
```python
from django.utils import timezone

user.cv_verified = True
user.cv_verified_at = timezone.now()
user.save(update_fields=['cv_verified', 'cv_verified_at'])
```

## Future Enhancements

### Planned Features

1. **Automatic EIN Verification**
   - Integration with IRS EIN verification API
   - Real-time business validation

2. **Document Management**
   - View submitted documents in user dashboard
   - Download verification certificates
   - Track verification history

3. **Verification Levels**
   - Basic: Email + Phone
   - Standard: + CV verification
   - Enhanced: + KYC verification
   - Complete: + EIN verification (for tenants)

4. **Automated Workflows**
   - Email notifications when verified
   - Expiration reminders for KYC documents
   - Batch verification tools for admins

5. **Third-Party Integrations**
   - Stripe Identity verification
   - Onfido/Jumio for KYC
   - Plaid for business verification

## Troubleshooting

### CV Upload Fails

**Issue:** File upload returns 400 error

**Solutions:**
- Check file size (must be ≤5MB)
- Verify file format (PDF, DOC, DOCX only)
- Ensure authentication token is valid

### EIN Verification Not Showing

**Issue:** EIN verification fields not visible

**Solutions:**
- Confirm user is part of a tenant
- Check tenant type (available for all tenant types)
- Verify user has permission (owner/admin)

### Verification Status Not Updating

**Issue:** Admin marked as verified but UI still shows unverified

**Solutions:**
- Clear browser cache
- Check database: `user.cv_verified` field value
- Ensure `cv_verified_at` timestamp is set
- Refresh verification status API call

## See Also

- [Tenant Type System](api/tenant_types.md) - Tenant type capabilities
- [UI Components](components.md) - Verification UI components
- [API Reference](api/) - Complete API documentation
