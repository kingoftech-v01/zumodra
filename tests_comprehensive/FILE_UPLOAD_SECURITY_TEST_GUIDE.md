# File Upload/Download Security Testing Guide

**Test Date:** January 16, 2026
**Version:** 1.0
**Status:** Active Development

---

## Table of Contents

1. [Overview](#overview)
2. [Test Architecture](#test-architecture)
3. [Security Test Categories](#security-test-categories)
4. [Configuration Audit](#configuration-audit)
5. [Running the Tests](#running-the-tests)
6. [Results Analysis](#results-analysis)
7. [Remediation Guide](#remediation-guide)
8. [Best Practices](#best-practices)

---

## Overview

This comprehensive testing suite validates security controls around file upload and download functionality in the Zumodra platform. It tests for common vulnerabilities including:

- **Unrestricted File Upload** - Uploading executable or dangerous files
- **Path Traversal** - Writing files outside intended directory
- **MIME Type Confusion** - Using incorrect MIME types to bypass validation
- **Polyglot Files** - Files that are both image and executable
- **Cross-Tenant File Access** - Unauthorized access to other tenant's files
- **Filename Manipulation** - Special characters, Unicode, null bytes in filenames

### Affected Components

| Component | File Fields | Upload Endpoints |
|-----------|------------|-----------------|
| **Accounts** | avatar, cv_file, transcript_file, diploma_file | /api/v1/accounts/profile, /api/v1/accounts/education |
| **ATS** | resume | /api/v1/ats/candidates/upload-resume |
| **Appointments** | image | /api/v1/appointments/services |
| **KYC** | document_file | /api/v1/accounts/kyc/upload-document |
| **AI Matching** | resume_file | /api/v1/ai-matching/resume-upload |

---

## Test Architecture

### Test Framework

```
tests_comprehensive/
├── test_file_upload_download_security.py    # Main test suite
├── run_file_security_tests.sh               # Test execution script
├── FILE_UPLOAD_SECURITY_TEST_GUIDE.md       # This file
└── reports/                                 # Test results
    ├── file_security_test_[timestamp].md    # Detailed report
    ├── file_security_test_[timestamp].json  # Machine-readable results
    └── test_output_[timestamp].log          # Raw test output
```

### Test Classes

1. **TestFileTypeValidation** - Verifies file type restrictions
2. **TestFileSizeValidation** - Tests size limit enforcement
3. **TestFilenameSanitization** - Validates filename processing
4. **TestPathTraversalPrevention** - Tests directory escape prevention
5. **TestSecureFileStorage** - Verifies secure storage practices
6. **TestDownloadAccessControl** - Tests access restrictions
7. **TestMalwareScanning** - Checks malware detection (if enabled)
8. **TestFileAccessLogging** - Verifies audit logging
9. **TestMimeTypeValidation** - Tests MIME type handling
10. **TestFileMetadataHandling** - Validates metadata safety

---

## Security Test Categories

### 1. File Type Validation

**Objective:** Ensure only whitelisted file types are accepted

**Test Cases:**

```python
# Allowed Types
✓ PNG, JPG, GIF, WebP (images)
✓ PDF, DOC, DOCX, RTF, TXT (documents)

# Blocked Types
✗ EXE, BAT, COM (Windows executables)
✗ SH, bash, zsh (Shell scripts)
✗ PHP, JSP, ASP (Server-side code)
✗ JAR, APP, DMG (Application packages)
✗ ZIP, RAR, 7Z (Archives)
```

**Vulnerabilities Tested:**

| Vulnerability | Test | Expected Result |
|---|---|---|
| **Executable Upload** | Upload .exe file | REJECTED |
| **Script Upload** | Upload .sh file | REJECTED |
| **Polyglot File** | Upload PHP content with JPG extension | REJECTED or SAFE |
| **Double Extension** | Upload shell.php.jpg | REJECTED or RENAMED |
| **Null Byte** | Upload image.jpg%00.php | REJECTED |

**File Type Configuration (Django):**

```python
# In models.py
class PublicProfile(models.Model):
    avatar = models.ImageField(
        upload_to='avatars/',
        validators=[
            FileExtensionValidator(
                allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'webp']
            )
        ],
        help_text='Allowed formats: JPG, PNG, GIF, WebP. Max size: 5MB'
    )

class Candidate(models.Model):
    resume = models.FileField(
        upload_to='resumes/',
        validators=[
            FileExtensionValidator(
                allowed_extensions=['pdf', 'doc', 'docx', 'rtf', 'txt']
            )
        ],
        help_text='Allowed formats: PDF, DOC, DOCX, RTF, TXT. Max size: 10MB'
    )
```

### 2. File Size Limits

**Objective:** Enforce maximum file sizes to prevent storage exhaustion

**Configured Limits:**

```
Avatar Images:      5 MB
CV/Resume Files:    10 MB
Education Files:    10 MB
KYC Documents:      50 MB
General Documents:  50 MB
```

**Django Configuration:**

```python
# In settings.py
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB in-memory limit
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # Form data limit
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755
FILE_UPLOAD_PERMISSIONS = 0o644
```

**Test Cases:**

```
✓ File at 90% of limit - ACCEPTED
✓ File at limit - ACCEPTED or REJECTED (edge case)
✗ File exceeding limit - REJECTED
✗ Zero-byte file - REJECTED
✗ Gigantic file (>100MB) - REJECTED early
```

### 3. Filename Sanitization

**Objective:** Prevent attacks via specially crafted filenames

**Attack Patterns Tested:**

```python
# Path Traversal
../../../etc/passwd
....//....//etc//passwd
..%2f..%2fetc%2fpasswd

# Null Bytes
image.jpg\x00.exe
file.pdf\x00.php

# Shell Injection
image;cat etc/passwd.png
image|whoami.png
image`id`.png
image$(whoami).png

# Command Substitution
${IFS}cat${IFS}/etc/passwd
command injection.png
```

**Safe Filename Handling:**

```python
# Django's default behavior
- Filenames are stored with upload_to prefix
- Special characters are typically removed or escaped
- Unicode is preserved but sanitized
- Path separators are removed

Example:
Input:    ../../../etc/passwd
Stored:   avatars/passwd_abc123.jpg
```

### 4. Path Traversal Prevention

**Objective:** Prevent files from being written outside media directory

**Test Cases:**

```python
# Direct Traversal
filename = "../../../etc/passwd"
# Should store in: /media/avatars/passwd_[random]

# Encoded Traversal
filename = "..%2f..%2f..%2fetc%2fpasswd"
# Should be decoded and rejected or sanitized

# Double Encoding
filename = "..%252f..%252fetc%252fpasswd"
# Should reject or handle safely

# Symlink Traversal
# Create symlink to sensitive file
# Upload via symlink
# Should either reject symlinks or verify path safety
```

**Django Protection:**

```python
# FileField automatically:
1. Stores in MEDIA_ROOT/upload_to/
2. Removes path separators from filename
3. Generates random filename suffix
4. Never executes uploaded content

# Additional safety:
os.path.normpath()  # Normalize path
os.path.realpath()  # Resolve symlinks
os.path.commonpath() # Verify within MEDIA_ROOT
```

### 5. Secure File Storage

**Objective:** Verify files are stored securely, outside web root

**Storage Locations:**

```
MEDIA_ROOT:  /var/lib/zumodra/media/  (outside web root)
STATIC_ROOT: /var/lib/zumodra/static/ (served separately)
WEB_ROOT:    /app/                     (web-accessible only)

File Permissions:
Directory: 0o755 (rwxr-xr-x)
Files:     0o644 (rw-r--r--)
Sensitive: 0o600 (rw-------)
```

**Tests:**

```
✓ Files not in /app/static/ or /app/public/
✓ Files not web-accessible without going through Django
✓ Media directory not in project root
✓ Proper file ownership
✓ No directory listing enabled
✓ No .htaccess or nginx config exposing files
```

### 6. Download Access Control

**Objective:** Ensure only authorized users can download files

**Access Control Matrix:**

| User Type | Own Files | Tenant Files | Other Tenant | Public |
|-----------|-----------|--------------|--------------|--------|
| **Owner** | ✓ Allow | ✓ If allowed by role | ✗ Block | ✓ If public |
| **Tenant Admin** | ✓ Allow | ✓ Allow | ✗ Block | ✓ If public |
| **Recruiter** | ✓ Allow | ✓ If assigned | ✗ Block | ✓ If public |
| **Guest** | ✗ Block | ✗ Block | ✗ Block | ✓ If public |

**Test Cases:**

```python
def test_unauthenticated_file_access():
    """Anonymous user cannot access private files"""
    file_url = profile.avatar.url
    response = client.get(file_url)
    assert response.status_code in [403, 404, 302]  # Redirect to login

def test_cross_tenant_access():
    """User cannot access files from other tenant"""
    other_file_url = other_tenant_profile.avatar.url
    client.force_authenticate(user=my_user)
    response = client.get(other_file_url)
    assert response.status_code in [403, 404]

def test_role_based_download():
    """Download only if user has appropriate role"""
    # Candidate cannot download recruiter's files
    # Recruiter can download assigned candidate files
```

### 7. MIME Type Validation

**Objective:** Prevent MIME type spoofing attacks

**Magic Byte Validation:**

```python
# Magic Bytes (File Signatures)
PNG:  89 50 4E 47 (‰PNG)
JPG:  FF D8 FF E0 (ÿØÿà)
GIF:  47 49 46 38 (GIF8)
PDF:  25 50 44 46 (%PDF)
ZIP:  50 4B 03 04 (PK..)

# Test Cases
✗ File with PDF header + .jpg extension → REJECT or RENAME
✗ PHP code with image MIME type → REJECT or ESCAPE
✓ Actual PNG with image/png MIME → ACCEPT
```

**Implementation:**

```python
def validate_file_type(file_obj):
    """Validate file by magic bytes, not just extension"""
    import magic

    mime_type = magic.from_buffer(file_obj.read(1024), mime=True)
    allowed_types = {
        'image/png', 'image/jpeg', 'image/gif',
        'application/pdf', 'text/plain'
    }

    if mime_type not in allowed_types:
        raise ValidationError(f"File type {mime_type} not allowed")
```

### 8. Malware/Virus Scanning

**Objective:** Detect and block known malware

**ClamAV Integration (Optional):**

```python
# If configured in settings.py
CLAMD_HOST = 'clamd'  # Docker service
CLAMD_PORT = 3310

# EICAR test file (recognized by all AV)
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Should be detected and blocked
response = upload_file(eicar)
assert response.status_code in [400, 403]
```

---

## Configuration Audit

### Django Settings Checklist

```python
# ✓ File Upload Settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755
FILE_UPLOAD_PERMISSIONS = 0o644

# ✓ Media Configuration
MEDIA_ROOT = '/var/lib/zumodra/media/'  # Outside web root
MEDIA_URL = '/media/'                    # Served via Django or separate server
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ✓ Security Headers
SECURE_CONTENT_SECURITY_POLICY = {
    'DEFAULT_SRC': ("'self'",),
    'MEDIA_SRC': ("'self'",),
    'IMG_SRC': ("'self'",),
}

# ✓ MIME Type Validation
MIMETYPES_ALLOWED = {
    'image': ['png', 'jpg', 'jpeg', 'gif', 'webp'],
    'document': ['pdf', 'doc', 'docx', 'txt', 'rtf'],
}

# ✓ File Upload Handlers
FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.MemoryFileUploadHandler',
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]

# ✓ Temporary File Cleanup
FILE_UPLOAD_TEMP_DIR = '/tmp/django-uploads/'
CLEANUP_TEMP_FILES = True
TEMP_FILE_CLEANUP_TIMEOUT = 3600  # 1 hour
```

### Nginx Configuration

```nginx
# Secure media serving configuration
location /media/ {
    # Add security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Disable script execution
    location ~ \.(php|sh|exe|bat)$ {
        return 403;
    }

    # Force download for sensitive types
    location ~ \.(pdf|doc)$ {
        add_header Content-Disposition "attachment";
    }

    # Prevent directory listing
    autoindex off;

    # Set proper MIME types
    types {
        image/png png;
        image/jpeg jpg jpeg;
        application/pdf pdf;
        text/plain txt;
    }

    alias /var/lib/zumodra/media/;
}
```

---

## Running the Tests

### Prerequisites

```bash
# Ensure Docker is running
docker-compose ps

# Ensure test database is ready
python manage.py migrate

# Install test requirements
pip install pytest pytest-django pytest-cov django-extensions
```

### Quick Test Run

```bash
# Run all file security tests
cd /c/Users/techn/OneDrive/Documents/zumodra
pytest tests_comprehensive/test_file_upload_download_security.py -v -m security

# Run specific test category
pytest tests_comprehensive/test_file_upload_download_security.py::TestFileTypeValidation -v

# Run with coverage
pytest tests_comprehensive/test_file_upload_download_security.py --cov=accounts --cov=ats --cov-report=html

# Generate JSON report
pytest tests_comprehensive/test_file_upload_download_security.py --json-report
```

### Full Test Suite Execution

```bash
# Make script executable
chmod +x tests_comprehensive/run_file_security_tests.sh

# Run complete test suite with Docker
./tests_comprehensive/run_file_security_tests.sh

# View results
cat tests_comprehensive/reports/file_security_test_*.md
```

### Continuous Integration

```yaml
# .github/workflows/file-security-tests.yml
name: File Security Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: docker/setup-buildx-action@v1
      - name: Run security tests
        run: |
          docker-compose up -d
          docker-compose exec -T web \
            pytest tests_comprehensive/test_file_upload_download_security.py \
            -v --tb=short --json-report
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-test-results
          path: tests_comprehensive/reports/
```

---

## Results Analysis

### Interpreting Test Output

```
PASSED - Security control is effective
FAILED - Vulnerability found, needs investigation
SKIPPED - Test not applicable or precondition not met
XFAIL - Expected failure (known limitation)
```

### Critical Vulnerabilities

If any of these tests fail, treat as CRITICAL:

1. **Executable files accepted** - Can lead to RCE
2. **Path traversal successful** - Can access sensitive files
3. **Cross-tenant access** - Data breach risk
4. **No size limits** - DoS vulnerability
5. **Malicious code execution** - Remote code execution

### Report Contents

Each test report includes:

```
1. Test Summary
   - Total tests run
   - Passed/Failed/Skipped count
   - Execution time

2. Detailed Results
   - Test name and description
   - Status (pass/fail)
   - Error messages (if failed)
   - Stack traces (if failed)

3. Vulnerability Assessment
   - List of found vulnerabilities
   - Severity levels
   - Affected components

4. Recommendations
   - Critical fixes required
   - High priority improvements
   - Medium/low priority enhancements

5. Configuration Audit Results
   - Settings checked
   - Compliance status
   - Missing configurations
```

---

## Remediation Guide

### Critical Fixes

#### 1. File Type Validation Bypass

**Issue:** Executable files are accepted

**Solution:**

```python
# In models.py - add validator
from django.core.validators import FileExtensionValidator

class Candidate(models.Model):
    resume = models.FileField(
        upload_to='resumes/',
        validators=[
            FileExtensionValidator(
                allowed_extensions=['pdf', 'doc', 'docx', 'rtf', 'txt']
            )
        ]
    )

# In forms.py - add field validator
class CandidateForm(forms.ModelForm):
    resume = forms.FileField(
        validators=[
            FileExtensionValidator(
                allowed_extensions=['pdf', 'doc', 'docx', 'rtf', 'txt']
            )
        ]
    )
```

#### 2. Path Traversal Vulnerability

**Issue:** Files can be written outside media directory

**Solution:**

```python
# In models.py - use upload_to function
import os
from django.utils.text import slugify

def upload_to_path(instance, filename):
    """Generate safe upload path"""
    # Remove any path separators
    safe_filename = os.path.basename(filename)
    # Remove special characters
    safe_filename = slugify(safe_filename)
    # Add random suffix to avoid collisions
    import uuid
    name, ext = os.path.splitext(safe_filename)
    safe_filename = f"{name}_{uuid.uuid4().hex[:8]}{ext}"
    # Return path within tenant directory
    return f"resumes/{instance.tenant.slug}/{safe_filename}"

class Candidate(models.Model):
    resume = models.FileField(upload_to=upload_to_path)
```

#### 3. Missing Access Control

**Issue:** Any authenticated user can download other tenant's files

**Solution:**

```python
# In views.py or viewsets.py
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import FileResponse
from django.core.exceptions import PermissionDenied

class CandidateViewSet(viewsets.ModelViewSet):
    @action(detail=True, methods=['get'])
    def download_resume(self, request, pk=None):
        candidate = self.get_object()

        # Check tenant isolation
        if candidate.tenant != request.user.tenant:
            raise PermissionDenied("Cannot download from other tenant")

        # Check role permissions
        if not request.user.has_perm('ats.download_candidate_files'):
            raise PermissionDenied("No download permission")

        # Serve file safely
        if candidate.resume:
            return FileResponse(
                candidate.resume.open('rb'),
                as_attachment=True,
                filename=candidate.resume.name
            )
        return Response(status=404)
```

#### 4. No Size Limits

**Issue:** Large files can exhaust storage

**Solution:**

```python
# In settings.py
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB

# In models.py - add validators
def validate_file_size(file_obj):
    """Validate file size"""
    file_size = file_obj.size
    limit_bytes = 5 * 1024 * 1024  # 5MB
    if file_size > limit_bytes:
        raise ValidationError(
            f"File size {file_size} exceeds limit of {limit_bytes}"
        )

class PublicProfile(models.Model):
    avatar = models.ImageField(
        validators=[validate_file_size]
    )
```

---

## Best Practices

### Development Guidelines

```python
# 1. Always validate file type
✓ Use FileExtensionValidator
✓ Validate magic bytes
✓ Check MIME type

# 2. Enforce size limits
✓ Set FILE_UPLOAD_MAX_MEMORY_SIZE
✓ Add model field validators
✓ Check in serializers

# 3. Sanitize filenames
✓ Use slugify() or similar
✓ Remove special characters
✓ Add random suffix for uniqueness

# 4. Check access permissions
✓ Verify user owns file
✓ Check tenant isolation
✓ Verify user role/permissions

# 5. Use secure storage
✓ Store outside web root
✓ Use proper file permissions
✓ Use separate media server

# 6. Log all access
✓ Log successful uploads
✓ Log failed upload attempts
✓ Log download access
✓ Track who accessed what file
```

### Deployment Checklist

- [ ] Django file upload settings configured
- [ ] MEDIA_ROOT outside web root
- [ ] Proper file/directory permissions
- [ ] File upload handlers configured
- [ ] Temp file cleanup scheduled
- [ ] Security headers added
- [ ] Access logging configured
- [ ] Rate limiting on upload endpoints
- [ ] File scanning (ClamAV) configured
- [ ] Backup procedures for media files
- [ ] Media server configured (Nginx/S3)
- [ ] CDN or edge caching (if applicable)

### Monitoring and Logging

```python
# In audit log
- User who uploaded file
- File name and size
- Upload timestamp
- File type/MIME
- Upload status (success/failure)
- Error details (if failed)
- Virus scan status (if enabled)

# In access log
- User who downloaded file
- Download timestamp
- File name and size
- User's IP address
- User's tenant
- Download status

# Alerts
- Multiple failed uploads from one IP
- Executable/blocked file upload attempts
- Large file uploads (>80% of limit)
- Virus detection
- Access from unusual locations
```

---

## References

### OWASP File Upload Security

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

### Django Security

- [Django File Upload Security](https://docs.djangoproject.com/en/5.0/topics/http/file-uploads/)
- [Django Security Middleware](https://docs.djangoproject.com/en/5.0/ref/middleware/#django.middleware.security.SecurityMiddleware)

### Testing Tools

- [Burp Suite](https://portswigger.net/burp) - Manual penetration testing
- [OWASP ZAP](https://www.zaproxy.org/) - Automated security scanning
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Template-based vulnerability scanning

---

**Report Generated:** 2026-01-16
**Next Review:** 2026-02-16
**Maintained By:** Security Team
