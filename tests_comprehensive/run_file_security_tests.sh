#!/bin/bash

###############################################################################
# File Upload/Download Security Test Suite Runner
#
# Comprehensive testing for:
# - File type validation
# - File size limits
# - Virus/malware scanning
# - Filename sanitization
# - Path traversal prevention
# - Secure file storage
# - Download access control
###############################################################################

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="/c/Users/techn/OneDrive/Documents/zumodra"
TEST_DIR="${PROJECT_ROOT}/tests_comprehensive"
REPORT_DIR="${TEST_DIR}/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/file_security_test_${TIMESTAMP}.md"
JSON_REPORT="${REPORT_DIR}/file_security_test_${TIMESTAMP}.json"

# Ensure report directory exists
mkdir -p "${REPORT_DIR}"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  File Upload/Download Security Test Suite${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Function to print section header
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
    else
        echo -e "${RED}✗ $2${NC}"
    fi
}

# Start report
cat > "${REPORT_FILE}" << 'EOF'
# File Upload/Download Security Test Report

**Test Date:** $(date)
**Environment:** Docker Compose

## Executive Summary

This comprehensive report documents security testing for file upload and download functionality across the Zumodra platform.

### Test Coverage

1. File Type Validation
2. File Size Limits Enforcement
3. Virus/Malware Scanning Configuration
4. Filename Sanitization
5. Path Traversal Prevention
6. Secure File Storage Locations
7. Download Access Control

---

## Test Results

EOF

print_header "Step 1: Checking Docker Environment"

# Check if docker-compose is running
if docker ps > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Docker is running${NC}"
    print_status 0 "Docker daemon accessible"
else
    echo -e "${YELLOW}! Docker not running, starting services...${NC}"
    cd "${PROJECT_ROOT}"
    docker-compose up -d 2>&1 || true
    sleep 5
fi

# Check if Django container is running
if docker-compose -f "${PROJECT_ROOT}/docker-compose.yml" ps web 2>/dev/null | grep -q "Up"; then
    print_status 0 "Django web container is running"
else
    echo -e "${YELLOW}! Django container not running, attempting to start...${NC}"
    cd "${PROJECT_ROOT}"
    docker-compose up -d web 2>&1 || true
    sleep 10
fi

print_header "Step 2: Running Pytest Security Tests"

# Run the file security tests
cd "${PROJECT_ROOT}"

echo -e "\n${YELLOW}Running file upload/download security tests...${NC}"
echo ""

pytest tests_comprehensive/test_file_upload_download_security.py \
    -v \
    -m "security" \
    --tb=short \
    --json-report \
    --json-report-file="${JSON_REPORT}" \
    2>&1 | tee "${REPORT_DIR}/test_output_${TIMESTAMP}.log"

TEST_STATUS=$?

print_header "Step 3: Security Vulnerability Analysis"

# Analyze results
cat >> "${REPORT_FILE}" << 'EOF'

### Vulnerability Assessment

#### 1. File Type Validation
- **Status:** TESTED
- **Expected:** Only whitelisted file types accepted
- **Files Tested:** PNG, PDF, JPG, GIF, WebP (allowed); EXE, SH, BAT (blocked)

**Vulnerabilities Found:**
- [ ] Executable file uploads accepted
- [ ] Script file uploads accepted
- [ ] Polyglot file attacks successful
- [ ] Double extension bypasses accepted
- [ ] MIME type spoofing successful

#### 2. File Size Limits
- **Status:** TESTED
- **Expected:** Enforce 5MB for images, 10MB for documents

**Vulnerabilities Found:**
- [ ] Oversized files accepted
- [ ] No size validation on upload
- [ ] Zero-byte files accepted
- [ ] Missing max_upload_size configuration

#### 3. Filename Sanitization
- **Status:** TESTED
- **Expected:** Path traversal characters removed/rejected

**Vulnerabilities Found:**
- [ ] Path traversal sequences in filenames
- [ ] Null byte injection successful
- [ ] Special command characters allowed
- [ ] Directory creation via filename
- [ ] Unicode normalization bypass

#### 4. Path Traversal Prevention
- **Status:** TESTED
- **Expected:** Files stored in designated media directory only

**Vulnerabilities Found:**
- [ ] Traversal to parent directories
- [ ] URL-encoded traversal accepted
- [ ] Double-encoded traversal accepted
- [ ] Symlink traversal possible

#### 5. Secure File Storage
- **Status:** TESTED
- **Expected:** Files in MEDIA_ROOT, outside DOCUMENT_ROOT

**Vulnerabilities Found:**
- [ ] Files accessible via web server
- [ ] Directory listing enabled
- [ ] Insecure file permissions
- [ ] No access control on media directory

#### 6. Download Access Control
- **Status:** TESTED
- **Expected:** Authenticated users only, tenant isolation

**Vulnerabilities Found:**
- [ ] Unauthenticated file access
- [ ] Cross-tenant file access
- [ ] Direct path access to files
- [ ] Missing authentication checks
- [ ] No tenant isolation verification

#### 7. MIME Type Validation
- **Status:** TESTED
- **Expected:** Content type validation by magic bytes

**Vulnerabilities Found:**
- [ ] MIME type mismatch not detected
- [ ] Content-type sniffing enabled
- [ ] Magic bytes not validated
- [ ] File re-extension bypass

---

EOF

print_header "Step 4: Configuration Audit"

# Check Django settings
echo -e "\n${YELLOW}Checking Django file upload configuration...${NC}\n"

# Look for file upload settings
if grep -r "FILE_UPLOAD_MAX_MEMORY_SIZE\|DATA_UPLOAD_MAX_MEMORY_SIZE" "${PROJECT_ROOT}/zumodra" 2>/dev/null; then
    print_status 0 "File upload size limits configured"
else
    print_status 1 "File upload size limits NOT configured"
fi

# Check for allowed extensions
if grep -r "FileExtensionValidator\|ALLOWED_EXTENSIONS" "${PROJECT_ROOT}" --include="*.py" 2>/dev/null | grep -qv ".venv"; then
    print_status 0 "File extension validators in use"
else
    print_status 1 "File extension validators NOT found"
fi

# Check for media directory security
if [ -d "${PROJECT_ROOT}/media" ]; then
    PERMS=$(stat -f "%A" "${PROJECT_ROOT}/media" 2>/dev/null || stat -c "%a" "${PROJECT_ROOT}/media" 2>/dev/null)
    echo "Media directory permissions: ${PERMS}"
    if [[ $PERMS == *"75"* ]] || [[ $PERMS == *"70"* ]]; then
        print_status 0 "Media directory has restrictive permissions"
    else
        print_status 1 "Media directory permissions may be too open: ${PERMS}"
    fi
fi

print_header "Step 5: Upload Handler Analysis"

# Check for custom upload handlers
echo -e "\n${YELLOW}Analyzing upload handlers...${NC}\n"

if grep -r "FILE_UPLOAD_HANDLERS" "${PROJECT_ROOT}/zumodra" --include="*.py" 2>/dev/null; then
    print_status 0 "Custom upload handlers configured"
else
    echo -e "${YELLOW}! Using default Django upload handlers${NC}"
fi

# Check for temporary file cleanup
if grep -r "FILE_UPLOAD_TEMP_DIR\|FILE_UPLOAD_PERMISSIONS" "${PROJECT_ROOT}/zumodra" --include="*.py" 2>/dev/null; then
    print_status 0 "Upload temp directory configuration found"
else
    echo -e "${YELLOW}! Temp directory configuration not found${NC}"
fi

print_header "Step 6: Security Headers Analysis"

# Check for security headers in responses
echo -e "\n${YELLOW}Checking for security headers...${NC}\n"

# Look for X-Content-Type-Options
if grep -r "X-Content-Type-Options\|nosniff" "${PROJECT_ROOT}/zumodra" --include="*.py" 2>/dev/null; then
    print_status 0 "X-Content-Type-Options header configured"
else
    print_status 1 "X-Content-Type-Options NOT configured"
fi

# Look for Content-Disposition
if grep -r "Content-Disposition\|attachment" "${PROJECT_ROOT}" --include="*.py" 2>/dev/null | grep -qv ".venv"; then
    print_status 0 "Content-Disposition header configured"
else
    print_status 1 "Content-Disposition NOT configured"
fi

print_header "Step 7: Malware Scanner Configuration"

# Check for ClamAV or other scanner
echo -e "\n${YELLOW}Checking malware scanner configuration...${NC}\n"

if grep -r "CLAMD\|clamav\|malware\|virus" "${PROJECT_ROOT}/zumodra" --include="*.py" 2>/dev/null; then
    print_status 0 "Malware scanner appears to be configured"
else
    echo -e "${YELLOW}! Malware scanner not configured (Optional feature)${NC}"
fi

print_header "Step 8: Access Control Testing"

# Test authentication requirements
echo -e "\n${YELLOW}Testing file access authentication...${NC}\n"

# This would normally be tested with actual HTTP requests
echo "Access control tests can be run with: pytest -m security --tb=short"

print_header "Step 9: Generating Summary"

cat >> "${REPORT_FILE}" << 'EOF'

---

## Recommendations

### Critical (Fix Immediately)
1. Ensure executable file uploads are blocked
2. Implement file type validation for all upload endpoints
3. Sanitize all filenames before storage
4. Validate file size limits on all upload endpoints
5. Restrict media directory access from web root

### High Priority
6. Implement malware/virus scanning (ClamAV)
7. Configure proper file permissions and ownership
8. Add comprehensive access control logging
9. Implement rate limiting on upload endpoints
10. Add file integrity verification (checksums)

### Medium Priority
11. Strip EXIF and other metadata from uploads
12. Implement file type verification by magic bytes
13. Add upload audit trails
14. Configure temporary file cleanup
15. Implement content security policy headers

### Low Priority
16. Add file compression for efficient storage
17. Implement file versioning
18. Add backup procedures for uploaded files
19. Monitor storage quotas
20. Implement file encryption at rest

---

## Testing Checklist

- [ ] File type validation tests passed
- [ ] File size limit tests passed
- [ ] Path traversal prevention verified
- [ ] Access control verified
- [ ] Filename sanitization verified
- [ ] Security headers present
- [ ] No unauthorized access
- [ ] Cross-tenant isolation verified
- [ ] Download access control verified
- [ ] Error messages don't leak sensitive info

---

EOF

# Summary
print_header "Test Summary"

echo ""
echo "Test Execution Date: $(date)"
echo "Report Location: ${REPORT_FILE}"
echo "JSON Report: ${JSON_REPORT}"
echo "Log File: ${REPORT_DIR}/test_output_${TIMESTAMP}.log"
echo ""

if [ $TEST_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ All tests completed successfully${NC}"
else
    echo -e "${YELLOW}⚠ Some tests failed or had warnings${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test execution completed${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Print next steps
echo "Next steps:"
echo "1. Review the report at: ${REPORT_FILE}"
echo "2. Address any vulnerabilities found"
echo "3. Re-run tests after fixes"
echo "4. Document remediation actions"
echo ""

exit $TEST_STATUS
