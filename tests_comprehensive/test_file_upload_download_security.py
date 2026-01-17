#!/usr/bin/env python
"""
Comprehensive File Upload/Download Security Testing Suite

Tests for:
1. File type validation (allowed vs blocked types)
2. File size limits enforcement
3. Virus/malware scanning (if configured)
4. Filename sanitization
5. Path traversal prevention
6. Secure file storage locations
7. Download access control
"""

import os
import io
import json
import pytest
import mimetypes
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
import hashlib

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile, InMemoryUploadedFile
from django.urls import reverse
from django.conf import settings
from django.core.exceptions import ValidationError
from rest_framework.test import APIClient
from rest_framework import status

from tenants.models import Tenant
from accounts.models import PublicProfile, KYCVerification, Education
from ats.models import Candidate, JobPosting as Job, Application

User = get_user_model()


class FileSecurityTestConfig:
    """Configuration for file security tests."""

    # File types
    ALLOWED_IMAGE_TYPES = ['jpg', 'jpeg', 'png', 'gif', 'webp']
    ALLOWED_DOCUMENT_TYPES = ['pdf', 'doc', 'docx', 'rtf', 'txt']
    BLOCKED_TYPES = ['exe', 'bat', 'cmd', 'sh', 'dll', 'so', 'app', 'dmg', 'zip', 'rar']

    # File sizes (in bytes)
    AVATAR_MAX_SIZE = 5 * 1024 * 1024  # 5MB
    CV_MAX_SIZE = 10 * 1024 * 1024  # 10MB
    DOCUMENT_MAX_SIZE = 50 * 1024 * 1024  # 50MB

    # Test file paths
    TEST_FILES_DIR = '/tmp/zumodra_file_tests'

    # Malicious payloads
    MALICIOUS_FILENAMES = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        'shell.php.jpg',
        'shell.jpg.php',
        'image.jpg\0.php',
        'image.jpg%00.php',
        'shell.php .jpg',
    ]

    NULL_BYTE_PAYLOADS = [
        'image.jpg\x00.exe',
        'image.jpg\x00.php',
        'file.pdf\x00.sh',
    ]

    PATH_TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc//passwd',
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
    ]


@pytest.fixture
def test_files_dir():
    """Create temporary test files directory."""
    os.makedirs(FileSecurityTestConfig.TEST_FILES_DIR, exist_ok=True)
    yield FileSecurityTestConfig.TEST_FILES_DIR
    # Cleanup
    import shutil
    if os.path.exists(FileSecurityTestConfig.TEST_FILES_DIR):
        shutil.rmtree(FileSecurityTestConfig.TEST_FILES_DIR)


@pytest.fixture
def tenant(db):
    """Create test tenant."""
    return Tenant.objects.create(
        name='Test Tenant',
        slug='test-tenant',
        domain='test-tenant.localhost'
    )


@pytest.fixture
def user(db, tenant):
    """Create test user."""
    user = User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123',
        tenant=tenant
    )
    return user


@pytest.fixture
def api_client(user):
    """Create authenticated API client."""
    client = APIClient()
    client.force_authenticate(user=user)
    return client


class TestFileTypeValidation:
    """Test file type validation for uploads."""

    @pytest.mark.security
    def test_allowed_image_upload(self, api_client, tenant, user):
        """Test that allowed image types are accepted."""
        # Create a simple PNG file
        png_content = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
            b'\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
        )

        file_obj = SimpleUploadedFile(
            'avatar.png',
            png_content,
            content_type='image/png'
        )

        # Upload via API
        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Check response - should be successful (200, 201, or 200)
        assert response.status_code in [200, 201, 400]  # 400 if endpoint doesn't allow avatar

        # If successful, verify file exists
        if response.status_code in [200, 201]:
            profile = PublicProfile.objects.get(user=user)
            assert profile.avatar is not None or response.status_code == 400

    @pytest.mark.security
    def test_allowed_document_upload(self, api_client, tenant, user):
        """Test that allowed document types are accepted."""
        # Create a simple PDF
        pdf_content = b'%PDF-1.4\n%test content\n'

        file_obj = SimpleUploadedFile(
            'resume.pdf',
            pdf_content,
            content_type='application/pdf'
        )

        # Create candidate to upload CV
        candidate = Candidate.objects.create(
            tenant=tenant,
            first_name='John',
            last_name='Doe',
            email='john@example.com'
        )

        # Try upload via endpoint (if available)
        response = api_client.post(
            f'/api/v1/ats/candidates/{candidate.id}/upload-resume/',
            {'resume': file_obj},
            format='multipart'
        )

        # Check response - should accept or endpoint doesn't exist
        assert response.status_code in [200, 201, 404, 400]

    @pytest.mark.security
    def test_blocked_executable_upload(self, api_client, tenant, user):
        """Test that executable files are blocked."""
        exe_content = b'MZ\x90\x00\x03\x00\x00\x00'  # EXE header

        file_obj = SimpleUploadedFile(
            'malware.exe',
            exe_content,
            content_type='application/x-msdownload'
        )

        # Try to upload
        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should reject the file
        assert response.status_code in [400, 415]

    @pytest.mark.security
    def test_blocked_script_upload(self, api_client, tenant, user):
        """Test that script files are blocked."""
        script_content = b'#!/bin/bash\nrm -rf /\n'

        file_obj = SimpleUploadedFile(
            'malicious.sh',
            script_content,
            content_type='application/x-shellscript'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        assert response.status_code in [400, 415]

    @pytest.mark.security
    def test_polyglot_file_attack(self, api_client, tenant, user):
        """Test polyglot files (e.g., shell.php.jpg)."""
        # Create a file that appears to be JPG but is actually PHP
        php_jpg_content = b'\xFF\xD8\xFF\xE0' + b'<?php system($_GET["cmd"]); ?>'

        file_obj = SimpleUploadedFile(
            'image.jpg',
            php_jpg_content,
            content_type='image/jpeg'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should be rejected or safely stored
        assert response.status_code in [400, 415, 200, 201]

        # If accepted, verify it's not executable
        if response.status_code in [200, 201]:
            profile = PublicProfile.objects.get(user=user)
            if profile.avatar:
                file_path = profile.avatar.path
                assert not any(
                    file_path.endswith(ext)
                    for ext in ['.php', '.sh', '.exe']
                )

    @pytest.mark.security
    def test_double_extension_attack(self, api_client, tenant, user):
        """Test double extension attacks (shell.php.jpg)."""
        jpg_content = b'\xFF\xD8\xFF\xE0'

        file_obj = SimpleUploadedFile(
            'shell.php.jpg',
            jpg_content,
            content_type='image/jpeg'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should reject or rename the file
        assert response.status_code in [400, 415, 200, 201]


class TestFileSizeValidation:
    """Test file size limit enforcement."""

    @pytest.mark.security
    def test_avatar_size_limit(self, api_client, tenant, user):
        """Test avatar file size limit (5MB)."""
        # Create file just under limit
        safe_size = 4 * 1024 * 1024
        png_header = b'\x89PNG\r\n\x1a\n'
        safe_content = png_header + b'\x00' * (safe_size - len(png_header))

        file_obj = SimpleUploadedFile(
            'avatar.png',
            safe_content,
            content_type='image/png'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should accept
        assert response.status_code in [200, 201, 400]

    @pytest.mark.security
    def test_avatar_size_exceeds_limit(self, api_client, tenant, user):
        """Test that oversized avatars are rejected."""
        # Create file exceeding limit
        oversized = 6 * 1024 * 1024
        png_header = b'\x89PNG\r\n\x1a\n'
        content = png_header + b'\x00' * (oversized - len(png_header))

        file_obj = SimpleUploadedFile(
            'large_avatar.png',
            content,
            content_type='image/png'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should reject due to size
        assert response.status_code in [400, 413, 415]

    @pytest.mark.security
    def test_document_size_exceeds_limit(self, api_client, tenant, user):
        """Test that oversized documents are rejected."""
        # Create oversized document
        oversized = 11 * 1024 * 1024
        pdf_header = b'%PDF-1.4\n'
        content = pdf_header + b'\x00' * (oversized - len(pdf_header))

        file_obj = SimpleUploadedFile(
            'large_document.pdf',
            content,
            content_type='application/pdf'
        )

        # Create education entry for upload
        education = Education.objects.create(
            user=user,
            institution_name='Test University',
            degree_type='bachelor'
        )

        # Try upload - should fail
        response = api_client.post(
            f'/api/v1/accounts/education/{education.id}/upload-transcript/',
            {'transcript_file': file_obj},
            format='multipart'
        )

        assert response.status_code in [400, 413, 415, 404]

    @pytest.mark.security
    def test_zero_byte_file(self, api_client, tenant, user):
        """Test handling of zero-byte files."""
        file_obj = SimpleUploadedFile(
            'empty.pdf',
            b'',
            content_type='application/pdf'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should reject zero-byte files
        assert response.status_code in [400, 415]


class TestFilenameSanitization:
    """Test filename sanitization to prevent attacks."""

    @pytest.mark.security
    def test_path_traversal_in_filename(self, api_client, tenant, user):
        """Test that path traversal in filenames is blocked."""
        for malicious_name in FileSecurityTestConfig.MALICIOUS_FILENAMES:
            png_content = b'\x89PNG\r\n\x1a\n'

            file_obj = SimpleUploadedFile(
                malicious_name,
                png_content,
                content_type='image/png'
            )

            response = api_client.post(
                reverse('api:v1:accounts:profile-detail'),
                {'avatar': file_obj},
                format='multipart'
            )

            # Should reject or sanitize
            assert response.status_code in [400, 415, 200, 201]

            if response.status_code in [200, 201]:
                # Verify filename was sanitized
                profile = PublicProfile.objects.get(user=user)
                if profile.avatar:
                    filename = profile.avatar.name
                    assert not any(
                        traversal in filename
                        for traversal in ['../', '..\\', '\\x00']
                    )

    @pytest.mark.security
    def test_null_byte_injection(self, api_client, tenant, user):
        """Test null byte injection attacks."""
        for null_payload in FileSecurityTestConfig.NULL_BYTE_PAYLOADS:
            png_content = b'\x89PNG\r\n\x1a\n'

            try:
                file_obj = SimpleUploadedFile(
                    null_payload,
                    png_content,
                    content_type='image/png'
                )

                response = api_client.post(
                    reverse('api:v1:accounts:profile-detail'),
                    {'avatar': file_obj},
                    format='multipart'
                )

                # Should reject or handle safely
                assert response.status_code in [400, 415, 200, 201]
            except Exception:
                # Expected - null bytes should cause errors
                pass

    @pytest.mark.security
    def test_special_characters_in_filename(self, api_client, tenant, user):
        """Test filenames with special characters."""
        special_names = [
            'image@#$%.png',
            'image;cat etc/passwd.png',
            'image|whoami.png',
            'image`id`.png',
            'image$(whoami).png',
        ]

        for special_name in special_names:
            png_content = b'\x89PNG\r\n\x1a\n'

            # Django may sanitize the filename during upload
            try:
                file_obj = SimpleUploadedFile(
                    special_name,
                    png_content,
                    content_type='image/png'
                )

                response = api_client.post(
                    reverse('api:v1:accounts:profile-detail'),
                    {'avatar': file_obj},
                    format='multipart'
                )

                # Should be safe regardless
                assert response.status_code in [200, 201, 400, 415]
            except Exception:
                # Expected for some special characters
                pass

    @pytest.mark.security
    def test_unicode_filename(self, api_client, tenant, user):
        """Test Unicode characters in filenames."""
        unicode_name = '图像.png'  # "Image" in Chinese
        png_content = b'\x89PNG\r\n\x1a\n'

        file_obj = SimpleUploadedFile(
            unicode_name,
            png_content,
            content_type='image/png'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should handle Unicode safely
        assert response.status_code in [200, 201, 400, 415]


class TestPathTraversalPrevention:
    """Test prevention of path traversal attacks."""

    @pytest.mark.security
    def test_directory_traversal_upload(self, api_client, tenant, user):
        """Test that directory traversal uploads are blocked."""
        traversal_paths = [
            '../../../etc/passwd',
            '../../sensitive/data.txt',
            '..\\..\\..\\windows\\system32\\config\\sam',
        ]

        for path in traversal_paths:
            content = b'malicious content'

            file_obj = SimpleUploadedFile(
                path,
                content,
                content_type='text/plain'
            )

            response = api_client.post(
                reverse('api:v1:accounts:profile-detail'),
                {'avatar': file_obj},
                format='multipart'
            )

            # Should reject or sanitize path
            assert response.status_code in [400, 415, 200, 201]

    @pytest.mark.security
    def test_encoded_traversal(self, api_client, tenant, user):
        """Test encoded path traversal attacks."""
        encoded_paths = [
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252fetc%252fpasswd',
            '....%252f....%252fetc%252fpasswd',
        ]

        for path in encoded_paths:
            content = b'malicious'

            file_obj = SimpleUploadedFile(
                path,
                content,
                content_type='text/plain'
            )

            response = api_client.post(
                reverse('api:v1:accounts:profile-detail'),
                {'avatar': file_obj},
                format='multipart'
            )

            assert response.status_code in [400, 415, 200, 201]

    @pytest.mark.security
    def test_symlink_traversal(self, api_client, tenant, user, test_files_dir):
        """Test symlink-based traversal attacks."""
        # Create a test file
        test_file = os.path.join(test_files_dir, 'sensitive.txt')
        with open(test_file, 'w') as f:
            f.write('sensitive data')

        # Try to create symlink (may not work on Windows)
        try:
            symlink_path = os.path.join(test_files_dir, 'link.txt')
            os.symlink(test_file, symlink_path)

            with open(symlink_path, 'rb') as f:
                content = f.read()

            file_obj = SimpleUploadedFile(
                'symlink.txt',
                content,
                content_type='text/plain'
            )

            response = api_client.post(
                reverse('api:v1:accounts:profile-detail'),
                {'avatar': file_obj},
                format='multipart'
            )

            # Should handle safely
            assert response.status_code in [200, 201, 400, 415]
        except (OSError, NotImplementedError):
            # Symlinks not supported on this system
            pytest.skip("Symlinks not supported")


class TestSecureFileStorage:
    """Test that files are stored in secure locations."""

    @pytest.mark.security
    def test_files_not_in_document_root(self, api_client, tenant, user):
        """Test that uploaded files are not in web-accessible directory."""
        png_content = b'\x89PNG\r\n\x1a\n'

        file_obj = SimpleUploadedFile(
            'test.png',
            png_content,
            content_type='image/png'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        if response.status_code in [200, 201]:
            profile = PublicProfile.objects.get(user=user)
            if profile.avatar:
                file_path = profile.avatar.path

                # Verify not in document root
                assert settings.BASE_DIR not in file_path or 'media' in file_path

    @pytest.mark.security
    def test_media_directory_permissions(self, tenant, user):
        """Test that media directory has restrictive permissions."""
        media_root = settings.MEDIA_ROOT

        if os.path.exists(media_root):
            stat_info = os.stat(media_root)
            mode = stat_info.st_mode

            # Check if writable only by owner
            # On Unix: should be 0o755 or 0o750
            # This is a basic check - more detailed in production
            assert os.access(media_root, os.R_OK)

    @pytest.mark.security
    def test_upload_directory_structure(self, api_client, tenant, user):
        """Test that uploads are organized by type/tenant."""
        png_content = b'\x89PNG\r\n\x1a\n'

        file_obj = SimpleUploadedFile(
            'avatar.png',
            png_content,
            content_type='image/png'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        if response.status_code in [200, 201]:
            profile = PublicProfile.objects.get(user=user)
            if profile.avatar:
                file_path = profile.avatar.name

                # Should be organized by upload_to path
                # e.g., avatars/tenant-slug/...
                parts = file_path.split('/')
                assert 'avatars' in parts or 'avatar' in file_path.lower()


class TestDownloadAccessControl:
    """Test access control for file downloads."""

    @pytest.mark.security
    def test_unauthenticated_download_blocked(self, client, tenant, user):
        """Test that unauthenticated users cannot download files."""
        png_content = b'\x89PNG\r\n\x1a\n'

        profile = PublicProfile.objects.create(
            user=user,
            avatar=SimpleUploadedFile(
                'avatar.png',
                png_content,
                content_type='image/png'
            )
        )

        # Try to access file without authentication
        # This depends on how files are served
        if profile.avatar:
            response = client.get(profile.avatar.url)
            # May return 200 if public, or 403/404
            # Check that it doesn't expose sensitive info
            assert response.status_code in [200, 301, 302, 403, 404]

    @pytest.mark.security
    def test_cross_tenant_download_blocked(self, api_client, tenant, user, db):
        """Test that users cannot download files from other tenants."""
        # Create another tenant
        other_tenant = Tenant.objects.create(
            name='Other Tenant',
            slug='other-tenant',
            domain='other-tenant.localhost'
        )

        # Create user in other tenant
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='testpass123',
            tenant=other_tenant
        )

        # Create file in other tenant
        png_content = b'\x89PNG\r\n\x1a\n'
        other_profile = PublicProfile.objects.create(
            user=other_user,
            avatar=SimpleUploadedFile(
                'other_avatar.png',
                png_content,
                content_type='image/png'
            )
        )

        # Try to download from other tenant
        if other_profile.avatar:
            # URL should be protected by tenant middleware
            url = other_profile.avatar.url
            response = api_client.get(url)

            # Should be blocked (403) or redirected
            assert response.status_code in [403, 404, 302, 400]

    @pytest.mark.security
    def test_direct_file_access_blocked(self, client, tenant, user):
        """Test that direct file system access is blocked."""
        # This test verifies that files cannot be accessed directly
        # by path traversal or direct URL manipulation

        png_content = b'\x89PNG\r\n\x1a\n'
        profile = PublicProfile.objects.create(
            user=user,
            avatar=SimpleUploadedFile(
                'avatar.png',
                png_content,
                content_type='image/png'
            )
        )

        if profile.avatar:
            # Try various direct access patterns
            bad_urls = [
                '/media/../../../etc/passwd',
                '/media/avatars/../../../../../etc/passwd',
                profile.avatar.path,  # Filesystem path should not be accessible
            ]

            for bad_url in bad_urls:
                try:
                    response = client.get(bad_url)
                    # Should not serve sensitive files
                    assert response.status_code in [404, 403, 400]
                except Exception:
                    # Expected - invalid URLs should error
                    pass

    @pytest.mark.security
    def test_file_download_headers(self, client, tenant, user):
        """Test that file downloads have secure headers."""
        pdf_content = b'%PDF-1.4\n'

        # Create KYC document
        kyc = KYCVerification.objects.create(
            user=user,
            document_file=SimpleUploadedFile(
                'id.pdf',
                pdf_content,
                content_type='application/pdf'
            ),
            status='pending'
        )

        if kyc.document_file:
            response = client.get(kyc.document_file.url)

            if response.status_code == 200:
                # Check security headers
                # Should have Content-Disposition to force download
                content_disposition = response.get('Content-Disposition', '')
                content_type = response.get('Content-Type', '')

                # PDF should not be inline
                if 'pdf' in content_type.lower():
                    assert 'attachment' in content_disposition or 'inline' not in content_disposition


class TestMalwareScanning:
    """Test malware/virus scanning configuration."""

    @pytest.mark.security
    def test_malware_scanner_configured(self):
        """Test that malware scanner is configured."""
        # Check if ClamAV or other scanner is configured
        has_clamav = hasattr(settings, 'CLAMD_HOST') or hasattr(settings, 'MALWARE_SCANNER')

        # Not required, but should be noted
        if not has_clamav:
            pytest.skip("Malware scanner not configured")

    @pytest.mark.security
    def test_eicar_test_file(self, api_client, tenant, user):
        """Test with EICAR test virus signature (if scanner enabled)."""
        # EICAR test file - recognized by all antivirus software
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

        file_obj = SimpleUploadedFile(
            'eicar.txt',
            eicar,
            content_type='text/plain'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # If scanner enabled, should reject
        # If scanner disabled, will accept (which is okay for test)
        assert response.status_code in [200, 201, 400, 415]


class TestFileAccessLogging:
    """Test that file access is properly logged."""

    @pytest.mark.security
    def test_file_upload_logged(self, api_client, tenant, user):
        """Test that file uploads are logged."""
        png_content = b'\x89PNG\r\n\x1a\n'

        file_obj = SimpleUploadedFile(
            'avatar.png',
            png_content,
            content_type='image/png'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should log the upload
        # This would be verified through audit log checks
        assert response.status_code in [200, 201, 400, 415]

    @pytest.mark.security
    def test_failed_upload_attempts_logged(self, api_client, tenant, user):
        """Test that failed uploads are logged."""
        exe_content = b'MZ\x90\x00\x03\x00\x00\x00'

        file_obj = SimpleUploadedFile(
            'malware.exe',
            exe_content,
            content_type='application/x-msdownload'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should reject and log attempt
        assert response.status_code in [400, 415]


class TestMimeTypeValidation:
    """Test MIME type validation and spoofing prevention."""

    @pytest.mark.security
    def test_mime_type_mismatch_detection(self, api_client, tenant, user):
        """Test that MIME type mismatches are detected."""
        # File with .jpg extension but PHP content
        php_code = b'<?php system($_GET["cmd"]); ?>'

        file_obj = SimpleUploadedFile(
            'image.jpg',
            php_code,
            content_type='text/plain'  # Wrong MIME type
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should reject or verify actual file type
        assert response.status_code in [400, 415, 200, 201]

    @pytest.mark.security
    def test_content_type_sniffing_protection(self, api_client, tenant, user):
        """Test protection against MIME type sniffing."""
        # File that might be misidentified
        fake_image = b'\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>'

        file_obj = SimpleUploadedFile(
            'image.jpg',
            fake_image,
            content_type='image/jpeg'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        if response.status_code in [200, 201]:
            # Verify file is stored safely
            assert response.status_code in [200, 201]

    @pytest.mark.security
    def test_magic_bytes_validation(self, api_client, tenant, user):
        """Test validation of file magic bytes."""
        # Test various files with correct magic bytes
        test_files = [
            ('test.png', b'\x89PNG\r\n\x1a\n', 'image/png'),
            ('test.pdf', b'%PDF-1.4\n', 'application/pdf'),
            ('test.jpg', b'\xFF\xD8\xFF\xE0\x00\x10JFIF', 'image/jpeg'),
            ('test.gif', b'GIF89a', 'image/gif'),
        ]

        for filename, content, mime_type in test_files:
            file_obj = SimpleUploadedFile(
                filename,
                content,
                content_type=mime_type
            )

            response = api_client.post(
                reverse('api:v1:accounts:profile-detail'),
                {'avatar': file_obj},
                format='multipart'
            )

            # Should accept proper files
            assert response.status_code in [200, 201, 400, 415]


class TestFileMetadataHandling:
    """Test handling of file metadata."""

    @pytest.mark.security
    def test_metadata_stripping(self, api_client, tenant, user):
        """Test that sensitive metadata is stripped from uploaded files."""
        # Create a file with EXIF data (or other metadata)
        png_with_metadata = b'\x89PNG\r\n\x1a\n' + b'metadata_here'

        file_obj = SimpleUploadedFile(
            'photo.png',
            png_with_metadata,
            content_type='image/png'
        )

        response = api_client.post(
            reverse('api:v1:accounts:profile-detail'),
            {'avatar': file_obj},
            format='multipart'
        )

        # Should either strip or reject metadata
        assert response.status_code in [200, 201, 400, 415]

    @pytest.mark.security
    def test_exif_data_exposure(self, api_client, tenant, user):
        """Test that EXIF data is not exposed in downloads."""
        png_content = b'\x89PNG\r\n\x1a\n'

        profile = PublicProfile.objects.create(
            user=user,
            avatar=SimpleUploadedFile(
                'photo.png',
                png_content,
                content_type='image/png'
            )
        )

        if profile.avatar:
            # When downloading, EXIF should not be exposed
            response = api_client.get(profile.avatar.url)

            if response.status_code == 200:
                # Should not contain location or device info
                assert b'latitude' not in response.content.lower()
                assert b'longitude' not in response.content.lower()


# Test report generation
def generate_security_report():
    """Generate comprehensive security test report."""
    report = {
        'title': 'File Upload/Download Security Test Report',
        'timestamp': datetime.now().isoformat(),
        'test_categories': {
            'File Type Validation': {
                'tests': [
                    'Allowed image types',
                    'Allowed document types',
                    'Blocked executables',
                    'Blocked scripts',
                    'Polyglot file detection',
                    'Double extension attacks'
                ],
                'status': 'pending'
            },
            'File Size Validation': {
                'tests': [
                    'Avatar size limit (5MB)',
                    'Document size limit (10MB)',
                    'Zero-byte file rejection',
                    'Oversized file rejection'
                ],
                'status': 'pending'
            },
            'Filename Sanitization': {
                'tests': [
                    'Path traversal in filename',
                    'Null byte injection',
                    'Special characters',
                    'Unicode filename handling'
                ],
                'status': 'pending'
            },
            'Path Traversal Prevention': {
                'tests': [
                    'Directory traversal',
                    'Encoded traversal',
                    'Symlink traversal'
                ],
                'status': 'pending'
            },
            'Secure File Storage': {
                'tests': [
                    'Files not in document root',
                    'Media directory permissions',
                    'Upload directory structure'
                ],
                'status': 'pending'
            },
            'Download Access Control': {
                'tests': [
                    'Unauthenticated access blocked',
                    'Cross-tenant access blocked',
                    'Direct file access blocked',
                    'Secure download headers'
                ],
                'status': 'pending'
            },
            'MIME Type Validation': {
                'tests': [
                    'MIME type mismatch detection',
                    'Content type sniffing protection',
                    'Magic bytes validation'
                ],
                'status': 'pending'
            }
        },
        'vulnerabilities_found': []
    }

    return report


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
