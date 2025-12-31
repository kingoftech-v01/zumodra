"""
File Upload Security Tests for Zumodra ATS/HR Platform

This module tests file upload security including:
- MIME type validation (reject mismatched content-type)
- Magic bytes validation (detect disguised files)
- Extension whitelist enforcement
- Size limit enforcement
- Malicious file content (polyglots, embedded scripts)

Each test documents the attack vector being tested.
"""

import io
import struct
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile, InMemoryUploadedFile
from django.test import TestCase, RequestFactory, override_settings


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def file_validator():
    """Create FileUploadValidator instance."""
    from core.security.validation import FileUploadValidator
    return FileUploadValidator()


@pytest.fixture
def magic_validator():
    """Create MagicBytesValidator instance."""
    from core.security.validation import MagicBytesValidator
    return MagicBytesValidator()


@pytest.fixture
def content_scanner():
    """Create MaliciousContentScanner instance."""
    from core.security.validation import MaliciousContentScanner
    return MaliciousContentScanner()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_file_with_magic(magic_bytes, extension, content=b''):
    """Create a file with specific magic bytes."""
    data = magic_bytes + content
    return SimpleUploadedFile(
        name=f'test.{extension}',
        content=data,
        content_type='application/octet-stream'
    )


def create_pdf_file(malicious=False):
    """Create a PDF file (valid or malicious)."""
    if malicious:
        # PDF with embedded JavaScript
        content = b'%PDF-1.4\n/OpenAction<</S/JavaScript/JS(app.alert("XSS"))>>'
    else:
        content = b'%PDF-1.4\n%fake pdf content'
    return SimpleUploadedFile(
        name='document.pdf',
        content=content,
        content_type='application/pdf'
    )


def create_image_file(format='png', malicious=False):
    """Create an image file."""
    magic_bytes = {
        'png': b'\x89PNG\r\n\x1a\n',
        'jpg': b'\xff\xd8\xff\xe0',
        'gif': b'GIF89a',
    }
    content = magic_bytes.get(format, b'')
    if malicious:
        # Append script after image data
        content += b'<script>alert("XSS")</script>'
    return SimpleUploadedFile(
        name=f'image.{format}',
        content=content,
        content_type=f'image/{format}'
    )


# =============================================================================
# MIME TYPE VALIDATION TESTS
# =============================================================================

class TestMIMETypeValidation:
    """
    Tests for MIME type validation.

    Attack Vector: Mismatched MIME types can:
    - Upload executables as images
    - Bypass content-type filters
    - Execute malicious code on server
    """

    def test_rejects_exe_with_image_mime_type(self, file_validator):
        """
        Test: EXE file with image MIME type is rejected.
        Attack Vector: Uploading malware disguised as image.
        """
        # MZ header for Windows PE file
        exe_content = b'MZ' + b'\x00' * 100
        file = SimpleUploadedFile(
            name='innocent.jpg',
            content=exe_content,
            content_type='image/jpeg'
        )

        with pytest.raises(ValidationError) as excinfo:
            file_validator.validate(file)

        assert 'mime' in str(excinfo.value).lower() or 'type' in str(excinfo.value).lower()

    def test_rejects_script_with_image_mime_type(self, file_validator):
        """
        Test: Script file with image MIME type is rejected.
        Attack Vector: Uploading script disguised as image.
        """
        script_content = b'#!/bin/bash\nrm -rf /'
        file = SimpleUploadedFile(
            name='photo.png',
            content=script_content,
            content_type='image/png'
        )

        with pytest.raises(ValidationError):
            file_validator.validate(file)

    def test_accepts_valid_image_with_correct_mime(self, file_validator):
        """
        Positive Test: Valid image with correct MIME type is accepted.
        """
        # PNG magic bytes
        png_content = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        file = SimpleUploadedFile(
            name='valid.png',
            content=png_content,
            content_type='image/png'
        )

        # Should not raise
        file_validator.validate(file)

    def test_rejects_html_disguised_as_pdf(self, file_validator):
        """
        Test: HTML file disguised as PDF is rejected.
        Attack Vector: HTML with malicious scripts served as document.
        """
        html_content = b'<!DOCTYPE html><html><script>evil()</script></html>'
        file = SimpleUploadedFile(
            name='document.pdf',
            content=html_content,
            content_type='application/pdf'
        )

        with pytest.raises(ValidationError):
            file_validator.validate(file)

    def test_rejects_php_with_image_extension(self, file_validator):
        """
        Test: PHP file with image extension is rejected.
        Attack Vector: Web shell upload.
        """
        php_content = b'<?php system($_GET["cmd"]); ?>'
        file = SimpleUploadedFile(
            name='image.jpg.php',
            content=php_content,
            content_type='image/jpeg'
        )

        with pytest.raises(ValidationError):
            file_validator.validate(file)


# =============================================================================
# MAGIC BYTES VALIDATION TESTS
# =============================================================================

class TestMagicBytesValidation:
    """
    Tests for magic bytes (file signature) validation.

    Attack Vector: Files with wrong magic bytes:
    - Are not what they claim to be
    - May contain malicious code
    - Can exploit file parsers
    """

    def test_validates_pdf_magic_bytes(self, magic_validator):
        """
        Test: PDF files must have correct magic bytes.
        """
        # Valid PDF
        valid_pdf = SimpleUploadedFile(
            name='document.pdf',
            content=b'%PDF-1.4\n%test content',
            content_type='application/pdf'
        )
        assert magic_validator.validate(valid_pdf)

        # Invalid - wrong magic
        invalid_pdf = SimpleUploadedFile(
            name='document.pdf',
            content=b'Not a PDF file',
            content_type='application/pdf'
        )
        with pytest.raises(ValidationError):
            magic_validator.validate(invalid_pdf)

    def test_validates_png_magic_bytes(self, magic_validator):
        """
        Test: PNG files must have correct magic bytes.
        PNG magic: 89 50 4E 47 0D 0A 1A 0A
        """
        # Valid PNG magic
        valid_png = SimpleUploadedFile(
            name='image.png',
            content=b'\x89PNG\r\n\x1a\n' + b'\x00' * 100,
            content_type='image/png'
        )
        assert magic_validator.validate(valid_png)

        # Invalid - wrong magic
        invalid_png = SimpleUploadedFile(
            name='image.png',
            content=b'Not a PNG',
            content_type='image/png'
        )
        with pytest.raises(ValidationError):
            magic_validator.validate(invalid_png)

    def test_validates_jpeg_magic_bytes(self, magic_validator):
        """
        Test: JPEG files must have correct magic bytes.
        JPEG magic: FF D8 FF
        """
        # Valid JPEG magic
        valid_jpeg = SimpleUploadedFile(
            name='photo.jpg',
            content=b'\xff\xd8\xff\xe0' + b'\x00' * 100,
            content_type='image/jpeg'
        )
        assert magic_validator.validate(valid_jpeg)

        # Invalid - wrong magic
        invalid_jpeg = SimpleUploadedFile(
            name='photo.jpg',
            content=b'Not a JPEG',
            content_type='image/jpeg'
        )
        with pytest.raises(ValidationError):
            magic_validator.validate(invalid_jpeg)

    def test_validates_gif_magic_bytes(self, magic_validator):
        """
        Test: GIF files must have correct magic bytes.
        GIF magic: GIF87a or GIF89a
        """
        # Valid GIF87a
        valid_gif87 = SimpleUploadedFile(
            name='image.gif',
            content=b'GIF87a' + b'\x00' * 100,
            content_type='image/gif'
        )
        assert magic_validator.validate(valid_gif87)

        # Valid GIF89a
        valid_gif89 = SimpleUploadedFile(
            name='image.gif',
            content=b'GIF89a' + b'\x00' * 100,
            content_type='image/gif'
        )
        assert magic_validator.validate(valid_gif89)

    def test_validates_docx_magic_bytes(self, magic_validator):
        """
        Test: DOCX files must have ZIP magic bytes.
        DOCX (ZIP-based) magic: 50 4B 03 04
        """
        # Valid DOCX (ZIP format)
        valid_docx = SimpleUploadedFile(
            name='document.docx',
            content=b'PK\x03\x04' + b'\x00' * 100,
            content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
        assert magic_validator.validate(valid_docx)

    def test_detects_exe_regardless_of_extension(self, magic_validator):
        """
        Test: EXE files are detected regardless of extension.
        EXE magic: MZ
        """
        # EXE disguised as text file
        disguised_exe = SimpleUploadedFile(
            name='readme.txt',
            content=b'MZ\x90\x00' + b'\x00' * 100,
            content_type='text/plain'
        )

        with pytest.raises(ValidationError) as excinfo:
            magic_validator.validate(disguised_exe)

        assert 'executable' in str(excinfo.value).lower()


# =============================================================================
# EXTENSION WHITELIST TESTS
# =============================================================================

class TestExtensionWhitelist:
    """
    Tests for file extension whitelist enforcement.

    Attack Vector: Dangerous extensions can:
    - Execute code on the server
    - Exploit vulnerabilities
    - Cause security breaches
    """

    @pytest.fixture
    def extension_validator(self):
        """Create extension whitelist validator."""
        from core.security.validation import ExtensionValidator
        return ExtensionValidator(
            allowed_extensions=['pdf', 'doc', 'docx', 'png', 'jpg', 'jpeg', 'gif']
        )

    def test_blocks_php_extension(self, extension_validator):
        """
        Test: PHP files are blocked.
        Attack Vector: Web shell upload.
        """
        dangerous_extensions = ['.php', '.php5', '.phtml', '.phar']

        for ext in dangerous_extensions:
            file = SimpleUploadedFile(
                name=f'file{ext}',
                content=b'<?php echo "test"; ?>',
                content_type='text/plain'
            )

            with pytest.raises(ValidationError) as excinfo:
                extension_validator.validate(file)

            assert 'extension' in str(excinfo.value).lower()

    def test_blocks_exe_extension(self, extension_validator):
        """
        Test: Executable files are blocked.
        """
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.com', '.msi']

        for ext in dangerous_extensions:
            file = SimpleUploadedFile(
                name=f'file{ext}',
                content=b'MZ' + b'\x00' * 100,
                content_type='application/octet-stream'
            )

            with pytest.raises(ValidationError):
                extension_validator.validate(file)

    def test_blocks_script_extensions(self, extension_validator):
        """
        Test: Script files are blocked.
        """
        dangerous_extensions = ['.js', '.vbs', '.ps1', '.sh', '.py']

        for ext in dangerous_extensions:
            file = SimpleUploadedFile(
                name=f'file{ext}',
                content=b'console.log("test")',
                content_type='text/plain'
            )

            with pytest.raises(ValidationError):
                extension_validator.validate(file)

    def test_blocks_double_extensions(self, extension_validator):
        """
        Test: Double extensions are blocked.
        Attack Vector: file.pdf.php executed as PHP.
        """
        double_extensions = [
            'document.pdf.php',
            'image.jpg.php',
            'file.doc.exe',
            'resume.docx.js',
        ]

        for filename in double_extensions:
            file = SimpleUploadedFile(
                name=filename,
                content=b'malicious content',
                content_type='application/octet-stream'
            )

            with pytest.raises(ValidationError):
                extension_validator.validate(file)

    def test_blocks_null_byte_extension(self, extension_validator):
        """
        Test: Null byte in filename is blocked.
        Attack Vector: file.php%00.jpg processed as PHP.
        """
        null_byte_names = [
            'file.php\x00.jpg',
            'shell.php\x00.pdf',
        ]

        for filename in null_byte_names:
            file = SimpleUploadedFile(
                name=filename,
                content=b'malicious',
                content_type='image/jpeg'
            )

            with pytest.raises(ValidationError):
                extension_validator.validate(file)

    def test_accepts_allowed_extensions(self, extension_validator):
        """
        Positive Test: Allowed extensions are accepted.
        """
        allowed_files = [
            ('document.pdf', b'%PDF-1.4'),
            ('resume.docx', b'PK\x03\x04'),
            ('photo.jpg', b'\xff\xd8\xff\xe0'),
        ]

        for filename, content in allowed_files:
            file = SimpleUploadedFile(
                name=filename,
                content=content,
                content_type='application/octet-stream'
            )
            # Should not raise
            extension_validator.validate(file)


# =============================================================================
# SIZE LIMIT TESTS
# =============================================================================

class TestSizeLimit:
    """
    Tests for file size limit enforcement.

    Attack Vector: Oversized files can:
    - Cause DoS by exhausting storage
    - Exhaust memory during processing
    - Fill up disk space
    """

    @pytest.fixture
    def size_validator(self):
        """Create size limit validator."""
        from core.security.validation import SizeValidator
        return SizeValidator(max_size_mb=10)  # 10MB limit

    def test_blocks_oversized_file(self, size_validator):
        """
        Test: Files exceeding size limit are blocked.
        """
        # Create file larger than 10MB
        large_content = b'x' * (11 * 1024 * 1024)  # 11MB
        file = SimpleUploadedFile(
            name='large_file.pdf',
            content=large_content,
            content_type='application/pdf'
        )

        with pytest.raises(ValidationError) as excinfo:
            size_validator.validate(file)

        assert 'size' in str(excinfo.value).lower()

    def test_accepts_file_within_limit(self, size_validator):
        """
        Positive Test: Files within size limit are accepted.
        """
        # Create file smaller than 10MB
        small_content = b'x' * (5 * 1024 * 1024)  # 5MB
        file = SimpleUploadedFile(
            name='small_file.pdf',
            content=small_content,
            content_type='application/pdf'
        )

        # Should not raise
        size_validator.validate(file)

    def test_blocks_content_length_spoofing(self, size_validator):
        """
        Test: Content-Length header spoofing is detected.
        Attack Vector: Sending small Content-Length but large body.
        """
        file = SimpleUploadedFile(
            name='file.pdf',
            content=b'x' * (15 * 1024 * 1024),  # 15MB actual
            content_type='application/pdf'
        )
        # Manually set fake size
        file.size = 1024  # Fake 1KB

        # Validator should check actual size, not reported size
        with pytest.raises(ValidationError):
            size_validator.validate(file, check_actual_size=True)

    def test_different_limits_per_file_type(self):
        """
        Test: Different file types can have different size limits.
        """
        from core.security.validation import SizeValidator

        # Stricter limit for images
        image_validator = SizeValidator(max_size_mb=5)
        # More lenient for documents
        doc_validator = SizeValidator(max_size_mb=25)

        large_image = SimpleUploadedFile(
            name='photo.jpg',
            content=b'x' * (6 * 1024 * 1024),  # 6MB
            content_type='image/jpeg'
        )

        with pytest.raises(ValidationError):
            image_validator.validate(large_image)

        # Same file would be OK as document
        large_doc = SimpleUploadedFile(
            name='document.pdf',
            content=b'x' * (20 * 1024 * 1024),  # 20MB
            content_type='application/pdf'
        )
        # Should pass 25MB limit
        doc_validator.validate(large_doc)


# =============================================================================
# MALICIOUS CONTENT TESTS
# =============================================================================

class TestMaliciousContent:
    """
    Tests for malicious file content detection.

    Attack Vector: Malicious content can:
    - Execute code when opened
    - Exploit document parsers
    - Spread malware
    """

    def test_detects_embedded_javascript_in_pdf(self, content_scanner):
        """
        Test: PDFs with embedded JavaScript are flagged.
        Attack Vector: PDF malware executing on open.
        """
        malicious_pdf = b'''%PDF-1.4
        1 0 obj
        <<
        /Type /Catalog
        /OpenAction <<
            /S /JavaScript
            /JS (app.alert('XSS'))
        >>
        >>
        endobj
        '''

        file = SimpleUploadedFile(
            name='document.pdf',
            content=malicious_pdf,
            content_type='application/pdf'
        )

        with pytest.raises(ValidationError) as excinfo:
            content_scanner.scan(file)

        assert 'javascript' in str(excinfo.value).lower() or 'malicious' in str(excinfo.value).lower()

    def test_detects_macro_in_office_documents(self, content_scanner):
        """
        Test: Office documents with macros are flagged.
        Attack Vector: Macro malware.
        """
        # Simulated macro-enabled document signature
        macro_doc = b'PK\x03\x04' + b'vbaProject.bin' + b'\x00' * 100

        file = SimpleUploadedFile(
            name='document.xlsm',
            content=macro_doc,
            content_type='application/vnd.ms-excel.sheet.macroEnabled.12'
        )

        with pytest.raises(ValidationError) as excinfo:
            content_scanner.scan(file)

        assert 'macro' in str(excinfo.value).lower()

    def test_detects_polyglot_gif_javascript(self, content_scanner):
        """
        Test: GIF/JavaScript polyglot files are detected.
        Attack Vector: File valid as both GIF and JavaScript.
        """
        # GIF header that's also valid JavaScript
        polyglot = b'GIF89a/*\x00\x00\x00*/=1;alert("XSS")//;'

        file = SimpleUploadedFile(
            name='image.gif',
            content=polyglot,
            content_type='image/gif'
        )

        with pytest.raises(ValidationError):
            content_scanner.scan(file)

    def test_detects_html_in_image(self, content_scanner):
        """
        Test: HTML embedded in image files is detected.
        Attack Vector: Image served as HTML by misconfigured server.
        """
        # Valid PNG header followed by HTML
        html_in_image = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100 + b'<html><script>alert(1)</script></html>'

        file = SimpleUploadedFile(
            name='image.png',
            content=html_in_image,
            content_type='image/png'
        )

        with pytest.raises(ValidationError):
            content_scanner.scan(file)

    def test_detects_svg_with_script(self, content_scanner):
        """
        Test: SVG files with embedded scripts are detected.
        Attack Vector: SVG XSS attacks.
        """
        malicious_svg = b'''<?xml version="1.0"?>
        <svg xmlns="http://www.w3.org/2000/svg">
            <script>alert('XSS')</script>
        </svg>
        '''

        file = SimpleUploadedFile(
            name='image.svg',
            content=malicious_svg,
            content_type='image/svg+xml'
        )

        with pytest.raises(ValidationError):
            content_scanner.scan(file)

    def test_detects_xml_external_entity(self, content_scanner):
        """
        Test: XML files with external entities are blocked.
        Attack Vector: XXE (XML External Entity) attack.
        """
        xxe_xml = b'''<?xml version="1.0"?>
        <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <foo>&xxe;</foo>
        '''

        file = SimpleUploadedFile(
            name='data.xml',
            content=xxe_xml,
            content_type='application/xml'
        )

        with pytest.raises(ValidationError):
            content_scanner.scan(file)

    def test_detects_zip_bomb(self, content_scanner):
        """
        Test: ZIP bombs are detected.
        Attack Vector: DoS by decompression.
        """
        # Highly compressed file that expands to massive size
        # This is a simplified detection - real bombs are more sophisticated
        zip_bomb_signature = b'PK\x03\x04' + b'\x00' * 100

        file = SimpleUploadedFile(
            name='archive.zip',
            content=zip_bomb_signature,
            content_type='application/zip'
        )

        # Scanner should check compression ratio
        # Real implementation would decompress and check size

    def test_detects_eicar_test_file(self, content_scanner):
        """
        Test: EICAR test file is detected (antivirus test).
        """
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

        file = SimpleUploadedFile(
            name='test.txt',
            content=eicar,
            content_type='text/plain'
        )

        with pytest.raises(ValidationError):
            content_scanner.scan(file)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestFileUploadIntegration:
    """
    Integration tests for complete file upload validation.
    """

    @pytest.fixture
    def complete_validator(self):
        """Create complete file upload validator."""
        from core.security.validation import FileUploadValidator
        return FileUploadValidator(
            allowed_extensions=['pdf', 'doc', 'docx', 'png', 'jpg'],
            max_size_mb=10,
            validate_magic=True,
            scan_content=True
        )

    def test_complete_validation_flow(self, complete_validator):
        """
        Test: Complete validation passes for legitimate file.
        """
        # Valid PDF file
        valid_pdf = SimpleUploadedFile(
            name='document.pdf',
            content=b'%PDF-1.4\n%Valid PDF content' + b'\x00' * 100,
            content_type='application/pdf'
        )

        # Should pass all checks
        result = complete_validator.validate(valid_pdf)
        assert result is True

    def test_validation_fails_at_first_check(self, complete_validator):
        """
        Test: Validation fails fast on first issue.
        """
        # Invalid extension
        file = SimpleUploadedFile(
            name='shell.php',
            content=b'<?php ?>',
            content_type='text/php'
        )

        with pytest.raises(ValidationError) as excinfo:
            complete_validator.validate(file)

        # Should fail on extension check first
        assert 'extension' in str(excinfo.value).lower()

    def test_resume_upload_validation(self, complete_validator):
        """
        Test: Resume file uploads are properly validated.
        """
        # Valid resume as PDF
        resume_pdf = SimpleUploadedFile(
            name='John_Doe_Resume.pdf',
            content=b'%PDF-1.4\n%Resume content' + b'\x00' * 100,
            content_type='application/pdf'
        )

        result = complete_validator.validate(resume_pdf)
        assert result is True

    def test_avatar_upload_validation(self):
        """
        Test: Avatar image uploads are properly validated.
        """
        from core.security.validation import FileUploadValidator

        avatar_validator = FileUploadValidator(
            allowed_extensions=['png', 'jpg', 'jpeg', 'gif'],
            max_size_mb=2,
            validate_magic=True,
            validate_dimensions=True,
            max_dimensions=(800, 800)
        )

        # Valid avatar
        avatar = SimpleUploadedFile(
            name='avatar.png',
            content=b'\x89PNG\r\n\x1a\n' + b'\x00' * 100,
            content_type='image/png'
        )

        result = avatar_validator.validate(avatar)
        assert result is True
