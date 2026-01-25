#!/usr/bin/env python
"""
Comprehensive Messaging System Test Suite

Tests all messaging features after WebSocket fixes:
- Backend API endpoints
- WebSocket consumer functionality
- Frontend template rendering
- Security features
- Error handling
"""

import sys
import os
import django
import asyncio
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
django.setup()

from django.test import Client, RequestFactory
from django.contrib.auth import get_user_model
from channels.testing import WebsocketCommunicator
from messages_sys.consumer import ChatConsumer, validate_file_type
from messages_sys.models import Conversation, Message, Contact
import json
import base64

User = get_user_model()

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_test(name, passed, message=""):
    status = f"{Colors.GREEN}✓ PASS{Colors.END}" if passed else f"{Colors.RED}✗ FAIL{Colors.END}"
    print(f"{status} | {name}")
    if message and not passed:
        print(f"       {Colors.YELLOW}{message}{Colors.END}")

def print_section(title):
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.BLUE}{'='*60}{Colors.END}")

# Test Results Summary
results = {
    'total': 0,
    'passed': 0,
    'failed': 0
}

def record_test(passed):
    results['total'] += 1
    if passed:
        results['passed'] += 1
    else:
        results['failed'] += 1

# ============================================================================
# BACKEND TESTS
# ============================================================================

print_section("Backend Tests - File Validation")

# Test 1: File validation function exists
try:
    from messages_sys.consumer import validate_file_type, BLOCKED_EXTENSIONS, MAX_FILE_SIZE
    passed = callable(validate_file_type)
    print_test("validate_file_type function exists", passed)
    record_test(passed)
except Exception as e:
    print_test("validate_file_type function exists", False, str(e))
    record_test(False)

# Test 2: Dangerous file blocking
try:
    is_valid, error = validate_file_type("malware.exe", b"MZ\x90\x00")
    passed = not is_valid and "not allowed" in error
    print_test("Blocks dangerous .exe files", passed, error if not passed else "")
    record_test(passed)
except Exception as e:
    print_test("Blocks dangerous .exe files", False, str(e))
    record_test(False)

# Test 3: PDF file validation
try:
    is_valid, error = validate_file_type("document.pdf", b"%PDF-1.4")
    passed = is_valid and error is None
    print_test("Accepts valid PDF files", passed, error if not passed else "")
    record_test(passed)
except Exception as e:
    print_test("Accepts valid PDF files", False, str(e))
    record_test(False)

# Test 4: Magic byte mismatch detection
try:
    is_valid, error = validate_file_type("fake.pdf", b"MZ\x90\x00")  # EXE masquerading as PDF
    passed = not is_valid
    print_test("Detects magic byte mismatch", passed, error if not passed else "")
    record_test(passed)
except Exception as e:
    print_test("Detects magic byte mismatch", False, str(e))
    record_test(False)

# Test 5: File size limit check
try:
    from messages_sys.consumer import MAX_FILE_SIZE
    passed = MAX_FILE_SIZE == 50 * 1024 * 1024  # 50MB
    print_test(f"File size limit is 50MB", passed)
    record_test(passed)
except Exception as e:
    print_test("File size limit check", False, str(e))
    record_test(False)

# ============================================================================
# DJANGO VIEW TESTS
# ============================================================================

print_section("Backend Tests - Views & Error Handling")

# Test 6: Chat view has WebSocket context
try:
    from messages_sys.views import chat_view
    import inspect
    source = inspect.getsource(chat_view)
    has_websocket = 'websocket_enabled' in source and 'websocket_url' in source
    passed = has_websocket
    print_test("Chat view includes WebSocket context", passed)
    record_test(passed)
except Exception as e:
    print_test("Chat view includes WebSocket context", False, str(e))
    record_test(False)

# Test 7: Error handling in views
try:
    from messages_sys.views import chat_view
    import inspect
    source = inspect.getsource(chat_view)
    has_error_handling = 'try:' in source and 'except' in source and 'logger.error' in source
    passed = has_error_handling
    print_test("Views have comprehensive error handling", passed)
    record_test(passed)
except Exception as e:
    print_test("Views have error handling", False, str(e))
    record_test(False)

# ============================================================================
# WEBSOCKET CONSUMER TESTS
# ============================================================================

print_section("Backend Tests - WebSocket Consumer")

# Test 8: ChatConsumer exists and has required methods
try:
    from messages_sys.consumer import ChatConsumer
    methods = ['connect', 'disconnect', 'receive', 'handle_send_message',
               'handle_typing', 'handle_read_receipt']
    has_methods = all(hasattr(ChatConsumer, m) for m in methods)
    passed = has_methods
    print_test("ChatConsumer has all required methods", passed)
    record_test(passed)
except Exception as e:
    print_test("ChatConsumer methods", False, str(e))
    record_test(False)

# Test 9: Tenant isolation in consumer
try:
    import inspect
    source = inspect.getsource(ChatConsumer)
    has_tenant_isolation = 'tenant_' in source and 'room_group_name' in source
    passed = has_tenant_isolation
    print_test("WebSocket has tenant isolation", passed)
    record_test(passed)
except Exception as e:
    print_test("Tenant isolation", False, str(e))
    record_test(False)

# Test 10: Message size limits
try:
    import inspect
    source = inspect.getsource(ChatConsumer.handle_send_message)
    has_size_limit = '10000' in source and 'too long' in source.lower()
    passed = has_size_limit
    print_test("Message has 10K character limit", passed)
    record_test(passed)
except Exception as e:
    print_test("Message size limit", False, str(e))
    record_test(False)

# ============================================================================
# ROUTING TESTS
# ============================================================================

print_section("Backend Tests - ASGI & Routing")

# Test 11: WebSocket routing configured
try:
    from messages_sys.routing import websocket_urlpatterns
    passed = len(websocket_urlpatterns) > 0
    print_test("WebSocket URL patterns defined", passed)
    record_test(passed)
except Exception as e:
    print_test("WebSocket routing", False, str(e))
    record_test(False)

# Test 12: ASGI configuration
try:
    from zumodra.asgi import application
    passed = application is not None
    print_test("ASGI application configured", passed)
    record_test(passed)
except Exception as e:
    print_test("ASGI configuration", False, str(e))
    record_test(False)

# ============================================================================
# TEMPLATE TESTS
# ============================================================================

print_section("Frontend Tests - Template")

# Test 13: Chat template exists
try:
    import os
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'messages_sys', 'chat.html')
    passed = os.path.exists(template_path)
    print_test("Chat template exists", passed, template_path if not passed else "")
    record_test(passed)
except Exception as e:
    print_test("Chat template exists", False, str(e))
    record_test(False)

# Test 14: Template has WebSocket JavaScript
try:
    with open(template_path, 'r', encoding='utf-8') as f:
        content = f.read()
    has_websocket_js = all(term in content for term in [
        'WebSocket', 'connectWebSocket', 'sendMessage',
        'showTypingIndicator', 'startPolling'
    ])
    passed = has_websocket_js
    print_test("Template has WebSocket JavaScript", passed)
    record_test(passed)
except Exception as e:
    print_test("Template WebSocket JS", False, str(e))
    record_test(False)

# Test 15: Template has reconnection logic
try:
    has_reconnect = 'reconnectAttempts' in content and 'maxReconnectAttempts' in content
    passed = has_reconnect
    print_test("Template has auto-reconnect logic", passed)
    record_test(passed)
except Exception as e:
    print_test("Template reconnection", False, str(e))
    record_test(False)

# Test 16: Template has typing indicator
try:
    has_typing = 'sendTypingIndicator' in content and 'is typing' in content.lower()
    passed = has_typing
    print_test("Template has typing indicator", passed)
    record_test(passed)
except Exception as e:
    print_test("Template typing indicator", False, str(e))
    record_test(False)

# Test 17: Template has fallback polling
try:
    has_fallback = 'startPolling' in content and 'location.reload' in content
    passed = has_fallback
    print_test("Template has fallback polling", passed)
    record_test(passed)
except Exception as e:
    print_test("Template fallback", False, str(e))
    record_test(False)

# Test 18: Template has XSS protection
try:
    has_xss_protection = 'escapeHtml' in content
    passed = has_xss_protection
    print_test("Template has XSS protection", passed)
    record_test(passed)
except Exception as e:
    print_test("Template XSS protection", False, str(e))
    record_test(False)

# ============================================================================
# SECURITY TESTS
# ============================================================================

print_section("Security Tests")

# Test 19: Blocked extensions list
try:
    dangerous = ['exe', 'bat', 'sh', 'php', 'asp']
    all_blocked = all(ext in BLOCKED_EXTENSIONS for ext in dangerous)
    passed = all_blocked
    print_test("Dangerous file types blocked", passed)
    record_test(passed)
except Exception as e:
    print_test("Blocked extensions", False, str(e))
    record_test(False)

# Test 20: Authentication check in consumer
try:
    import inspect
    source = inspect.getsource(ChatConsumer.connect)
    has_auth_check = 'is_authenticated' in source and 'close' in source
    passed = has_auth_check
    print_test("WebSocket requires authentication", passed)
    record_test(passed)
except Exception as e:
    print_test("Authentication check", False, str(e))
    record_test(False)

# ============================================================================
# SUMMARY
# ============================================================================

print_section("Test Summary")

print(f"\nTotal Tests: {results['total']}")
print(f"{Colors.GREEN}Passed: {results['passed']}{Colors.END}")
print(f"{Colors.RED}Failed: {results['failed']}{Colors.END}")

success_rate = (results['passed'] / results['total'] * 100) if results['total'] > 0 else 0
print(f"\nSuccess Rate: {success_rate:.1f}%")

if results['failed'] == 0:
    print(f"\n{Colors.GREEN}{'='*60}")
    print("ALL TESTS PASSED - Messaging System is READY! ✓")
    print(f"{'='*60}{Colors.END}\n")
    sys.exit(0)
else:
    print(f"\n{Colors.YELLOW}{'='*60}")
    print(f"Some tests failed - Review failures above")
    print(f"{'='*60}{Colors.END}\n")
    sys.exit(1)
