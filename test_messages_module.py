#!/usr/bin/env python3
"""
Zumodra Messages/Real-time Chat Module Testing Script
=====================================================

This script comprehensively tests the Messages/Real-time Chat module on the
production instance with authenticated access using Playwright.

Test URL: https://demo-company.zumodra.rhematek-solutions.com
Login: company.owner@demo.zumodra.rhematek-solutions.com
Password: Demo@2024!

TESTING SCOPE:
--------------
1. Message inbox (/app/messages/)
2. Conversation list (/app/messages/conversations/ if exists)
3. Compose new message (/app/messages/compose/ if exists)
4. Conversation detail (/app/messages/<id>/ if exists)
5. WebSocket real-time functionality
6. Message sending/receiving
7. User status indicators
8. Contact list functionality
9. Blocked users functionality
10. All messaging-related API endpoints

FINDINGS DOCUMENTATION:
-----------------------
All findings are documented inline with detailed comments:
- 500 errors
- 404 errors
- UI issues
- Broken features
- Missing functionality
- WebSocket connection status
- Real-time update functionality

SETUP:
------
pip install playwright pytest-playwright
playwright install chromium

RUN:
----
python test_messages_module.py

RESULTS:
--------
- Screenshots: ./test_results/messages/
- Console output with detailed findings
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Set UTF-8 encoding for console output (Windows compatibility)
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Check if playwright is installed
try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("ERROR: Playwright is not installed.")
    print("Please install it with:")
    print("  pip install playwright pytest-playwright")
    print("  playwright install chromium")
    sys.exit(1)


# Test Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
LOGIN_EMAIL = "company.owner@demo.zumodra.rhematek-solutions.com"
LOGIN_PASSWORD = "Demo@2024!"

# Test results directory
RESULTS_DIR = Path("./test_results/messages")
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")


class MessageTestResult:
    """Store test results for a single messaging page"""
    def __init__(self, page_name: str, url: str):
        self.page_name = page_name
        self.url = url
        self.status_code: Optional[int] = None
        self.load_time: Optional[float] = None
        self.screenshot_path: Optional[str] = None
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.success: bool = False
        self.ui_elements_visible: List[str] = []
        self.ui_elements_missing: List[str] = []
        self.console_errors: List[str] = []
        self.console_warnings: List[str] = []
        self.websocket_status: Optional[str] = None
        self.message_count: Optional[int] = None
        self.conversation_count: Optional[int] = None
        self.notes: List[str] = []

    def add_error(self, error: str):
        """Add an error message"""
        self.errors.append(error)
        self.success = False

    def add_warning(self, warning: str):
        """Add a warning message"""
        self.warnings.append(warning)

    def add_note(self, note: str):
        """Add a note/observation"""
        self.notes.append(note)

    def to_dict(self) -> Dict:
        """Convert result to dictionary for JSON export"""
        return {
            'page_name': self.page_name,
            'url': self.url,
            'status_code': self.status_code,
            'load_time': self.load_time,
            'screenshot_path': self.screenshot_path,
            'success': self.success,
            'errors': self.errors,
            'warnings': self.warnings,
            'ui_elements_visible': self.ui_elements_visible,
            'ui_elements_missing': self.ui_elements_missing,
            'console_errors': self.console_errors,
            'console_warnings': self.console_warnings,
            'websocket_status': self.websocket_status,
            'message_count': self.message_count,
            'conversation_count': self.conversation_count,
            'notes': self.notes,
        }


class MessageModuleTester:
    """Test harness for Messages/Real-time Chat module"""

    def __init__(self):
        self.results: List[MessageTestResult] = []
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.authenticated = False

        # Ensure results directory exists
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    def setup(self):
        """Initialize Playwright browser"""
        print("\n" + "="*80)
        print("ZUMODRA MESSAGES MODULE TEST - Starting")
        print("="*80)
        print(f"Base URL: {BASE_URL}")
        print(f"Timestamp: {TIMESTAMP}")
        print(f"Results Directory: {RESULTS_DIR}")
        print("="*80 + "\n")

        playwright = sync_playwright().start()
        self.browser = playwright.chromium.launch(headless=False)  # Set to True for CI/CD
        self.context = self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )

        # Enable console logging
        self.page = self.context.new_page()

        # Track console messages
        self.page.on("console", lambda msg: self._handle_console(msg))
        self.page.on("pageerror", lambda exc: self._handle_page_error(exc))

    def _handle_console(self, msg):
        """Handle console messages"""
        # Store in current result if available
        if self.results:
            current_result = self.results[-1]
            if msg.type == "error":
                current_result.console_errors.append(msg.text)
            elif msg.type == "warning":
                current_result.console_warnings.append(msg.text)

    def _handle_page_error(self, exc):
        """Handle page errors"""
        if self.results:
            current_result = self.results[-1]
            current_result.add_error(f"Page error: {exc}")

    def teardown(self):
        """Close browser and cleanup"""
        if self.page:
            self.page.close()
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()

    def login(self) -> bool:
        """
        Authenticate to the application.

        FINDING: Tests if login functionality works correctly
        - Checks if login page loads
        - Verifies login form elements
        - Tests authentication process
        - Captures any login errors
        """
        print("\n" + "-"*80)
        print("STEP 1: Authentication")
        print("-"*80)

        result = MessageTestResult("Login Page", f"{BASE_URL}/accounts/login/")
        self.results.append(result)

        try:
            start_time = time.time()

            # Navigate to login page
            print(f"Navigating to: {result.url}")
            response = self.page.goto(result.url, wait_until='networkidle', timeout=30000)
            result.status_code = response.status if response else None
            result.load_time = time.time() - start_time

            print(f"Status Code: {result.status_code}")
            print(f"Load Time: {result.load_time:.2f}s")

            # Take screenshot
            screenshot_file = RESULTS_DIR / f"01_login_page_{TIMESTAMP}.png"
            self.page.screenshot(path=str(screenshot_file), full_page=True)
            result.screenshot_path = str(screenshot_file)
            print(f"Screenshot: {screenshot_file}")

            # Check for login form
            email_input = self.page.locator('input[name="login"], input[type="email"]')
            password_input = self.page.locator('input[name="password"], input[type="password"]')
            login_button = self.page.locator('button[type="submit"], input[type="submit"]')

            if email_input.count() > 0:
                result.ui_elements_visible.append("Email input field")
            else:
                result.add_error("Email input field not found")

            if password_input.count() > 0:
                result.ui_elements_visible.append("Password input field")
            else:
                result.add_error("Password input field not found")

            if login_button.count() > 0:
                result.ui_elements_visible.append("Login button")
            else:
                result.add_error("Login button not found")

            # Attempt login
            if email_input.count() > 0 and password_input.count() > 0:
                print(f"\nAttempting login with: {LOGIN_EMAIL}")
                email_input.first.fill(LOGIN_EMAIL)
                password_input.first.fill(LOGIN_PASSWORD)

                # Click login button
                login_button.first.click()

                # Wait for navigation
                self.page.wait_for_load_state('networkidle', timeout=30000)

                # Check if we're logged in
                current_url = self.page.url
                print(f"After login URL: {current_url}")

                # Take post-login screenshot
                screenshot_file = RESULTS_DIR / f"02_after_login_{TIMESTAMP}.png"
                self.page.screenshot(path=str(screenshot_file), full_page=True)
                print(f"Post-login Screenshot: {screenshot_file}")

                # Check for common login failure indicators
                if 'login' in current_url.lower():
                    # Check for error messages
                    error_msg = self.page.locator('.error, .alert-danger, .errorlist').first
                    if error_msg.count() > 0:
                        error_text = error_msg.inner_text()
                        result.add_error(f"Login failed: {error_text}")
                        print(f"ERROR: Login failed - {error_text}")
                        return False
                    else:
                        result.add_warning("Still on login page, but no error message visible")
                        print("WARNING: Still on login page after login attempt")
                        return False
                else:
                    result.success = True
                    self.authenticated = True
                    print("SUCCESS: Login successful")
                    result.add_note("Successfully authenticated")
                    return True
            else:
                result.add_error("Cannot login - form elements missing")
                return False

        except PlaywrightTimeoutError as e:
            result.add_error(f"Timeout during login: {str(e)}")
            print(f"ERROR: Timeout - {str(e)}")
            return False
        except Exception as e:
            result.add_error(f"Login failed: {str(e)}")
            print(f"ERROR: {str(e)}")
            return False

    def test_messages_inbox(self):
        """
        Test the main messages inbox page.

        URL: /app/messages/

        FINDING: Documents the state of the main messaging interface
        - Page accessibility (status code)
        - UI elements (conversation list, message panel, compose button)
        - Conversation count
        - Message count
        - User status indicators
        - WebSocket connection status
        - Any errors or missing features
        """
        print("\n" + "-"*80)
        print("STEP 2: Testing Messages Inbox (/app/messages/)")
        print("-"*80)

        result = MessageTestResult("Messages Inbox", f"{BASE_URL}/app/messages/")
        self.results.append(result)

        try:
            start_time = time.time()

            print(f"Navigating to: {result.url}")
            response = self.page.goto(result.url, wait_until='networkidle', timeout=30000)
            result.status_code = response.status if response else None
            result.load_time = time.time() - start_time

            print(f"Status Code: {result.status_code}")
            print(f"Load Time: {result.load_time:.2f}s")

            # FINDING: Check status code
            if result.status_code == 500:
                result.add_error("500 Internal Server Error - Messages inbox is broken")
                print("ERROR: 500 Internal Server Error")
            elif result.status_code == 404:
                result.add_error("404 Not Found - Messages inbox URL does not exist")
                print("ERROR: 404 Not Found")
            elif result.status_code == 403:
                result.add_error("403 Forbidden - Access denied to messages inbox")
                print("ERROR: 403 Forbidden")
            elif result.status_code == 200:
                result.add_note("Messages inbox loaded successfully (200 OK)")
                print("SUCCESS: Page loaded (200 OK)")
            else:
                result.add_warning(f"Unexpected status code: {result.status_code}")
                print(f"WARNING: Unexpected status code: {result.status_code}")

            # Take screenshot
            screenshot_file = RESULTS_DIR / f"03_messages_inbox_{TIMESTAMP}.png"
            self.page.screenshot(path=str(screenshot_file), full_page=True)
            result.screenshot_path = str(screenshot_file)
            print(f"Screenshot: {screenshot_file}")

            # FINDING: Check for error page content
            page_content = self.page.content()
            if "500" in page_content or "Internal Server Error" in page_content:
                result.add_error("Page shows 500 error content")
                print("ERROR: Page content indicates 500 error")
            if "404" in page_content or "Not Found" in page_content:
                result.add_error("Page shows 404 error content")
                print("ERROR: Page content indicates 404 error")

            # FINDING: Check UI elements
            print("\nChecking UI elements...")

            # Conversation list
            conversation_list = self.page.locator('.conversation-list, .chat-list, [data-conversation-list]')
            if conversation_list.count() > 0:
                result.ui_elements_visible.append("Conversation list")
                result.conversation_count = conversation_list.first.locator('.conversation-item, .chat-item, li, div.conversation').count()
                result.add_note(f"Found {result.conversation_count} conversations")
                print(f"✓ Conversation list visible ({result.conversation_count} conversations)")
            else:
                result.ui_elements_missing.append("Conversation list")
                result.add_warning("Conversation list not found")
                print("✗ Conversation list not found")

            # Message panel
            message_panel = self.page.locator('.message-panel, .chat-panel, .messages-container, [data-message-panel]')
            if message_panel.count() > 0:
                result.ui_elements_visible.append("Message panel")
                print("✓ Message panel visible")
            else:
                result.ui_elements_missing.append("Message panel")
                result.add_warning("Message panel not found")
                print("✗ Message panel not found")

            # Compose button
            compose_btn = self.page.locator('button:has-text("Compose"), a:has-text("Compose"), .compose-btn, [data-compose]')
            if compose_btn.count() > 0:
                result.ui_elements_visible.append("Compose button")
                print("✓ Compose button visible")
            else:
                result.ui_elements_missing.append("Compose button")
                result.add_warning("Compose button not found")
                print("✗ Compose button not found")

            # Contact list
            contact_list = self.page.locator('.contact-list, .contacts, [data-contact-list]')
            if contact_list.count() > 0:
                result.ui_elements_visible.append("Contact list")
                contact_count = contact_list.first.locator('.contact-item, li, div.contact').count()
                result.add_note(f"Found {contact_count} contacts")
                print(f"✓ Contact list visible ({contact_count} contacts)")
            else:
                result.ui_elements_missing.append("Contact list")
                result.add_warning("Contact list not found")
                print("✗ Contact list not found")

            # User status indicators
            status_indicators = self.page.locator('.user-status, .online-status, .status-indicator')
            if status_indicators.count() > 0:
                result.ui_elements_visible.append("User status indicators")
                print("✓ User status indicators visible")
            else:
                result.ui_elements_missing.append("User status indicators")
                result.add_warning("User status indicators not found")
                print("✗ User status indicators not found")

            # Search functionality
            search_input = self.page.locator('input[type="search"], input[placeholder*="Search"], .search-input')
            if search_input.count() > 0:
                result.ui_elements_visible.append("Search input")
                print("✓ Search input visible")
            else:
                result.ui_elements_missing.append("Search input")
                result.add_note("Search functionality not found (may not be implemented)")
                print("✗ Search input not found")

            # FINDING: Check WebSocket connection
            print("\nChecking WebSocket connection...")
            try:
                # Look for WebSocket connection in network
                ws_status = self.page.evaluate("""
                    () => {
                        // Check for WebSocket objects in window
                        if (window.chatSocket || window.messageSocket || window.ws) {
                            const ws = window.chatSocket || window.messageSocket || window.ws;
                            return {
                                connected: ws.readyState === WebSocket.OPEN,
                                readyState: ws.readyState,
                                url: ws.url
                            };
                        }
                        return null;
                    }
                """)

                if ws_status:
                    if ws_status.get('connected'):
                        result.websocket_status = "Connected"
                        result.add_note(f"WebSocket connected to: {ws_status.get('url')}")
                        print(f"✓ WebSocket connected: {ws_status.get('url')}")
                    else:
                        result.websocket_status = "Disconnected"
                        result.add_warning(f"WebSocket disconnected (readyState: {ws_status.get('readyState')})")
                        print(f"✗ WebSocket disconnected (readyState: {ws_status.get('readyState')})")
                else:
                    result.websocket_status = "Not found"
                    result.add_warning("WebSocket object not found in page")
                    print("✗ WebSocket object not found")
            except Exception as e:
                result.websocket_status = "Error checking"
                result.add_warning(f"Error checking WebSocket: {str(e)}")
                print(f"✗ Error checking WebSocket: {str(e)}")

            # Success criteria
            if result.status_code == 200 and len(result.errors) == 0:
                result.success = True
                print("\n✓ Messages inbox test PASSED")
            else:
                print("\n✗ Messages inbox test FAILED")

        except PlaywrightTimeoutError as e:
            result.add_error(f"Timeout loading messages inbox: {str(e)}")
            print(f"ERROR: Timeout - {str(e)}")
        except Exception as e:
            result.add_error(f"Error testing messages inbox: {str(e)}")
            print(f"ERROR: {str(e)}")

    def test_message_sending(self):
        """
        Test sending a message functionality.

        FINDING: Documents message sending capability
        - Message input field presence
        - Send button functionality
        - Message delivery
        - Real-time updates
        - Any errors during send
        """
        print("\n" + "-"*80)
        print("STEP 3: Testing Message Sending")
        print("-"*80)

        result = MessageTestResult("Send Message", f"{BASE_URL}/app/messages/")
        self.results.append(result)

        try:
            # Check if we're still on messages page
            current_url = self.page.url
            if '/messages' not in current_url:
                print("Navigating back to messages page...")
                self.page.goto(f"{BASE_URL}/app/messages/", wait_until='networkidle', timeout=30000)

            # FINDING: Look for message input field
            message_input = self.page.locator('textarea[placeholder*="message"], input[placeholder*="message"], .message-input, [data-message-input]')

            if message_input.count() > 0:
                result.ui_elements_visible.append("Message input field")
                print("✓ Message input field found")

                # Try to send a test message
                test_message = f"Test message from automated testing - {datetime.now().strftime('%H:%M:%S')}"
                print(f"Attempting to send: '{test_message}'")

                message_input.first.fill(test_message)

                # Take screenshot before sending
                screenshot_file = RESULTS_DIR / f"04_before_send_{TIMESTAMP}.png"
                self.page.screenshot(path=str(screenshot_file), full_page=True)
                print(f"Screenshot (before send): {screenshot_file}")

                # Look for send button
                send_btn = self.page.locator('button:has-text("Send"), .send-btn, [data-send]')
                if send_btn.count() > 0:
                    result.ui_elements_visible.append("Send button")
                    print("✓ Send button found")

                    # Click send
                    send_btn.first.click()

                    # Wait a moment for message to be sent
                    time.sleep(2)

                    # Take screenshot after sending
                    screenshot_file = RESULTS_DIR / f"05_after_send_{TIMESTAMP}.png"
                    self.page.screenshot(path=str(screenshot_file), full_page=True)
                    result.screenshot_path = str(screenshot_file)
                    print(f"Screenshot (after send): {screenshot_file}")

                    # Check if message appears in the chat
                    sent_message = self.page.locator(f'text="{test_message}"')
                    if sent_message.count() > 0:
                        result.add_note("Message successfully sent and appears in chat")
                        result.success = True
                        print("✓ Message sent successfully")
                    else:
                        result.add_warning("Message sent but does not appear in chat (may be async delay)")
                        print("⚠ Message not immediately visible (may be async)")

                        # Wait a bit longer and check again
                        time.sleep(3)
                        if sent_message.count() > 0:
                            result.add_note("Message appeared after delay")
                            result.success = True
                            print("✓ Message appeared after delay")
                        else:
                            result.add_error("Message never appeared in chat after sending")
                            print("✗ Message never appeared")
                else:
                    result.ui_elements_missing.append("Send button")
                    result.add_error("Send button not found - cannot test sending")
                    print("✗ Send button not found")
            else:
                result.ui_elements_missing.append("Message input field")
                result.add_error("Message input field not found - cannot test sending")
                print("✗ Message input field not found")

        except Exception as e:
            result.add_error(f"Error testing message sending: {str(e)}")
            print(f"ERROR: {str(e)}")

    def test_conversation_detail(self):
        """
        Test viewing a conversation detail.

        FINDING: Documents conversation detail view
        - Ability to open conversations
        - Message history display
        - Conversation metadata
        - Any errors loading conversation
        """
        print("\n" + "-"*80)
        print("STEP 4: Testing Conversation Detail View")
        print("-"*80)

        result = MessageTestResult("Conversation Detail", f"{BASE_URL}/app/messages/")
        self.results.append(result)

        try:
            # Check if we're still on messages page
            current_url = self.page.url
            if '/messages' not in current_url:
                print("Navigating back to messages page...")
                self.page.goto(f"{BASE_URL}/app/messages/", wait_until='networkidle', timeout=30000)

            # FINDING: Try to click on a conversation
            conversation_items = self.page.locator('.conversation-item, .chat-item, [data-conversation]')

            if conversation_items.count() > 0:
                print(f"Found {conversation_items.count()} conversations, clicking first one...")

                # Click first conversation
                conversation_items.first.click()

                # Wait for messages to load
                time.sleep(2)

                # Take screenshot
                screenshot_file = RESULTS_DIR / f"06_conversation_detail_{TIMESTAMP}.png"
                self.page.screenshot(path=str(screenshot_file), full_page=True)
                result.screenshot_path = str(screenshot_file)
                print(f"Screenshot: {screenshot_file}")

                # Check for message display
                messages = self.page.locator('.message, .chat-message, [data-message]')
                if messages.count() > 0:
                    result.message_count = messages.count()
                    result.add_note(f"Conversation has {result.message_count} messages")
                    result.ui_elements_visible.append("Message history")
                    result.success = True
                    print(f"✓ Conversation loaded with {result.message_count} messages")
                else:
                    result.add_warning("No messages found in conversation (may be empty)")
                    print("⚠ No messages found in conversation")

                # Check for conversation header
                header = self.page.locator('.conversation-header, .chat-header, [data-conversation-header]')
                if header.count() > 0:
                    result.ui_elements_visible.append("Conversation header")
                    print("✓ Conversation header visible")
                else:
                    result.ui_elements_missing.append("Conversation header")
                    print("✗ Conversation header not found")

                # Check for participant info
                participant = self.page.locator('.participant, .chat-participant, .user-info')
                if participant.count() > 0:
                    result.ui_elements_visible.append("Participant info")
                    print("✓ Participant info visible")
                else:
                    result.ui_elements_missing.append("Participant info")
                    print("✗ Participant info not found")

            else:
                result.add_warning("No conversations found to test detail view")
                print("⚠ No conversations available to test")

        except Exception as e:
            result.add_error(f"Error testing conversation detail: {str(e)}")
            print(f"ERROR: {str(e)}")

    def test_compose_message(self):
        """
        Test composing a new message/conversation.

        URL: /app/messages/compose/ (if exists)

        FINDING: Documents compose functionality
        - Compose button/link
        - Recipient selection
        - Message composition
        - Any errors
        """
        print("\n" + "-"*80)
        print("STEP 5: Testing Compose New Message")
        print("-"*80)

        result = MessageTestResult("Compose Message", f"{BASE_URL}/app/messages/compose/")
        self.results.append(result)

        try:
            # First, try the dedicated compose URL
            print(f"Trying compose URL: {result.url}")
            response = self.page.goto(result.url, wait_until='networkidle', timeout=30000)
            result.status_code = response.status if response else None

            print(f"Status Code: {result.status_code}")

            # Take screenshot
            screenshot_file = RESULTS_DIR / f"07_compose_message_{TIMESTAMP}.png"
            self.page.screenshot(path=str(screenshot_file), full_page=True)
            result.screenshot_path = str(screenshot_file)
            print(f"Screenshot: {screenshot_file}")

            if result.status_code == 404:
                result.add_warning("Compose URL returns 404 - may not be implemented")
                print("⚠ Compose URL not found (404)")

                # Try to find compose button on main page
                print("Looking for compose button on main messages page...")
                self.page.goto(f"{BASE_URL}/app/messages/", wait_until='networkidle', timeout=30000)

                compose_btn = self.page.locator('button:has-text("Compose"), a:has-text("Compose"), .compose-btn, [data-compose], button:has-text("New Message"), a:has-text("New Message")')
                if compose_btn.count() > 0:
                    result.add_note("Compose button found on main page")
                    print("✓ Compose button found on main page")

                    compose_btn.first.click()
                    time.sleep(2)

                    # Take screenshot after clicking
                    screenshot_file = RESULTS_DIR / f"08_compose_opened_{TIMESTAMP}.png"
                    self.page.screenshot(path=str(screenshot_file), full_page=True)
                    print(f"Screenshot (after compose click): {screenshot_file}")

                    # Check for compose form
                    recipient_field = self.page.locator('input[placeholder*="recipient"], select[name*="recipient"], .recipient-select')
                    if recipient_field.count() > 0:
                        result.ui_elements_visible.append("Recipient field")
                        result.success = True
                        print("✓ Recipient field found")
                    else:
                        result.ui_elements_missing.append("Recipient field")
                        print("✗ Recipient field not found")
                else:
                    result.add_error("Compose functionality not found")
                    print("✗ Compose button not found")

            elif result.status_code == 200:
                result.add_note("Compose page loads successfully")
                print("✓ Compose page loaded (200 OK)")

                # Check for compose form elements
                recipient_field = self.page.locator('input[placeholder*="recipient"], select[name*="recipient"], .recipient-select')
                message_field = self.page.locator('textarea[placeholder*="message"], .message-input')
                send_button = self.page.locator('button:has-text("Send"), .send-btn')

                if recipient_field.count() > 0:
                    result.ui_elements_visible.append("Recipient field")
                    print("✓ Recipient field found")
                else:
                    result.ui_elements_missing.append("Recipient field")
                    print("✗ Recipient field not found")

                if message_field.count() > 0:
                    result.ui_elements_visible.append("Message field")
                    print("✓ Message field found")
                else:
                    result.ui_elements_missing.append("Message field")
                    print("✗ Message field not found")

                if send_button.count() > 0:
                    result.ui_elements_visible.append("Send button")
                    result.success = True
                    print("✓ Send button found")
                else:
                    result.ui_elements_missing.append("Send button")
                    print("✗ Send button not found")
            else:
                result.add_error(f"Unexpected status code: {result.status_code}")
                print(f"✗ Unexpected status code: {result.status_code}")

        except Exception as e:
            result.add_error(f"Error testing compose message: {str(e)}")
            print(f"ERROR: {str(e)}")

    def test_api_endpoints(self):
        """
        Test Messages API endpoints.

        API Endpoints:
        - /api/v1/messages/conversations/
        - /api/v1/messages/messages/
        - /api/v1/messages/contacts/
        - /api/v1/messages/status/

        FINDING: Documents API availability and functionality
        """
        print("\n" + "-"*80)
        print("STEP 6: Testing Messages API Endpoints")
        print("-"*80)

        api_endpoints = [
            ('/api/v1/messages/conversations/', 'Conversations API'),
            ('/api/v1/messages/messages/', 'Messages API'),
            ('/api/v1/messages/contacts/', 'Contacts API'),
            ('/api/v1/messages/friend-requests/', 'Friend Requests API'),
            ('/api/v1/messages/blocked/', 'Blocked Users API'),
            ('/api/v1/messages/status/', 'User Status API'),
        ]

        for endpoint_path, endpoint_name in api_endpoints:
            result = MessageTestResult(endpoint_name, f"{BASE_URL}{endpoint_path}")
            self.results.append(result)

            try:
                print(f"\nTesting: {endpoint_name}")
                print(f"URL: {result.url}")

                response = self.page.goto(result.url, wait_until='networkidle', timeout=30000)
                result.status_code = response.status if response else None

                print(f"Status Code: {result.status_code}")

                # Take screenshot
                screenshot_file = RESULTS_DIR / f"09_api_{endpoint_name.lower().replace(' ', '_')}_{TIMESTAMP}.png"
                self.page.screenshot(path=str(screenshot_file), full_page=True)
                result.screenshot_path = str(screenshot_file)
                print(f"Screenshot: {screenshot_file}")

                # Check response
                if result.status_code == 200:
                    result.add_note("API endpoint is accessible")
                    result.success = True
                    print("✓ API endpoint accessible (200 OK)")

                    # Try to parse JSON response
                    try:
                        content = self.page.content()
                        if 'application/json' in content or '{' in content:
                            result.add_note("API returns JSON response")
                            print("✓ API returns JSON")
                        else:
                            result.add_warning("API response may not be JSON")
                            print("⚠ Response may not be JSON")
                    except:
                        pass

                elif result.status_code == 401:
                    result.add_warning("API requires authentication (401)")
                    print("⚠ API requires authentication")
                elif result.status_code == 403:
                    result.add_warning("API access forbidden (403)")
                    print("⚠ API access forbidden")
                elif result.status_code == 404:
                    result.add_error("API endpoint not found (404)")
                    print("✗ API endpoint not found")
                elif result.status_code == 500:
                    result.add_error("API server error (500)")
                    print("✗ API server error")
                else:
                    result.add_warning(f"Unexpected status code: {result.status_code}")
                    print(f"⚠ Unexpected status code: {result.status_code}")

            except Exception as e:
                result.add_error(f"Error testing API endpoint: {str(e)}")
                print(f"ERROR: {str(e)}")

    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n\n" + "="*80)
        print("TEST RESULTS SUMMARY")
        print("="*80)

        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.success)
        failed_tests = total_tests - passed_tests

        print(f"\nTotal Tests: {total_tests}")
        print(f"Passed: {passed_tests} ({passed_tests/total_tests*100:.1f}%)")
        print(f"Failed: {failed_tests} ({failed_tests/total_tests*100:.1f}%)")

        # Count issues
        total_errors = sum(len(r.errors) for r in self.results)
        total_warnings = sum(len(r.warnings) for r in self.results)

        print(f"\nTotal Errors: {total_errors}")
        print(f"Total Warnings: {total_warnings}")

        # Detailed results
        print("\n" + "="*80)
        print("DETAILED FINDINGS")
        print("="*80)

        for i, result in enumerate(self.results, 1):
            print(f"\n{i}. {result.page_name}")
            print(f"   URL: {result.url}")
            print(f"   Status: {'PASS' if result.success else 'FAIL'}")
            print(f"   HTTP Status: {result.status_code}")
            print(f"   Load Time: {result.load_time:.2f}s" if result.load_time else "   Load Time: N/A")
            print(f"   Screenshot: {result.screenshot_path}")

            if result.websocket_status:
                print(f"   WebSocket: {result.websocket_status}")
            if result.message_count is not None:
                print(f"   Messages: {result.message_count}")
            if result.conversation_count is not None:
                print(f"   Conversations: {result.conversation_count}")

            if result.ui_elements_visible:
                print(f"   ✓ Visible Elements: {', '.join(result.ui_elements_visible)}")
            if result.ui_elements_missing:
                print(f"   ✗ Missing Elements: {', '.join(result.ui_elements_missing)}")

            if result.notes:
                print(f"   Notes:")
                for note in result.notes:
                    print(f"     - {note}")

            if result.errors:
                print(f"   ERRORS:")
                for error in result.errors:
                    print(f"     ✗ {error}")

            if result.warnings:
                print(f"   WARNINGS:")
                for warning in result.warnings:
                    print(f"     ⚠ {warning}")

            if result.console_errors:
                print(f"   Console Errors:")
                for error in result.console_errors[:5]:  # Show first 5
                    print(f"     - {error}")
                if len(result.console_errors) > 5:
                    print(f"     ... and {len(result.console_errors) - 5} more")

        # Save JSON report
        report_file = RESULTS_DIR / f"test_report_{TIMESTAMP}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'timestamp': TIMESTAMP,
                'base_url': BASE_URL,
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'total_errors': total_errors,
                'total_warnings': total_warnings,
                'results': [r.to_dict() for r in self.results]
            }, f, indent=2)

        print(f"\n\n{'='*80}")
        print(f"JSON Report saved to: {report_file}")
        print("="*80 + "\n")

    def run(self):
        """Execute all tests"""
        try:
            self.setup()

            # Step 1: Login
            if not self.login():
                print("\nERROR: Authentication failed. Cannot proceed with tests.")
                return

            # Step 2-6: Test messaging features
            self.test_messages_inbox()
            self.test_message_sending()
            self.test_conversation_detail()
            self.test_compose_message()
            self.test_api_endpoints()

            # Generate report
            self.generate_report()

        except Exception as e:
            print(f"\nFATAL ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self.teardown()


def main():
    """Main entry point"""
    tester = MessageModuleTester()
    tester.run()


if __name__ == '__main__':
    main()
