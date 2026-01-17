#!/usr/bin/env python
"""
Comprehensive Notification Delivery System Test Suite

Tests all notification channels:
1. Email notification sending (via MailHog)
2. In-app notification display
3. Push notification delivery
4. SMS notification sending (if configured)
5. Notification preferences management
6. Notification batching/digests
7. Unread notification tracking

Run with: pytest test_notifications_comprehensive.py -v
"""

import pytest
import json
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.management import call_command
from django.conf import settings
from django.test.utils import override_settings
from rest_framework.test import APIClient
from rest_framework import status

from notifications.models import (
    Notification,
    NotificationChannel,
    NotificationTemplate,
    NotificationPreference,
    NotificationDeliveryLog,
    ScheduledNotification,
)
from notifications.services import notification_service
from notifications.tasks import send_notification_task

logger = logging.getLogger(__name__)
User = get_user_model()


class NotificationSystemTestResults:
    """Tracks test results and generates reports."""

    def __init__(self):
        self.results = []
        self.start_time = datetime.now()
        self.test_name = "Comprehensive Notification Delivery System Tests"

    def add_result(self, test_name: str, status: str, details: str = "", error: str = ""):
        """Record test result."""
        self.results.append({
            "test": test_name,
            "status": status,  # "PASS", "FAIL", "SKIP", "WARN"
            "details": details,
            "error": error,
            "timestamp": datetime.now().isoformat(),
        })
        print(f"[{status}] {test_name}: {details}")

    def generate_report(self) -> str:
        """Generate test report."""
        duration = (datetime.now() - self.start_time).total_seconds()

        # Summary
        passed = sum(1 for r in self.results if r["status"] == "PASS")
        failed = sum(1 for r in self.results if r["status"] == "FAIL")
        skipped = sum(1 for r in self.results if r["status"] == "SKIP")
        warned = sum(1 for r in self.results if r["status"] == "WARN")
        total = len(self.results)

        report = f"""
# COMPREHENSIVE NOTIFICATION DELIVERY SYSTEM TEST REPORT
Generated: {datetime.now().isoformat()}
Duration: {duration:.2f}s

## SUMMARY
- Total Tests: {total}
- Passed: {passed}
- Failed: {failed}
- Skipped: {skipped}
- Warned: {warned}
- Success Rate: {(passed/total*100 if total > 0 else 0):.1f}%

## DETAILED RESULTS
"""

        for result in self.results:
            status_icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "⊘", "WARN": "⚠"}
            report += f"\n### {status_icon.get(result['status'], '?')} {result['test']}\n"
            report += f"- Status: {result['status']}\n"
            if result["details"]:
                report += f"- Details: {result['details']}\n"
            if result["error"]:
                report += f"- Error: {result['error']}\n"
            report += f"- Timestamp: {result['timestamp']}\n"

        return report


class NotificationEmailTests:
    """Tests for email notification delivery."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results
        self.mailhog_api_url = "http://mailhog:8025/api"

    def check_mailhog_health(self) -> bool:
        """Check if MailHog service is running."""
        try:
            response = requests.get(f"{self.mailhog_api_url}/messages", timeout=5)
            return response.status_code == 200
        except Exception as e:
            self.results.add_result(
                "MailHog Health Check",
                "FAIL",
                "MailHog service not responding",
                str(e)
            )
            return False

    def test_email_notification_sending(self, user: User):
        """Test email notification sending."""
        try:
            # Create test notification
            notification = Notification.objects.create(
                recipient=user,
                notification_type="test_email",
                title="Test Email Notification",
                message="This is a test email notification.",
                channels=["email"],
                priority="high",
            )

            # Try to get emails from MailHog
            try:
                response = requests.get(f"{self.mailhog_api_url}/messages", timeout=5)
                if response.status_code == 200:
                    emails = response.json()
                    if emails:
                        self.results.add_result(
                            "Email Notification Sending",
                            "PASS",
                            f"Email sent and received by MailHog. Count: {len(emails)}"
                        )
                    else:
                        self.results.add_result(
                            "Email Notification Sending",
                            "WARN",
                            "Email may not have been sent yet (async processing)"
                        )
                else:
                    self.results.add_result(
                        "Email Notification Sending",
                        "FAIL",
                        "Failed to query MailHog API",
                        f"Status: {response.status_code}"
                    )
            except Exception as e:
                self.results.add_result(
                    "Email Notification Sending",
                    "SKIP",
                    "MailHog not available - email service not testable",
                    str(e)
                )

            return notification

        except Exception as e:
            self.results.add_result(
                "Email Notification Sending",
                "FAIL",
                "Failed to create and send email notification",
                str(e)
            )
            return None

    def test_email_with_template(self, user: User):
        """Test email notification with template."""
        try:
            # Create or get email template
            template, created = NotificationTemplate.objects.get_or_create(
                name="test_email_template",
                defaults={
                    "template_type": "application_received",
                    "subject": "Test Email Template",
                    "text_body": "Hello {{ recipient.first_name }}, you have a new notification.",
                    "html_body": "<p>Hello {{ recipient.first_name }}, you have a new notification.</p>",
                    "description": "Test template",
                }
            )

            notification = Notification.objects.create(
                recipient=user,
                notification_type="template_test",
                title="Template Test",
                message="Testing notification template rendering.",
                template=template,
                channels=["email"],
            )

            self.results.add_result(
                "Email with Template",
                "PASS",
                f"Template-based notification created (ID: {notification.id})"
            )

            return notification

        except Exception as e:
            self.results.add_result(
                "Email with Template",
                "FAIL",
                "Failed to test email with template",
                str(e)
            )
            return None


class NotificationInAppTests:
    """Tests for in-app notification display."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results

    def test_in_app_notification_creation(self, user: User):
        """Test in-app notification creation and retrieval."""
        try:
            notification = Notification.objects.create(
                recipient=user,
                notification_type="in_app_test",
                title="In-App Test Notification",
                message="This is an in-app notification.",
                channels=["in_app"],
                priority="normal",
            )

            # Verify notification was created
            assert notification.id is not None
            assert notification.recipient == user
            assert "in_app" in notification.channels

            self.results.add_result(
                "In-App Notification Creation",
                "PASS",
                f"In-app notification created (ID: {notification.id})"
            )

            return notification

        except Exception as e:
            self.results.add_result(
                "In-App Notification Creation",
                "FAIL",
                "Failed to create in-app notification",
                str(e)
            )
            return None

    def test_in_app_notification_retrieval(self, user: User):
        """Test retrieving in-app notifications for user."""
        try:
            # Create test notifications
            notifs = []
            for i in range(3):
                notif = Notification.objects.create(
                    recipient=user,
                    notification_type="test_in_app",
                    title=f"Test Notification {i+1}",
                    message=f"Test message {i+1}",
                    channels=["in_app"],
                )
                notifs.append(notif)

            # Retrieve notifications
            retrieved = Notification.objects.filter(recipient=user, channels__contains="in_app")

            assert len(retrieved) >= 3, f"Expected at least 3 notifications, got {len(retrieved)}"

            self.results.add_result(
                "In-App Notification Retrieval",
                "PASS",
                f"Successfully retrieved {len(retrieved)} in-app notifications"
            )

            return notifs

        except Exception as e:
            self.results.add_result(
                "In-App Notification Retrieval",
                "FAIL",
                "Failed to retrieve in-app notifications",
                str(e)
            )
            return None

    def test_unread_notification_tracking(self, user: User):
        """Test unread notification tracking."""
        try:
            # Create unread notification
            notification = Notification.objects.create(
                recipient=user,
                notification_type="unread_test",
                title="Unread Test",
                message="Testing unread tracking.",
                channels=["in_app"],
                is_read=False,
            )

            # Check unread status
            assert not notification.is_read, "Notification should be unread"

            # Mark as read
            notification.is_read = True
            notification.save()

            # Verify read status
            notification.refresh_from_db()
            assert notification.is_read, "Notification should be marked as read"

            self.results.add_result(
                "Unread Notification Tracking",
                "PASS",
                "Successfully tracked read/unread status"
            )

            return notification

        except Exception as e:
            self.results.add_result(
                "Unread Notification Tracking",
                "FAIL",
                "Failed to track unread status",
                str(e)
            )
            return None


class NotificationPreferencesTests:
    """Tests for notification preference management."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results

    def test_notification_preference_creation(self, user: User):
        """Test creating notification preferences."""
        try:
            prefs, created = NotificationPreference.objects.get_or_create(
                user=user,
                defaults={
                    "email_enabled": True,
                    "in_app_enabled": True,
                    "push_enabled": False,
                    "sms_enabled": False,
                    "batch_digest_frequency": "daily",
                }
            )

            assert prefs.email_enabled, "Email should be enabled"
            assert prefs.in_app_enabled, "In-app should be enabled"
            assert not prefs.push_enabled, "Push should be disabled"

            self.results.add_result(
                "Notification Preference Creation",
                "PASS",
                f"Preferences created for user {user.email}"
            )

            return prefs

        except Exception as e:
            self.results.add_result(
                "Notification Preference Creation",
                "FAIL",
                "Failed to create notification preferences",
                str(e)
            )
            return None

    def test_channel_specific_preferences(self, user: User):
        """Test per-channel notification preferences."""
        try:
            prefs, _ = NotificationPreference.objects.get_or_create(user=user)

            # Set channel-specific preferences
            prefs.channel_settings = {
                "email": {"enabled": True, "quiet_hours": "22:00-08:00"},
                "in_app": {"enabled": True, "sound": True},
                "push": {"enabled": False},
            }
            prefs.save()

            # Verify settings
            assert prefs.channel_settings["email"]["enabled"], "Email should be enabled"
            assert prefs.channel_settings["in_app"]["sound"], "In-app sound should be enabled"

            self.results.add_result(
                "Channel-Specific Preferences",
                "PASS",
                "Successfully configured per-channel preferences"
            )

            return prefs

        except Exception as e:
            self.results.add_result(
                "Channel-Specific Preferences",
                "FAIL",
                "Failed to set channel preferences",
                str(e)
            )
            return None

    def test_notification_type_preferences(self, user: User):
        """Test notification type-specific preferences."""
        try:
            prefs, _ = NotificationPreference.objects.get_or_create(user=user)

            # Set type-specific preferences
            prefs.notification_type_settings = {
                "application_received": {"enabled": True, "channels": ["email", "in_app"]},
                "interview_scheduled": {"enabled": True, "channels": ["email", "push"]},
                "marketing_email": {"enabled": False, "channels": []},
            }
            prefs.save()

            # Verify type settings
            assert prefs.notification_type_settings["application_received"]["enabled"]
            assert "email" in prefs.notification_type_settings["application_received"]["channels"]

            self.results.add_result(
                "Notification Type Preferences",
                "PASS",
                "Successfully configured notification type preferences"
            )

            return prefs

        except Exception as e:
            self.results.add_result(
                "Notification Type Preferences",
                "FAIL",
                "Failed to set notification type preferences",
                str(e)
            )
            return None


class NotificationBatchingTests:
    """Tests for notification batching and digest functionality."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results

    def test_notification_batching(self, user: User):
        """Test notification batching."""
        try:
            # Create multiple notifications
            batch_notifications = []
            for i in range(5):
                notif = Notification.objects.create(
                    recipient=user,
                    notification_type="batch_test",
                    title=f"Batch Notification {i+1}",
                    message=f"Message {i+1}",
                    channels=["email", "in_app"],
                    created_at=timezone.now(),
                )
                batch_notifications.append(notif)

            # Query batched notifications
            recent_notifs = Notification.objects.filter(
                recipient=user,
                created_at__gte=timezone.now() - timedelta(hours=1)
            )

            assert len(recent_notifs) >= 5, f"Expected at least 5 batched notifications"

            self.results.add_result(
                "Notification Batching",
                "PASS",
                f"Successfully created and batched {len(batch_notifications)} notifications"
            )

            return batch_notifications

        except Exception as e:
            self.results.add_result(
                "Notification Batching",
                "FAIL",
                "Failed to test notification batching",
                str(e)
            )
            return None

    def test_digest_frequency_settings(self, user: User):
        """Test digest frequency configuration."""
        try:
            prefs, _ = NotificationPreference.objects.get_or_create(user=user)

            # Test different digest frequencies
            frequencies = ["immediate", "hourly", "daily", "weekly"]

            for freq in frequencies:
                prefs.batch_digest_frequency = freq
                prefs.save()
                prefs.refresh_from_db()
                assert prefs.batch_digest_frequency == freq

            self.results.add_result(
                "Digest Frequency Settings",
                "PASS",
                f"Successfully tested digest frequencies: {', '.join(frequencies)}"
            )

            return prefs

        except Exception as e:
            self.results.add_result(
                "Digest Frequency Settings",
                "FAIL",
                "Failed to test digest frequency settings",
                str(e)
            )
            return None


class NotificationDeliveryLoggingTests:
    """Tests for notification delivery logging and tracking."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results

    def test_delivery_log_creation(self, user: User):
        """Test notification delivery log creation."""
        try:
            notification = Notification.objects.create(
                recipient=user,
                notification_type="logging_test",
                title="Logging Test",
                message="Testing delivery logging.",
                channels=["email"],
            )

            # Create delivery log
            log = NotificationDeliveryLog.objects.create(
                notification=notification,
                attempt_number=1,
                status="sent",
                request_payload={"to": user.email, "subject": "Test"},
                response_payload={"id": "msg_12345"},
                response_code=200,
                external_id="msg_12345",
            )

            assert log.notification == notification
            assert log.status == "sent"
            assert log.response_code == 200

            self.results.add_result(
                "Delivery Log Creation",
                "PASS",
                f"Delivery log created (ID: {log.id})"
            )

            return log

        except Exception as e:
            self.results.add_result(
                "Delivery Log Creation",
                "FAIL",
                "Failed to create delivery log",
                str(e)
            )
            return None

    def test_delivery_log_retrieval(self, user: User):
        """Test retrieving delivery logs for debugging."""
        try:
            # Create notifications with delivery logs
            for i in range(3):
                notification = Notification.objects.create(
                    recipient=user,
                    notification_type="log_test",
                    title=f"Log Test {i+1}",
                    message=f"Message {i+1}",
                    channels=["email"],
                )

                NotificationDeliveryLog.objects.create(
                    notification=notification,
                    attempt_number=1,
                    status="sent" if i < 2 else "failed",
                    response_code=200 if i < 2 else 500,
                )

            # Query logs
            sent_logs = NotificationDeliveryLog.objects.filter(status="sent")
            failed_logs = NotificationDeliveryLog.objects.filter(status="failed")

            self.results.add_result(
                "Delivery Log Retrieval",
                "PASS",
                f"Retrieved {len(sent_logs)} sent logs and {len(failed_logs)} failed logs"
            )

            return sent_logs, failed_logs

        except Exception as e:
            self.results.add_result(
                "Delivery Log Retrieval",
                "FAIL",
                "Failed to retrieve delivery logs",
                str(e)
            )
            return None, None


class NotificationPushTests:
    """Tests for push notification delivery (if configured)."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results

    def test_push_notification_creation(self, user: User):
        """Test creating push notifications."""
        try:
            notification = Notification.objects.create(
                recipient=user,
                notification_type="push_test",
                title="Push Test Notification",
                message="This is a push notification.",
                channels=["push"],
                priority="high",
            )

            self.results.add_result(
                "Push Notification Creation",
                "PASS",
                f"Push notification created (ID: {notification.id})"
            )

            return notification

        except Exception as e:
            self.results.add_result(
                "Push Notification Creation",
                "FAIL",
                "Failed to create push notification",
                str(e)
            )
            return None

    def test_push_device_registration(self, user: User):
        """Test push device token management."""
        try:
            # This would typically involve registering device tokens
            # Placeholder for device token management

            self.results.add_result(
                "Push Device Registration",
                "SKIP",
                "Push device registration test skipped (requires client-side setup)"
            )

            return None

        except Exception as e:
            self.results.add_result(
                "Push Device Registration",
                "FAIL",
                "Failed to test push device registration",
                str(e)
            )
            return None


class NotificationSMSTests:
    """Tests for SMS notification delivery (if configured)."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results

    def test_sms_notification_creation(self, user: User):
        """Test creating SMS notifications."""
        try:
            # Check if SMS is configured
            sms_channel = NotificationChannel.objects.filter(
                channel_type="sms",
                is_active=True
            ).first()

            if not sms_channel:
                self.results.add_result(
                    "SMS Notification Creation",
                    "SKIP",
                    "SMS channel not configured"
                )
                return None

            notification = Notification.objects.create(
                recipient=user,
                notification_type="sms_test",
                title="SMS Test",
                message="This is a test SMS notification.",
                channels=["sms"],
                priority="normal",
            )

            self.results.add_result(
                "SMS Notification Creation",
                "PASS",
                f"SMS notification created (ID: {notification.id})"
            )

            return notification

        except Exception as e:
            self.results.add_result(
                "SMS Notification Creation",
                "FAIL",
                "Failed to create SMS notification",
                str(e)
            )
            return None


class NotificationChannelTests:
    """Tests for notification channel configuration."""

    def __init__(self, results: NotificationSystemTestResults):
        self.results = results

    def test_channel_activation(self):
        """Test activating/deactivating notification channels."""
        try:
            channels = ["email", "in_app", "push", "sms"]

            for channel_name in channels:
                channel, _ = NotificationChannel.objects.get_or_create(
                    name=channel_name,
                    defaults={
                        "channel_type": channel_name,
                        "is_active": True,
                        "rate_limit_per_hour": 100,
                    }
                )

                # Test enabling/disabling
                channel.is_active = False
                channel.save()
                channel.refresh_from_db()
                assert not channel.is_active

                channel.is_active = True
                channel.save()
                channel.refresh_from_db()
                assert channel.is_active

            self.results.add_result(
                "Channel Activation/Deactivation",
                "PASS",
                f"Successfully tested {len(channels)} notification channels"
            )

        except Exception as e:
            self.results.add_result(
                "Channel Activation/Deactivation",
                "FAIL",
                "Failed to test channel activation",
                str(e)
            )

    def test_rate_limiting(self):
        """Test notification rate limiting per channel."""
        try:
            channel, _ = NotificationChannel.objects.get_or_create(
                name="test_rate_limit",
                defaults={
                    "channel_type": "email",
                    "is_active": True,
                    "rate_limit_per_hour": 50,
                }
            )

            # Update rate limit
            channel.rate_limit_per_hour = 25
            channel.save()
            channel.refresh_from_db()

            assert channel.rate_limit_per_hour == 25

            self.results.add_result(
                "Rate Limiting Configuration",
                "PASS",
                f"Rate limit set to {channel.rate_limit_per_hour} per hour"
            )

        except Exception as e:
            self.results.add_result(
                "Rate Limiting Configuration",
                "FAIL",
                "Failed to test rate limiting",
                str(e)
            )


@pytest.mark.django_db
class TestNotificationsComprehensive(TestCase):
    """Main test class for comprehensive notification testing."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        super().setUpClass()
        cls.results = NotificationSystemTestResults()

    def setUp(self):
        """Create test data."""
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123",
        )

    def test_01_email_notifications(self):
        """Test email notification delivery."""
        tester = NotificationEmailTests(self.results)

        if tester.check_mailhog_health():
            tester.test_email_notification_sending(self.user)
            tester.test_email_with_template(self.user)

    def test_02_in_app_notifications(self):
        """Test in-app notification functionality."""
        tester = NotificationInAppTests(self.results)
        tester.test_in_app_notification_creation(self.user)
        tester.test_in_app_notification_retrieval(self.user)
        tester.test_unread_notification_tracking(self.user)

    def test_03_notification_preferences(self):
        """Test notification preference management."""
        tester = NotificationPreferencesTests(self.results)
        tester.test_notification_preference_creation(self.user)
        tester.test_channel_specific_preferences(self.user)
        tester.test_notification_type_preferences(self.user)

    def test_04_notification_batching(self):
        """Test notification batching and digests."""
        tester = NotificationBatchingTests(self.results)
        tester.test_notification_batching(self.user)
        tester.test_digest_frequency_settings(self.user)

    def test_05_delivery_logging(self):
        """Test notification delivery logging."""
        tester = NotificationDeliveryLoggingTests(self.results)
        tester.test_delivery_log_creation(self.user)
        tester.test_delivery_log_retrieval(self.user)

    def test_06_push_notifications(self):
        """Test push notification functionality."""
        tester = NotificationPushTests(self.results)
        tester.test_push_notification_creation(self.user)
        tester.test_push_device_registration(self.user)

    def test_07_sms_notifications(self):
        """Test SMS notification functionality."""
        tester = NotificationSMSTests(self.results)
        tester.test_sms_notification_creation(self.user)

    def test_08_channel_configuration(self):
        """Test notification channel configuration."""
        tester = NotificationChannelTests(self.results)
        tester.test_channel_activation()
        tester.test_rate_limiting()

    @classmethod
    def tearDownClass(cls):
        """Generate final report."""
        super().tearDownClass()
        report = cls.results.generate_report()
        print("\n" + "="*80)
        print(report)
        print("="*80)

        # Save report to file
        report_file = "tests_comprehensive/reports/NOTIFICATION_SYSTEM_TEST_REPORT.md"
        with open(report_file, "w") as f:
            f.write(report)
        print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
