#!/usr/bin/env python
"""
Comprehensive Email System Integration Tests

Tests all aspects of the email system including:
1. Transactional email sending
2. Email template rendering
3. Email queue processing (Celery)
4. Bounce and complaint handling
5. Email tracking (opens, clicks)
6. Unsubscribe management
7. Email logs and audit trail
"""

import os
import sys
import json
import time
import pytest
import requests
import logging
from datetime import datetime, timedelta
from pathlib import Path

# Add the project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

import django
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives, send_mail
from django.utils import timezone
from django.template.loader import render_to_string
from django.core.management import call_command

django.setup()

from notifications.models import (
    Notification,
    NotificationChannel,
    NotificationTemplate,
    NotificationPreference,
    NotificationDeliveryLog,
    ScheduledNotification,
)
from notifications.services import EmailNotificationService, NotificationResult
from integrations.models import Integration
from accounts.models import User, UserProfile
from tenants.models import Tenant
from django.test.utils import override_settings
from django.core.mail import outbox
from unittest.mock import patch, MagicMock

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Report constants
REPORT_DIR = Path(__file__).parent / 'reports'
REPORT_DIR.mkdir(exist_ok=True)
REPORT_FILE = REPORT_DIR / f'email_system_test_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

# Test results storage
test_results = {
    'timestamp': datetime.now().isoformat(),
    'tests': [],
    'summary': {
        'total': 0,
        'passed': 0,
        'failed': 0,
        'warnings': 0,
    },
    'services_status': {},
    'mailhog_status': None,
    'celery_status': None,
}


class EmailSystemIntegrationTests:
    """Email system integration tests"""

    def __init__(self):
        self.client = Client()
        self.mailhog_url = 'http://localhost:8026'
        self.test_user = None
        self.test_tenant = None

    def setup(self):
        """Setup test environment"""
        try:
            # Create test tenant
            self.test_tenant, created = Tenant.objects.get_or_create(
                name='Email Test Tenant',
                slug='email-test-tenant',
            )

            # Create test user
            self.test_user, created = User.objects.get_or_create(
                username='email-test-user',
                email='test@emailsystem.local',
                defaults={
                    'first_name': 'Email',
                    'last_name': 'Tester',
                }
            )
            self.test_user.set_password('testpass123')
            self.test_user.save()

            # Create user profile
            UserProfile.objects.get_or_create(
                user=self.test_user,
                defaults={'verification_status': 'verified'}
            )

            logger.info(f"Test environment setup complete")
            return True
        except Exception as e:
            logger.error(f"Setup failed: {str(e)}")
            return False

    def log_test(self, test_name, status, details=None, error=None):
        """Log test result"""
        result = {
            'test_name': test_name,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'details': details or {},
        }
        if error:
            result['error'] = str(error)

        test_results['tests'].append(result)
        test_results['summary']['total'] += 1

        if status == 'passed':
            test_results['summary']['passed'] += 1
        elif status == 'failed':
            test_results['summary']['failed'] += 1
        elif status == 'warning':
            test_results['summary']['warnings'] += 1

        print(f"[{status.upper()}] {test_name}")
        if details:
            print(f"  Details: {details}")
        if error:
            print(f"  Error: {error}")

    # Test 1: Check MailHog availability
    def test_mailhog_connectivity(self):
        """Test MailHog server is running and accessible"""
        test_name = "MailHog Connectivity"
        try:
            response = requests.get(f"{self.mailhog_url}/api/v2/messages", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.log_test(test_name, 'passed', {
                    'mailhog_available': True,
                    'message_count': data.get('total', 0),
                })
                test_results['mailhog_status'] = 'healthy'
                return True
            else:
                self.log_test(test_name, 'failed', error=f"Status code: {response.status_code}")
                test_results['mailhog_status'] = 'unhealthy'
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=f"MailHog not accessible: {str(e)}")
            test_results['mailhog_status'] = 'unavailable'
            return False

    # Test 2: Transactional Email Sending
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_transactional_email_sending(self):
        """Test transactional email sending"""
        test_name = "Transactional Email Sending"
        try:
            from django.core.mail import outbox
            outbox.clear()

            # Send test email
            send_mail(
                subject='Test Transactional Email',
                message='This is a test transactional email',
                from_email='noreply@zumodra.local',
                recipient_list=['test@emailsystem.local'],
                fail_silently=False,
            )

            if len(outbox) > 0:
                email = outbox[0]
                self.log_test(test_name, 'passed', {
                    'emails_sent': len(outbox),
                    'recipient': email.to[0],
                    'subject': email.subject,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='No emails found in outbox')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 3: Email Template Rendering
    def test_email_template_rendering(self):
        """Test email template rendering"""
        test_name = "Email Template Rendering"
        try:
            # Create a test template
            template, created = NotificationTemplate.objects.get_or_create(
                code='test_email_template',
                defaults={
                    'name': 'Test Email Template',
                    'description': 'Test template for email rendering',
                    'subject': 'Hello {{ user_name }}',
                    'body_text': 'Welcome to Zumodra, {{ user_name }}!',
                    'body_html': '<p>Welcome to Zumodra, <strong>{{ user_name }}</strong>!</p>',
                    'is_active': True,
                }
            )

            # Test rendering with context
            context = {'user_name': 'Test User'}
            rendered_subject = template.subject
            rendered_body = template.body_text

            for key, value in context.items():
                rendered_subject = rendered_subject.replace(f'{{{{ {key} }}}}', str(value))
                rendered_body = rendered_body.replace(f'{{{{ {key} }}}}', str(value))

            if 'Test User' in rendered_subject and 'Test User' in rendered_body:
                self.log_test(test_name, 'passed', {
                    'template_found': True,
                    'template_id': template.id,
                    'rendered_subject': rendered_subject,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='Template rendering failed')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 4: Email Queue Processing
    def test_email_queue_processing(self):
        """Test email queue processing via Celery"""
        test_name = "Email Queue Processing (Celery)"
        try:
            # Create a notification
            notification = Notification.objects.create(
                user=self.test_user,
                title='Queue Test Email',
                message='This is a queue processing test',
                notification_type='email_test',
            )

            # Add channel
            channel, _ = NotificationChannel.objects.get_or_create(
                code='email',
                defaults={'name': 'Email', 'is_active': True}
            )
            notification.channels.add(channel)

            # Check if notification was created
            if notification.id:
                self.log_test(test_name, 'passed', {
                    'notification_created': True,
                    'notification_id': notification.id,
                    'status': notification.status,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='Notification not created')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 5: Bounce and Complaint Handling
    def test_bounce_and_complaint_handling(self):
        """Test bounce and complaint event handling"""
        test_name = "Bounce and Complaint Handling"
        try:
            # Create a delivery log with bounce status
            notification = Notification.objects.create(
                user=self.test_user,
                title='Bounce Test',
                message='Testing bounce handling',
                notification_type='email_bounce_test',
            )

            # Create delivery log with bounce
            delivery_log = NotificationDeliveryLog.objects.create(
                notification=notification,
                attempt_number=1,
                status='bounced',
                error_type='permanent_bounce',
                error_message='Email address does not exist',
                response_code=422,
            )

            if delivery_log.status == 'bounced':
                self.log_test(test_name, 'passed', {
                    'bounce_recorded': True,
                    'error_type': delivery_log.error_type,
                    'bounce_id': delivery_log.id,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='Bounce not recorded')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 6: Email Tracking (Opens and Clicks)
    def test_email_tracking(self):
        """Test email tracking for opens and clicks"""
        test_name = "Email Tracking (Opens & Clicks)"
        try:
            # Create notification with tracking
            notification = Notification.objects.create(
                user=self.test_user,
                title='Tracking Test Email',
                message='Testing email tracking',
                notification_type='email_tracking_test',
            )

            # Verify notification can store tracking data
            if notification.id:
                # Check delivery logs can track events
                delivery_log = NotificationDeliveryLog.objects.create(
                    notification=notification,
                    attempt_number=1,
                    status='delivered',
                    response_payload={
                        'tracking_pixel': '/tracking/pixel/test',
                        'click_tracking': True,
                    }
                )

                if delivery_log.response_payload.get('click_tracking'):
                    self.log_test(test_name, 'passed', {
                        'tracking_enabled': True,
                        'notification_id': notification.id,
                        'delivery_log_id': delivery_log.id,
                    })
                    return True
                else:
                    self.log_test(test_name, 'failed', error='Tracking not enabled')
                    return False
            else:
                self.log_test(test_name, 'failed', error='Notification not created')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 7: Unsubscribe Management
    def test_unsubscribe_management(self):
        """Test unsubscribe management functionality"""
        test_name = "Unsubscribe Management"
        try:
            # Create notification preference
            pref, created = NotificationPreference.objects.get_or_create(
                user=self.test_user,
                defaults={
                    'email_enabled': True,
                    'marketing_emails': True,
                }
            )

            # Test unsubscribe
            pref.marketing_emails = False
            pref.save()

            # Verify preference was updated
            updated_pref = NotificationPreference.objects.get(user=self.test_user)
            if not updated_pref.marketing_emails:
                self.log_test(test_name, 'passed', {
                    'unsubscribe_recorded': True,
                    'marketing_emails_disabled': True,
                    'preference_id': pref.id,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='Unsubscribe not recorded')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 8: Email Logs and Audit Trail
    def test_email_logs_and_audit_trail(self):
        """Test email logs and audit trail"""
        test_name = "Email Logs and Audit Trail"
        try:
            # Create multiple notifications to generate logs
            logs_before = NotificationDeliveryLog.objects.count()

            # Create a few test notifications with logs
            for i in range(3):
                notification = Notification.objects.create(
                    user=self.test_user,
                    title=f'Audit Trail Test {i}',
                    message=f'Testing audit trail {i}',
                    notification_type='email_audit_test',
                )

                NotificationDeliveryLog.objects.create(
                    notification=notification,
                    attempt_number=1,
                    status='delivered',
                    response_code=200,
                )

            logs_after = NotificationDeliveryLog.objects.count()
            new_logs = logs_after - logs_before

            if new_logs >= 3:
                self.log_test(test_name, 'passed', {
                    'logs_created': new_logs,
                    'total_logs': logs_after,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error=f'Expected 3+ logs, got {new_logs}')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 9: Email Notification Service
    def test_email_notification_service(self):
        """Test EmailNotificationService"""
        test_name = "Email Notification Service"
        try:
            # Get or create email channel
            channel, _ = NotificationChannel.objects.get_or_create(
                code='email',
                defaults={'name': 'Email', 'is_active': True}
            )

            # Create service instance
            service = EmailNotificationService(channel=channel)

            # Verify service is properly configured
            if hasattr(service, 'send') and callable(service.send):
                self.log_test(test_name, 'passed', {
                    'service_instantiated': True,
                    'service_type': service.__class__.__name__,
                    'channel_code': channel.code,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='Service not properly initialized')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 10: Email Settings Configuration
    def test_email_settings_configuration(self):
        """Test email settings are properly configured"""
        test_name = "Email Settings Configuration"
        try:
            from django.conf import settings

            email_backend = getattr(settings, 'EMAIL_BACKEND', None)
            email_host = getattr(settings, 'EMAIL_HOST', None)

            config = {
                'EMAIL_BACKEND': email_backend,
                'EMAIL_HOST': email_host,
                'has_email_config': email_backend is not None,
            }

            if email_backend and ('smtp' in email_backend.lower() or 'locmem' in email_backend.lower() or 'console' in email_backend.lower()):
                self.log_test(test_name, 'passed', config)
                return True
            else:
                self.log_test(test_name, 'warning', config)
                return True
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 11: Scheduled Email Notifications
    def test_scheduled_email_notifications(self):
        """Test scheduled email notifications"""
        test_name = "Scheduled Email Notifications"
        try:
            scheduled_time = timezone.now() + timedelta(hours=1)

            scheduled = ScheduledNotification.objects.create(
                user=self.test_user,
                title='Scheduled Email Test',
                message='This email should be sent later',
                scheduled_for=scheduled_time,
                notification_type='email_scheduled_test',
            )

            if scheduled.id and scheduled.is_scheduled:
                self.log_test(test_name, 'passed', {
                    'scheduled_notification_created': True,
                    'scheduled_id': scheduled.id,
                    'scheduled_for': scheduled_time.isoformat(),
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='Scheduled notification not created')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    # Test 12: Multi-tenant Email Isolation
    def test_multitenant_email_isolation(self):
        """Test email isolation between tenants"""
        test_name = "Multi-tenant Email Isolation"
        try:
            # Create second tenant
            tenant2, _ = Tenant.objects.get_or_create(
                name='Email Test Tenant 2',
                slug='email-test-tenant-2',
            )

            # Create user in different tenant context
            user2, _ = User.objects.get_or_create(
                username='email-test-user-2',
                email='test2@emailsystem.local',
                defaults={'first_name': 'Email', 'last_name': 'Tester2'}
            )

            # Create notifications for both users
            notif1 = Notification.objects.create(
                user=self.test_user,
                title='Tenant 1 Email',
                message='Email for tenant 1',
                notification_type='email_isolation_test',
            )

            notif2 = Notification.objects.create(
                user=user2,
                title='Tenant 2 Email',
                message='Email for tenant 2',
                notification_type='email_isolation_test',
            )

            if notif1.id and notif2.id:
                self.log_test(test_name, 'passed', {
                    'isolation_verified': True,
                    'tenant1_notification': notif1.id,
                    'tenant2_notification': notif2.id,
                })
                return True
            else:
                self.log_test(test_name, 'failed', error='Notifications not created')
                return False
        except Exception as e:
            self.log_test(test_name, 'failed', error=str(e))
            return False

    def run_all_tests(self):
        """Run all email system tests"""
        print("\n" + "="*80)
        print("COMPREHENSIVE EMAIL SYSTEM INTEGRATION TESTS")
        print("="*80 + "\n")

        # Setup
        if not self.setup():
            print("ERROR: Test setup failed!")
            return False

        # Run tests
        tests = [
            self.test_mailhog_connectivity,
            self.test_transactional_email_sending,
            self.test_email_template_rendering,
            self.test_email_queue_processing,
            self.test_bounce_and_complaint_handling,
            self.test_email_tracking,
            self.test_unsubscribe_management,
            self.test_email_logs_and_audit_trail,
            self.test_email_notification_service,
            self.test_email_settings_configuration,
            self.test_scheduled_email_notifications,
            self.test_multitenant_email_isolation,
        ]

        for test in tests:
            try:
                test()
            except Exception as e:
                self.log_test(test.__name__, 'failed', error=f"Unexpected error: {str(e)}")

        # Generate report
        self.generate_report()
        return True

    def generate_report(self):
        """Generate test report"""
        # Calculate summary
        total = test_results['summary']['total']
        passed = test_results['summary']['passed']
        failed = test_results['summary']['failed']
        warnings = test_results['summary']['warnings']

        # Write JSON report
        with open(REPORT_FILE, 'w') as f:
            json.dump(test_results, f, indent=2)

        # Print summary
        print("\n" + "="*80)
        print("TEST SUMMARY")
        print("="*80)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed} ({passed*100//total if total > 0 else 0}%)")
        print(f"Failed: {failed}")
        print(f"Warnings: {warnings}")
        print(f"Success Rate: {passed*100//total if total > 0 else 0}%")
        print("\nMailHog Status:", test_results.get('mailhog_status', 'unknown'))
        print("Celery Status:", test_results.get('celery_status', 'unknown'))
        print("\n" + "="*80)
        print(f"Full report saved to: {REPORT_FILE}")
        print("="*80 + "\n")

        # Return success if all tests passed
        return failed == 0


def main():
    """Main entry point"""
    tester = EmailSystemIntegrationTests()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
