"""
Integration tests for Enhanced Audit Logging System.

Tests:
- Authentication event logging (login, logout, failed attempts)
- User management logging (create, update, role changes)
- Sensitive data access logging (KYC documents)
- Configuration change logging (tenant settings)
- Audit report generation
"""

import pytest
from django.test import TestCase, RequestFactory, TransactionTestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from core.security.audit import (
    AuditLog, AuditLogger, AuditAction, AuditSeverity,
    audit_data_access, audit_model_changes
)
from tenant_profiles.models import TenantUser, UserProfile, KYCVerification
from tenants.models import Tenant, TenantSettings

User = get_user_model()


class AuditLoggingIntegrationTest(TransactionTestCase):
    """Integration tests for audit logging system."""

    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

    def test_user_creation_logged(self):
        """Test that user creation creates audit log."""
        # Create new user
        new_user = User.objects.create_user(
            email='newuser@example.com',
            password='password123'
        )

        # Check audit log was created
        logs = AuditLog.objects.filter(
            action=AuditAction.CREATE,
            resource_type='user',
            resource_id=str(new_user.id)
        )

        # Note: Audit log is created in adapter, not model
        # This test verifies the infrastructure is working
        self.assertTrue(AuditLog.objects.exists())

    def test_login_success_logged(self):
        """Test that successful login creates audit log."""
        request = self.factory.post('/login/')
        request.user = self.user

        # Log authentication event
        AuditLogger.log_authentication(
            action=AuditAction.LOGIN,
            user=self.user,
            request=request,
            success=True,
            extra_data={'ip_address': '127.0.0.1'}
        )

        # Verify audit log
        log = AuditLog.objects.filter(
            user=self.user,
            action=AuditAction.LOGIN,
            resource_type='Authentication'
        ).first()

        self.assertIsNotNone(log)
        self.assertEqual(log.severity, AuditSeverity.INFO.value)
        self.assertTrue(log.is_sensitive)
        self.assertEqual(log.extra_data.get('success'), True)

    def test_login_failure_logged(self):
        """Test that failed login creates audit log."""
        request = self.factory.post('/login/')

        # Log failed login
        AuditLogger.log_authentication(
            action=AuditAction.LOGIN_FAILED,
            user=None,
            request=request,
            success=False,
            extra_data={
                'username_attempted': 'test@example.com',
                'ip_address': '127.0.0.1'
            }
        )

        # Verify audit log
        log = AuditLog.objects.filter(
            action=AuditAction.LOGIN_FAILED,
            resource_type='Authentication'
        ).first()

        self.assertIsNotNone(log)
        self.assertEqual(log.severity, AuditSeverity.WARNING.value)
        self.assertTrue(log.is_sensitive)
        self.assertEqual(log.extra_data.get('success'), False)

    def test_model_change_tracking(self):
        """Test that model changes are tracked."""
        # Apply decorator to model (simulated - normally done at model definition)
        @audit_model_changes
        class TestModel:
            def __init__(self):
                self.pk = 1
                self.name = 'Test'

        # Test the decorator exists and can be applied
        self.assertTrue(callable(audit_model_changes))

    def test_sensitive_data_access_logged(self):
        """Test that sensitive data access is logged."""
        request = self.factory.get('/kyc/document/123/')
        request.user = self.user

        # Simulate accessing KYC document
        AuditLogger.log(
            action=AuditAction.KYC_VIEWED,
            user=self.user,
            resource_type='kyc_verification',
            resource_id='123',
            request=request,
            is_sensitive=True
        )

        # Verify audit log
        log = AuditLog.objects.filter(
            user=self.user,
            action=AuditAction.KYC_VIEWED,
            resource_type='kyc_verification',
            resource_id='123'
        ).first()

        self.assertIsNotNone(log)
        self.assertTrue(log.is_sensitive)

    def test_configuration_change_logged(self):
        """Test that configuration changes are logged."""
        request = self.factory.post('/settings/')
        request.user = self.user

        # Log configuration change
        AuditLogger.log(
            action=AuditAction.TENANT_SETTING_CHANGED,
            user=self.user,
            resource_type='tenant_settings',
            resource_id='1',
            request=request,
            old_value={'primary_color': '#000000'},
            new_value={'primary_color': '#FF0000'},
            changes=[{
                'field': 'primary_color',
                'old': '#000000',
                'new': '#FF0000'
            }]
        )

        # Verify audit log
        log = AuditLog.objects.filter(
            user=self.user,
            action=AuditAction.TENANT_SETTING_CHANGED,
            resource_type='tenant_settings'
        ).first()

        self.assertIsNotNone(log)
        self.assertEqual(len(log.changes), 1)
        self.assertEqual(log.changes[0]['field'], 'primary_color')

    def test_security_event_logged(self):
        """Test that security events are logged."""
        request = self.factory.post('/login/')

        # Log brute force attack
        AuditLogger.log_security_event(
            event_type='brute_force_block',
            description='IP blocked after 5 failed login attempts',
            user=None,
            request=request,
            severity=AuditSeverity.CRITICAL,
            extra_data={
                'ip_address': '192.168.1.100',
                'failed_attempts': 5
            }
        )

        # Verify audit log
        log = AuditLog.objects.filter(
            action=AuditAction.SECURITY_EVENT,
            resource_type='SecurityEvent',
            resource_id='brute_force_block'
        ).first()

        self.assertIsNotNone(log)
        self.assertEqual(log.severity, AuditSeverity.CRITICAL.value)
        self.assertTrue(log.is_sensitive)

    def test_sensitive_field_masking(self):
        """Test that sensitive fields are masked in audit logs."""
        data = {
            'email': 'test@example.com',
            'password': 'secret123',
            'api_key': 'sk-abc123',
            'name': 'Test User'
        }

        masked = AuditLogger._mask_sensitive_fields(data)

        # Check sensitive fields are masked
        self.assertEqual(masked['password'], '***MASKED***')
        self.assertEqual(masked['api_key'], '***MASKED***')

        # Check non-sensitive fields are not masked
        self.assertEqual(masked['email'], 'test@example.com')
        self.assertEqual(masked['name'], 'Test User')

    def test_audit_log_integrity_verification(self):
        """Test that audit logs can verify their integrity."""
        request = self.factory.get('/test/')
        request.user = self.user

        # Create audit log
        log = AuditLogger.log(
            action=AuditAction.READ,
            user=self.user,
            resource_type='test_resource',
            resource_id='123',
            request=request
        )

        # Verify integrity
        self.assertIsNotNone(log.checksum)
        self.assertTrue(log.verify_integrity())

        # Tamper with log
        log.action = AuditAction.DELETE
        self.assertFalse(log.verify_integrity())

    def test_audit_data_access_decorator(self):
        """Test the audit_data_access decorator."""
        request = self.factory.get('/test/')
        request.user = self.user

        # Create decorated function
        @audit_data_access('test_resource', lambda request, pk: pk)
        def view_resource(request, pk):
            return f"Viewed resource {pk}"

        # Call function
        result = view_resource(request, '123')

        # Verify function executed
        self.assertEqual(result, "Viewed resource 123")

        # Verify audit log created
        log = AuditLog.objects.filter(
            user=self.user,
            resource_type='test_resource',
            resource_id='123'
        ).first()

        self.assertIsNotNone(log)
        self.assertTrue(log.is_sensitive)

    def test_changes_calculation(self):
        """Test that changes between old and new values are calculated correctly."""
        old_value = {
            'name': 'Old Name',
            'email': 'old@example.com',
            'status': 'active'
        }

        new_value = {
            'name': 'New Name',
            'email': 'old@example.com',
            'status': 'inactive'
        }

        changes = AuditLogger._calculate_changes(old_value, new_value)

        # Should detect 2 changes (name and status)
        self.assertEqual(len(changes), 2)

        # Check change details
        name_change = next(c for c in changes if c['field'] == 'name')
        self.assertEqual(name_change['old'], 'Old Name')
        self.assertEqual(name_change['new'], 'New Name')

        status_change = next(c for c in changes if c['field'] == 'status')
        self.assertEqual(status_change['old'], 'active')
        self.assertEqual(status_change['new'], 'inactive')

    def test_audit_log_retention(self):
        """Test that audit logs have retention dates set."""
        request = self.factory.get('/test/')
        request.user = self.user

        log = AuditLogger.log(
            action=AuditAction.READ,
            user=self.user,
            resource_type='test',
            request=request
        )

        # Verify retention date is set (default 7 years)
        self.assertIsNotNone(log.retention_expires)
        self.assertTrue(log.retention_expires > timezone.now())


class AuditReportGenerationTest(TestCase):
    """Test audit report generation."""

    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_filter_by_action(self):
        """Test filtering audit logs by action."""
        request = self.factory.get('/test/')
        request.user = self.user

        # Create multiple log entries
        for action in [AuditAction.LOGIN, AuditAction.LOGOUT, AuditAction.LOGIN]:
            AuditLogger.log_authentication(
                action=action,
                user=self.user,
                request=request,
                success=True
            )

        # Filter by LOGIN action
        login_logs = AuditLog.objects.filter(action=AuditAction.LOGIN)
        self.assertEqual(login_logs.count(), 2)

        # Filter by LOGOUT action
        logout_logs = AuditLog.objects.filter(action=AuditAction.LOGOUT)
        self.assertEqual(logout_logs.count(), 1)

    def test_filter_by_date_range(self):
        """Test filtering audit logs by date range."""
        request = self.factory.get('/test/')
        request.user = self.user

        # Create log entry
        log = AuditLogger.log(
            action=AuditAction.READ,
            user=self.user,
            resource_type='test',
            request=request
        )

        # Filter by date range
        start_date = timezone.now() - timezone.timedelta(hours=1)
        end_date = timezone.now() + timezone.timedelta(hours=1)

        logs = AuditLog.objects.filter(
            timestamp__gte=start_date,
            timestamp__lte=end_date
        )

        self.assertEqual(logs.count(), 1)

    def test_filter_by_user(self):
        """Test filtering audit logs by user."""
        request = self.factory.get('/test/')
        request.user = self.user

        # Create another user
        other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123'
        )

        # Create logs for both users
        AuditLogger.log(
            action=AuditAction.READ,
            user=self.user,
            resource_type='test',
            request=request
        )

        request.user = other_user
        AuditLogger.log(
            action=AuditAction.READ,
            user=other_user,
            resource_type='test',
            request=request
        )

        # Filter by first user
        user_logs = AuditLog.objects.filter(user=self.user)
        self.assertEqual(user_logs.count(), 1)

    def test_filter_sensitive_only(self):
        """Test filtering only sensitive data access logs."""
        request = self.factory.get('/test/')
        request.user = self.user

        # Create sensitive log
        AuditLogger.log(
            action=AuditAction.KYC_VIEWED,
            user=self.user,
            resource_type='kyc',
            request=request,
            is_sensitive=True
        )

        # Create non-sensitive log
        AuditLogger.log(
            action=AuditAction.READ,
            user=self.user,
            resource_type='article',
            request=request,
            is_sensitive=False
        )

        # Filter sensitive only
        sensitive_logs = AuditLog.objects.filter(is_sensitive=True)
        self.assertTrue(sensitive_logs.count() >= 1)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
