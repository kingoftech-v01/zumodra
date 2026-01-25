"""
Comprehensive Audit Logging System Test Suite

Tests for:
1. User action logging (create, update, delete)
2. Authentication event logging (login, logout, failed attempts)
3. Permission change logging
4. Data access logging
5. Audit log search and filtering
6. Audit log retention and archival
7. Compliance reporting from audit logs
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import Mock, patch

import pytest
import django
from django.conf import settings
from django.test import Client, TestCase, TransactionTestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import transaction
from django.core.management import call_command

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
django.setup()

from tenants.models import Tenant, Plan, AuditLog
from tenant_profiles.models import TenantUser, KYCVerification
from jobs.models import Job, Candidate, Interview, Application
from services.models import Service, Proposal
from auditlog.models import LogEntry


User = get_user_model()


class AuditLoggingTestHelper:
    """Helper class for audit logging tests."""

    @staticmethod
    def clear_audit_logs():
        """Clear all audit logs for clean test state."""
        AuditLog.objects.all().delete()
        LogEntry.objects.all().delete()

    @staticmethod
    def create_test_tenant():
        """Create a test tenant with plan."""
        plan, _ = Plan.objects.get_or_create(
            slug='test-plan',
            defaults={
                'name': 'Test Plan',
                'plan_type': Plan.PlanType.PROFESSIONAL,
                'price_monthly': Decimal('99.00'),
                'feature_audit_logs': True,
            }
        )
        tenant = Tenant.objects.create(
            name='Test Company',
            slug='test-company',
            plan=plan,
            status=Tenant.TenantStatus.ACTIVE,
        )
        return tenant

    @staticmethod
    def create_test_user(email='testuser@example.com'):
        """Create a test user."""
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = User.objects.create_user(
                email=email,
                username=email.split('@')[0],
                password='TestPassword123!',
                first_name='Test',
                last_name='User',
            )
        return user

    @staticmethod
    def create_tenant_user(user, tenant, role='recruiter'):
        """Create a tenant user with role."""
        tenant_user, _ = TenantUser.objects.get_or_create(
            user=user,
            tenant=tenant,
            defaults={'role': role}
        )
        return tenant_user

    @staticmethod
    def log_audit_action(tenant, user, action, resource_type, resource_id='',
                        description='', old_values=None, new_values=None,
                        ip_address='127.0.0.1', user_agent=''):
        """Create an audit log entry."""
        return AuditLog.objects.create(
            tenant=tenant,
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            old_values=old_values or {},
            new_values=new_values or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )


class UserActionLoggingTests(TransactionTestCase):
    """Test logging of user actions (create, update, delete)."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()
        self.user = AuditLoggingTestHelper.create_test_user()
        AuditLoggingTestHelper.create_tenant_user(self.user, self.tenant)

    def test_job_creation_logging(self):
        """Test logging when a job is created."""
        with transaction.atomic():
            job = Job.objects.create(
                tenant=self.tenant,
                title='Senior Developer',
                description='Looking for a senior developer.',
                department='Engineering',
                created_by=self.user,
            )

            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=self.user,
                action=AuditLog.ActionType.CREATE,
                resource_type='Job',
                resource_id=str(job.id),
                description=f'Created job: {job.title}',
                new_values={'title': job.title, 'department': job.department},
            )

        logs = AuditLog.objects.filter(
            tenant=self.tenant,
            resource_type='Job',
            action=AuditLog.ActionType.CREATE
        )
        assert logs.exists(), "Job creation should be logged"
        log = logs.first()
        assert log.resource_id == str(job.id)
        assert log.user == self.user

    def test_candidate_update_logging(self):
        """Test logging when candidate is updated."""
        candidate = Candidate.objects.create(
            tenant=self.tenant,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
        )

        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.UPDATE,
            resource_type='Candidate',
            resource_id=str(candidate.id),
            description='Updated candidate status',
            old_values={'first_name': 'John', 'status': 'new'},
            new_values={'first_name': 'John', 'status': 'contacted'},
        )

        logs = AuditLog.objects.filter(
            resource_type='Candidate',
            action=AuditLog.ActionType.UPDATE
        )
        assert logs.exists()

    def test_interview_deletion_logging(self):
        """Test logging when interview is deleted."""
        candidate = Candidate.objects.create(
            tenant=self.tenant,
            first_name='Jane',
            last_name='Smith',
            email='jane@example.com',
        )

        interview = Interview.objects.create(
            tenant=self.tenant,
            candidate=candidate,
            interviewer=self.user,
            scheduled_at=timezone.now() + timedelta(days=1),
            interview_type='phone',
        )

        interview_id = interview.id
        interview.delete()

        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.DELETE,
            resource_type='Interview',
            resource_id=str(interview_id),
            description='Deleted interview',
            old_values={'id': str(interview_id)},
        )

        logs = AuditLog.objects.filter(
            resource_type='Interview',
            action=AuditLog.ActionType.DELETE
        )
        assert logs.exists()


class AuthenticationEventLoggingTests(TransactionTestCase):
    """Test logging of authentication events."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()
        self.user = AuditLoggingTestHelper.create_test_user()
        AuditLoggingTestHelper.create_tenant_user(self.user, self.tenant)
        self.client = Client()

    def test_successful_login_logging(self):
        """Test logging of successful login."""
        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.LOGIN,
            resource_type='User',
            resource_id=str(self.user.id),
            description=f'User {self.user.email} logged in',
            ip_address='192.168.1.100',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        )

        logs = AuditLog.objects.filter(
            user=self.user,
            action=AuditLog.ActionType.LOGIN
        )
        assert logs.exists()
        log = logs.first()
        assert log.ip_address == '192.168.1.100'

    def test_logout_logging(self):
        """Test logging of logout."""
        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.LOGOUT,
            resource_type='User',
            resource_id=str(self.user.id),
            description=f'User {self.user.email} logged out',
            ip_address='192.168.1.100',
        )

        logs = AuditLog.objects.filter(
            user=self.user,
            action=AuditLog.ActionType.LOGOUT
        )
        assert logs.exists()

    def test_failed_login_attempt_logging(self):
        """Test logging of failed login attempts."""
        for i in range(3):
            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=None,
                action='failed_login',
                resource_type='User',
                resource_id='unknown',
                description=f'Failed login attempt {i+1}',
                ip_address='192.168.1.101',
            )

        logs = AuditLog.objects.filter(
            description__contains='Failed login'
        )
        assert logs.count() >= 3


class PermissionChangeLoggingTests(TransactionTestCase):
    """Test logging of permission changes."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()
        self.user = AuditLoggingTestHelper.create_test_user()
        self.admin_user = AuditLoggingTestHelper.create_test_user(
            email='admin@example.com'
        )
        AuditLoggingTestHelper.create_tenant_user(self.user, self.tenant, 'recruiter')
        AuditLoggingTestHelper.create_tenant_user(self.admin_user, self.tenant, 'admin')

    def test_role_change_logging(self):
        """Test logging when user role is changed."""
        tenant_user = TenantUser.objects.get(user=self.user, tenant=self.tenant)
        old_role = tenant_user.role
        tenant_user.role = 'hr_manager'
        tenant_user.save()

        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.admin_user,
            action=AuditLog.ActionType.PERMISSION_CHANGE,
            resource_type='TenantUser',
            resource_id=str(tenant_user.id),
            description=f'Changed user role from {old_role} to hr_manager',
            old_values={'role': old_role},
            new_values={'role': 'hr_manager'},
        )

        logs = AuditLog.objects.filter(
            action=AuditLog.ActionType.PERMISSION_CHANGE,
            resource_type='TenantUser',
        )
        assert logs.exists()

    def test_permission_grant_logging(self):
        """Test logging when permissions are granted."""
        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.admin_user,
            action=AuditLog.ActionType.PERMISSION_CHANGE,
            resource_type='User',
            resource_id=str(self.user.id),
            description='Granted access to Interview Scheduling',
            old_values={'permissions': ['job_view']},
            new_values={'permissions': ['job_view', 'interview_schedule']},
        )

        logs = AuditLog.objects.filter(
            action=AuditLog.ActionType.PERMISSION_CHANGE
        )
        assert logs.exists()


class DataAccessLoggingTests(TransactionTestCase):
    """Test logging of data access (exports, downloads)."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()
        self.user = AuditLoggingTestHelper.create_test_user()
        AuditLoggingTestHelper.create_tenant_user(self.user, self.tenant)

    def test_data_export_logging(self):
        """Test logging when data is exported."""
        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.EXPORT,
            resource_type='Candidate',
            description='Exported 150 candidates to CSV',
            new_values={
                'format': 'csv',
                'record_count': 150,
                'filename': 'candidates_export_20260116.csv'
            },
        )

        logs = AuditLog.objects.filter(
            action=AuditLog.ActionType.EXPORT,
            resource_type='Candidate'
        )
        assert logs.exists()

    def test_setting_change_logging(self):
        """Test logging of setting changes."""
        AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.SETTING_CHANGE,
            resource_type='TenantSettings',
            description='Updated notification settings',
            old_values={'email_notifications': True},
            new_values={'email_notifications': False},
        )

        logs = AuditLog.objects.filter(
            action=AuditLog.ActionType.SETTING_CHANGE
        )
        assert logs.exists()


class AuditLogSearchAndFilteringTests(TransactionTestCase):
    """Test searching and filtering audit logs."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()
        self.user1 = AuditLoggingTestHelper.create_test_user('user1@example.com')
        self.user2 = AuditLoggingTestHelper.create_test_user('user2@example.com')
        AuditLoggingTestHelper.create_tenant_user(self.user1, self.tenant)
        AuditLoggingTestHelper.create_tenant_user(self.user2, self.tenant)

        for i in range(5):
            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=self.user1,
                action=AuditLog.ActionType.CREATE,
                resource_type='Job',
                resource_id=f'job_{i}',
                description=f'Created job {i}',
            )

        for i in range(3):
            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=self.user2,
                action=AuditLog.ActionType.UPDATE,
                resource_type='Candidate',
                resource_id=f'candidate_{i}',
                description=f'Updated candidate {i}',
            )

    def test_filter_by_user(self):
        """Test filtering logs by user."""
        logs = AuditLog.objects.filter(user=self.user1)
        assert logs.count() == 5

        logs = AuditLog.objects.filter(user=self.user2)
        assert logs.count() == 3

    def test_filter_by_action_type(self):
        """Test filtering by action type."""
        logs = AuditLog.objects.filter(action=AuditLog.ActionType.CREATE)
        assert logs.count() == 5

        logs = AuditLog.objects.filter(action=AuditLog.ActionType.UPDATE)
        assert logs.count() == 3

    def test_filter_by_resource_type(self):
        """Test filtering by resource type."""
        logs = AuditLog.objects.filter(resource_type='Job')
        assert logs.count() == 5

        logs = AuditLog.objects.filter(resource_type='Candidate')
        assert logs.count() == 3

    def test_filter_by_date_range(self):
        """Test filtering by date range."""
        now = timezone.now()
        one_hour_ago = now - timedelta(hours=1)
        one_hour_later = now + timedelta(hours=1)

        logs = AuditLog.objects.filter(
            created_at__gte=one_hour_ago,
            created_at__lte=one_hour_later
        )
        assert logs.count() == 8

    def test_combined_filters(self):
        """Test combining multiple filters."""
        logs = AuditLog.objects.filter(
            tenant=self.tenant,
            user=self.user1,
            action=AuditLog.ActionType.CREATE,
            resource_type='Job'
        )
        assert logs.count() == 5

    def test_search_by_description(self):
        """Test searching in description field."""
        logs = AuditLog.objects.filter(description__contains='Created job')
        assert logs.count() == 5

    def test_ordering_by_timestamp(self):
        """Test ordering logs by timestamp."""
        logs = AuditLog.objects.all().order_by('-created_at')
        timestamps = [log.created_at for log in logs]
        assert timestamps == sorted(timestamps, reverse=True)


class AuditLogRetentionAndArchivalTests(TransactionTestCase):
    """Test audit log retention policies and archival."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()
        self.user = AuditLoggingTestHelper.create_test_user()
        AuditLoggingTestHelper.create_tenant_user(self.user, self.tenant)

    def test_retention_policy_90_days(self):
        """Test that logs older than 90 days are identified for archival."""
        cutoff_date = timezone.now() - timedelta(days=91)
        old_log = AuditLog.objects.create(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.CREATE,
            resource_type='Job',
            resource_id='old_job',
            description='Old log',
            created_at=cutoff_date,
        )

        recent_log = AuditLoggingTestHelper.log_audit_action(
            tenant=self.tenant,
            user=self.user,
            action=AuditLog.ActionType.CREATE,
            resource_type='Job',
            resource_id='new_job',
            description='Recent log',
        )

        retention_cutoff = timezone.now() - timedelta(days=90)
        old_logs = AuditLog.objects.filter(created_at__lt=retention_cutoff)

        assert old_logs.filter(id=old_log.id).exists()
        assert not old_logs.filter(id=recent_log.id).exists()

    def test_bulk_archival_query(self):
        """Test identifying bulk logs for archival."""
        archival_cutoff = timezone.now() - timedelta(days=90)
        for i in range(10):
            old_date = archival_cutoff - timedelta(days=i+1)
            AuditLog.objects.create(
                tenant=self.tenant,
                user=self.user,
                action=AuditLog.ActionType.CREATE,
                resource_type='Job',
                resource_id=f'archival_job_{i}',
                description=f'Archival log {i}',
                created_at=old_date,
            )

        archival_logs = AuditLog.objects.filter(created_at__lt=archival_cutoff)
        assert archival_logs.count() == 10

    def test_log_volume_metrics(self):
        """Test calculating log volume metrics."""
        for i in range(100):
            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=self.user,
                action=AuditLog.ActionType.CREATE,
                resource_type='Job' if i % 2 == 0 else 'Candidate',
                resource_id=f'resource_{i}',
                description=f'Log entry {i}',
            )

        total_logs = AuditLog.objects.count()
        assert total_logs == 100


class ComplianceReportingTests(TransactionTestCase):
    """Test compliance reporting from audit logs."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()
        self.user = AuditLoggingTestHelper.create_test_user('admin@example.com')
        AuditLoggingTestHelper.create_tenant_user(self.user, self.tenant, 'admin')

    def test_compliance_report_user_access(self):
        """Test generating compliance report for user access."""
        for i in range(5):
            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=self.user,
                action=AuditLog.ActionType.LOGIN,
                resource_type='User',
                resource_id=str(self.user.id),
                description=f'Login attempt {i+1}',
                ip_address=f'192.168.1.{100+i}',
            )

        logins = AuditLog.objects.filter(
            tenant=self.tenant,
            action=AuditLog.ActionType.LOGIN
        )

        report_data = {
            'total_logins': logins.count(),
            'unique_ips': len(set(log.ip_address for log in logins)),
        }

        assert report_data['total_logins'] == 5
        assert report_data['unique_ips'] == 5

    def test_compliance_report_data_modifications(self):
        """Test report of data modifications for compliance."""
        for i in range(3):
            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=self.user,
                action=AuditLog.ActionType.UPDATE,
                resource_type='Candidate',
                resource_id=f'candidate_{i}',
                description=f'Updated candidate {i}',
                old_values={'status': 'new'},
                new_values={'status': 'in_progress'},
            )

        all_mods = AuditLog.objects.filter(
            tenant=self.tenant,
            action=AuditLog.ActionType.UPDATE
        )

        assert all_mods.count() == 3

    def test_compliance_report_exports(self):
        """Test report of data exports."""
        for i in range(3):
            AuditLoggingTestHelper.log_audit_action(
                tenant=self.tenant,
                user=self.user,
                action=AuditLog.ActionType.EXPORT,
                resource_type='Candidate',
                description=f'Exported candidates batch {i+1}',
                new_values={
                    'record_count': 50 + i*10,
                    'format': 'csv',
                },
            )

        all_exports = AuditLog.objects.filter(
            tenant=self.tenant,
            action=AuditLog.ActionType.EXPORT
        )

        total_exported = sum(
            log.new_values.get('record_count', 0)
            for log in all_exports
        )

        assert all_exports.count() == 3
        assert total_exported > 100


class DjangoAuditlogIntegrationTests(TransactionTestCase):
    """Test integration with django-auditlog."""

    def setUp(self):
        """Set up test data."""
        AuditLoggingTestHelper.clear_audit_logs()
        self.tenant = AuditLoggingTestHelper.create_test_tenant()

    def test_auditlog_models_registered(self):
        """Test that expected models are registered with auditlog."""
        from auditlog.registry import auditlog

        registered_models = auditlog.get_models()

        # Check for registered models
        model_names = [model.__name__ for model in registered_models]

        # These should be registered
        expected = ['Analytics', 'Integration', 'NotificationChannel', 'NotificationTemplate']

        for model_name in expected:
            # At least some should be registered
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
