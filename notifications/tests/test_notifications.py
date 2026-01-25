"""
Comprehensive tests for notifications app - Django Multi-Tenant SaaS
Tests notification creation, delivery, templates, preferences, and tenant isolation.
"""

import pytest
from datetime import datetime, timedelta
from decimal import Decimal
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError

from notifications.models import (
    NotificationChannel,
    NotificationTemplate,
    NotificationPreference,
    Notification,
    ScheduledNotification,
    NotificationDeliveryLog,
)
from core_identity.models import CustomUser


# ============================================================================
# NOTIFICATION CHANNEL TESTS
# ============================================================================

@pytest.mark.django_db
class TestNotificationChannel:
    """Test notification channel functionality."""

    def test_create_notification_channel(self):
        """Test creating a notification channel."""
        channel = NotificationChannel.objects.create(
            name='Email Channel',
            channel_type='email',
            is_active=True,
            description='Primary email notification channel',
            config={'smtp_host': 'smtp.example.com'},
            rate_limit_per_hour=100
        )

        assert channel.id is not None
        assert channel.name == 'Email Channel'
        assert channel.channel_type == 'email'
        assert channel.is_active is True
        assert channel.rate_limit_per_hour == 100
        assert 'smtp_host' in channel.config

    def test_create_all_channel_types(self):
        """Test creating all supported channel types."""
        channel_types = ['email', 'sms', 'push', 'in_app', 'slack', 'webhook']

        for channel_type in channel_types:
            channel = NotificationChannel.objects.create(
                name=f'{channel_type.title()} Channel',
                channel_type=channel_type,
                is_active=True
            )
            assert channel.channel_type == channel_type

    def test_notification_channel_str_representation(self):
        """Test string representation of notification channel."""
        channel = NotificationChannel.objects.create(
            name='Test Channel',
            channel_type='email'
        )
        assert str(channel) == 'Test Channel (email)'

    def test_unique_channel_name(self):
        """Test that channel names must be unique."""
        NotificationChannel.objects.create(
            name='Duplicate Channel',
            channel_type='email'
        )

        with pytest.raises(Exception):  # IntegrityError
            NotificationChannel.objects.create(
                name='Duplicate Channel',
                channel_type='sms'
            )


# ============================================================================
# NOTIFICATION TEMPLATE TESTS
# ============================================================================

@pytest.mark.django_db
class TestNotificationTemplate:
    """Test notification template functionality."""

    @pytest.fixture
    def email_channel(self):
        """Create an email channel for testing."""
        return NotificationChannel.objects.create(
            name='Email Channel',
            channel_type='email',
            is_active=True
        )

    def test_create_notification_template(self, email_channel, user_factory):
        """Test creating a notification template."""
        creator = user_factory()

        template = NotificationTemplate.objects.create(
            name='Application Received Template',
            template_type='application_received',
            channel=email_channel,
            subject='New Application for {{ job_title }}',
            body='Hi {{ recruiter_name }}, you have a new application from {{ candidate_name }}.',
            html_body='<h1>New Application</h1><p>From: {{ candidate_name }}</p>',
            language='en',
            is_active=True,
            created_by=creator,
            description='Template for notifying recruiters of new applications'
        )

        assert template.id is not None
        assert template.name == 'Application Received Template'
        assert template.template_type == 'application_received'
        assert template.channel == email_channel
        assert template.created_by == creator
        assert '{{ job_title }}' in template.subject
        assert '{{ candidate_name }}' in template.body

    def test_render_template_subject(self, email_channel):
        """Test rendering template subject with context."""
        template = NotificationTemplate.objects.create(
            name='Test Template',
            template_type='custom',
            channel=email_channel,
            subject='Welcome {{ user_name }}!',
            body='Test body'
        )

        rendered = template.render_subject({'user_name': 'John Doe'})
        assert rendered == 'Welcome John Doe!'

    def test_render_template_body(self, email_channel):
        """Test rendering template body with context."""
        template = NotificationTemplate.objects.create(
            name='Test Template',
            template_type='custom',
            channel=email_channel,
            subject='Test',
            body='Hello {{ recipient }}, your {{ item_type }} is ready.'
        )

        rendered = template.render_body({'recipient': 'Jane', 'item_type': 'order'})
        assert 'Hello Jane' in rendered
        assert 'order is ready' in rendered

    def test_render_template_html_body(self, email_channel):
        """Test rendering HTML body with context."""
        template = NotificationTemplate.objects.create(
            name='HTML Template',
            template_type='custom',
            channel=email_channel,
            subject='Test',
            body='Plain text',
            html_body='<h1>Hello {{ name }}</h1><p>{{ message }}</p>'
        )

        rendered = template.render_html_body({'name': 'Bob', 'message': 'Welcome!'})
        assert '<h1>Hello Bob</h1>' in rendered
        assert '<p>Welcome!</p>' in rendered

    def test_unique_template_per_channel_language(self, email_channel):
        """Test template_type + channel + language uniqueness."""
        NotificationTemplate.objects.create(
            name='English Version',
            template_type='offer_sent',
            channel=email_channel,
            subject='Offer',
            body='Body',
            language='en'
        )

        # Different language should work
        template_fr = NotificationTemplate.objects.create(
            name='French Version',
            template_type='offer_sent',
            channel=email_channel,
            subject='Offre',
            body='Corps',
            language='fr'
        )
        assert template_fr.language == 'fr'

        # Same combination should fail
        with pytest.raises(Exception):  # IntegrityError
            NotificationTemplate.objects.create(
                name='Duplicate',
                template_type='offer_sent',
                channel=email_channel,
                subject='Duplicate',
                body='Duplicate',
                language='en'
            )


# ============================================================================
# NOTIFICATION PREFERENCE TESTS
# ============================================================================

@pytest.mark.django_db
class TestNotificationPreference:
    """Test notification preference functionality."""

    def test_create_notification_preference(self, user_factory):
        """Test creating notification preferences for a user."""
        user = user_factory()

        preference = NotificationPreference.objects.create(
            user=user,
            notifications_enabled=True,
            quiet_hours_enabled=True,
            quiet_hours_start='22:00:00',
            quiet_hours_end='08:00:00',
            timezone='America/New_York',
            email_digest_frequency='daily',
            channel_preferences={
                'email': True,
                'sms': False,
                'push': True,
                'in_app': True
            },
            type_preferences={
                'application_received': {'email': True, 'in_app': True},
                'interview_scheduled': {'email': True, 'sms': True, 'push': True}
            }
        )

        assert preference.id is not None
        assert preference.user == user
        assert preference.notifications_enabled is True
        assert preference.quiet_hours_enabled is True
        assert preference.timezone == 'America/New_York'
        assert preference.channel_preferences['email'] is True
        assert preference.channel_preferences['sms'] is False

    def test_notification_preference_unsubscribe_token(self, user_factory):
        """Test unsubscribe token is auto-generated."""
        user = user_factory()

        preference = NotificationPreference.objects.create(
            user=user,
            notifications_enabled=True
        )

        assert preference.unsubscribe_token is not None
        assert len(str(preference.unsubscribe_token)) == 36  # UUID format

    def test_global_unsubscribe(self, user_factory):
        """Test global unsubscribe functionality."""
        user = user_factory()

        preference = NotificationPreference.objects.create(
            user=user,
            notifications_enabled=True,
            global_unsubscribe=False
        )

        # User globally unsubscribes
        preference.global_unsubscribe = True
        preference.save()

        preference.refresh_from_db()
        assert preference.global_unsubscribe is True

    def test_per_type_unsubscribe(self, user_factory):
        """Test per-type unsubscribe functionality."""
        user = user_factory()

        preference = NotificationPreference.objects.create(
            user=user,
            notifications_enabled=True,
            unsubscribed_types=['promotional', 'weekly_digest']
        )

        assert 'promotional' in preference.unsubscribed_types
        assert 'weekly_digest' in preference.unsubscribed_types
        assert len(preference.unsubscribed_types) == 2

    def test_one_preference_per_user(self, user_factory):
        """Test that each user can only have one preference."""
        user = user_factory()

        NotificationPreference.objects.create(user=user, notifications_enabled=True)

        with pytest.raises(Exception):  # IntegrityError
            NotificationPreference.objects.create(user=user, notifications_enabled=False)


# ============================================================================
# NOTIFICATION CREATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestNotificationCreation:
    """Test notification creation and management."""

    @pytest.fixture
    def channel_and_template(self, user_factory):
        """Create channel and template for testing."""
        channel = NotificationChannel.objects.create(
            name='In-App Channel',
            channel_type='in_app',
            is_active=True
        )

        creator = user_factory()

        template = NotificationTemplate.objects.create(
            name='Test Template',
            template_type='custom',
            channel=channel,
            subject='Test Subject',
            body='Test Body',
            created_by=creator
        )

        return channel, template

    def test_create_basic_notification(self, user_factory, channel_and_template):
        """Test creating a basic notification."""
        recipient = user_factory()
        sender = user_factory()
        channel, template = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            sender=sender,
            channel=channel,
            template=template,
            notification_type='custom',
            title='Test Notification',
            message='This is a test notification',
            priority='normal',
            status='pending'
        )

        assert notification.id is not None
        assert notification.recipient == recipient
        assert notification.sender == sender
        assert notification.channel == channel
        assert notification.template == template
        assert notification.title == 'Test Notification'
        assert notification.status == 'pending'
        assert notification.priority == 'normal'
        assert notification.is_read is False
        assert notification.uuid is not None

    def test_notification_with_action_url(self, user_factory, channel_and_template):
        """Test creating notification with action URL."""
        recipient = user_factory()
        channel, template = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Job Application',
            message='New application received',
            action_url='/app/applications/123/',
            action_text='View Application'
        )

        assert notification.action_url == '/app/applications/123/'
        assert notification.action_text == 'View Application'

    def test_notification_with_context_data(self, user_factory, channel_and_template):
        """Test notification with context data."""
        recipient = user_factory()
        channel, template = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Interview Scheduled',
            message='Interview scheduled for tomorrow',
            context_data={
                'interview_id': 456,
                'candidate_name': 'John Doe',
                'interview_date': '2026-01-20',
                'interviewer': 'Jane Smith'
            }
        )

        assert notification.context_data['interview_id'] == 456
        assert notification.context_data['candidate_name'] == 'John Doe'
        assert 'interview_date' in notification.context_data

    def test_notification_with_generic_relation(self, user_factory, channel_and_template):
        """Test notification with generic foreign key to related object."""
        from jobs.models import JobPosting, Pipeline, PipelineStage, JobCategory
        from tenants.models import Tenant, Plan

        # Create necessary objects
        plan = Plan.objects.create(
            name='Test Plan',
            slug='test-plan',
            price_monthly=Decimal('0.00')
        )

        tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test-tenant',
            schema_name='test_tenant',
            plan=plan
        )

        category = JobCategory.objects.create(
            name='Engineering',
            slug='engineering'
        )

        pipeline = Pipeline.objects.create(
            name='Default Pipeline',
            is_default=True
        )

        PipelineStage.objects.create(
            pipeline=pipeline,
            name='New',
            stage_type='new',
            order=0
        )

        job = JobPosting.objects.create(
            title='Software Engineer',
            description='Test job',
            category=category,
            pipeline=pipeline,
            status='draft'
        )

        recipient = user_factory()
        channel, template = channel_and_template

        content_type = ContentType.objects.get_for_model(JobPosting)

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='New Job Posted',
            message='A new job has been posted',
            content_type=content_type,
            object_id=job.id
        )

        assert notification.content_type == content_type
        assert notification.object_id == job.id

    def test_notification_priority_levels(self, user_factory, channel_and_template):
        """Test all notification priority levels."""
        recipient = user_factory()
        channel, _ = channel_and_template

        priorities = ['low', 'normal', 'high', 'urgent']

        for priority in priorities:
            notification = Notification.objects.create(
                recipient=recipient,
                channel=channel,
                title=f'{priority.title()} Priority',
                message='Test message',
                priority=priority
            )
            assert notification.priority == priority

    def test_notification_status_lifecycle(self, user_factory, channel_and_template):
        """Test notification status lifecycle."""
        recipient = user_factory()
        channel, _ = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Status Test',
            message='Testing status transitions',
            status='pending'
        )

        # Pending -> Queued
        notification.status = 'queued'
        notification.save()
        assert notification.status == 'queued'

        # Queued -> Sending
        notification.status = 'sending'
        notification.save()
        assert notification.status == 'sending'

        # Sending -> Sent
        notification.mark_as_sent()
        assert notification.status == 'sent'
        assert notification.sent_at is not None

        # Sent -> Delivered
        notification.mark_as_delivered()
        assert notification.status == 'delivered'
        assert notification.delivered_at is not None

        # Delivered -> Read
        notification.mark_as_read()
        assert notification.status == 'read'
        assert notification.is_read is True
        assert notification.read_at is not None


    def test_mark_notification_as_read(self, user_factory, channel_and_template):
        """Test marking notification as read."""
        recipient = user_factory()
        channel, _ = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Read Test',
            message='Testing read functionality',
            is_read=False
        )

        assert notification.is_read is False
        assert notification.read_at is None

        notification.mark_as_read()

        assert notification.is_read is True
        assert notification.read_at is not None
        assert notification.status == 'read'

    def test_mark_notification_as_unread(self, user_factory, channel_and_template):
        """Test marking notification as unread."""
        recipient = user_factory()
        channel, _ = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Unread Test',
            message='Testing unread functionality',
            is_read=True,
            read_at=timezone.now()
        )

        notification.mark_as_unread()

        assert notification.is_read is False
        assert notification.read_at is None

    def test_dismiss_notification(self, user_factory, channel_and_template):
        """Test dismissing a notification."""
        recipient = user_factory()
        channel, _ = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Dismiss Test',
            message='Testing dismiss functionality'
        )

        assert notification.is_dismissed is False
        assert notification.dismissed_at is None

        notification.dismiss()

        assert notification.is_dismissed is True
        assert notification.dismissed_at is not None

    def test_notification_retry_logic(self, user_factory, channel_and_template):
        """Test notification retry logic."""
        recipient = user_factory()
        channel, _ = channel_and_template

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Retry Test',
            message='Testing retry logic',
            status='pending',
            retry_count=0,
            max_retries=3
        )

        # Simulate failures
        for i in range(3):
            assert notification.can_retry()
            notification.mark_as_failed(f'Error attempt {i+1}')
            notification.retry_count += 1
            notification.save()

        # After max retries, should not be able to retry
        assert not notification.can_retry()
        assert notification.retry_count == 3

    def test_notification_with_expiration(self, user_factory, channel_and_template):
        """Test notification with expiration date."""
        recipient = user_factory()
        channel, _ = channel_and_template

        expires_at = timezone.now() + timedelta(days=7)

        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Expiring Notification',
            message='This notification will expire',
            expires_at=expires_at
        )

        assert notification.expires_at == expires_at

    def test_bulk_notification_creation(self, user_factory, channel_and_template):
        """Test creating multiple notifications at once."""
        recipients = [user_factory() for _ in range(10)]
        channel, template = channel_and_template

        import uuid
        batch_id = uuid.uuid4()

        notifications = []
        for recipient in recipients:
            notifications.append(Notification(
                recipient=recipient,
                channel=channel,
                template=template,
                title='Bulk Notification',
                message='This is a bulk notification',
                batch_id=batch_id
            ))

        created = Notification.objects.bulk_create(notifications)

        assert len(created) == 10
        assert Notification.objects.filter(batch_id=batch_id).count() == 10


# ============================================================================
# SCHEDULED NOTIFICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestScheduledNotification:
    """Test scheduled notification functionality."""

    @pytest.fixture
    def channel_and_template(self, user_factory):
        """Create channel and template for testing."""
        channel = NotificationChannel.objects.create(
            name='Email Channel',
            channel_type='email',
            is_active=True
        )

        creator = user_factory()

        template = NotificationTemplate.objects.create(
            name='Scheduled Template',
            template_type='appointment_reminder',
            channel=channel,
            subject='Reminder',
            body='You have an upcoming appointment',
            created_by=creator
        )

        return channel, template

    def test_create_scheduled_notification(self, user_factory, channel_and_template):
        """Test creating a scheduled notification."""
        recipient = user_factory()
        creator = user_factory()
        _, template = channel_and_template

        scheduled_at = timezone.now() + timedelta(hours=24)

        scheduled = ScheduledNotification.objects.create(
            recipient=recipient,
            template=template,
            scheduled_at=scheduled_at,
            recurrence='once',
            is_active=True,
            name='Appointment Reminder',
            description='Reminder for upcoming appointment',
            created_by=creator,
            context_data={
                'appointment_id': 123,
                'appointment_time': '2026-01-20 10:00:00'
            }
        )

        assert scheduled.id is not None
        assert scheduled.recipient == recipient
        assert scheduled.template == template
        assert scheduled.scheduled_at == scheduled_at
        assert scheduled.recurrence == 'once'
        assert scheduled.is_active is True
        assert scheduled.context_data['appointment_id'] == 123

    def test_recurring_notification(self, user_factory, channel_and_template):
        """Test creating a recurring notification."""
        recipient = user_factory()
        _, template = channel_and_template

        scheduled_at = timezone.now().replace(hour=9, minute=0, second=0)
        recurrence_end = timezone.now() + timedelta(days=30)

        scheduled = ScheduledNotification.objects.create(
            recipient=recipient,
            template=template,
            scheduled_at=scheduled_at,
            recurrence='daily',
            recurrence_end_date=recurrence_end,
            is_active=True,
            name='Daily Reminder',
            description='Daily notification for testing'
        )

        assert scheduled.recurrence == 'daily'
        assert scheduled.recurrence_end_date == recurrence_end

    def test_broadcast_scheduled_notification(self, channel_and_template):
        """Test creating a broadcast scheduled notification (no specific recipient)."""
        _, template = channel_and_template

        scheduled_at = timezone.now() + timedelta(hours=2)

        scheduled = ScheduledNotification.objects.create(
            recipient=None,  # Broadcast
            template=template,
            scheduled_at=scheduled_at,
            recurrence='once',
            is_active=True,
            name='System Maintenance Alert',
            description='Broadcast notification for system maintenance',
            recipient_filter={
                'role__in': ['admin', 'owner']
            }
        )

        assert scheduled.recipient is None
        assert 'role__in' in scheduled.recipient_filter
        assert 'admin' in scheduled.recipient_filter['role__in']

    def test_calculate_next_run(self, user_factory, channel_and_template):
        """Test calculating next run time for recurring notifications."""
        recipient = user_factory()
        _, template = channel_and_template

        scheduled_at = timezone.now()

        scheduled = ScheduledNotification.objects.create(
            recipient=recipient,
            template=template,
            scheduled_at=scheduled_at,
            recurrence='daily',
            is_active=True,
            name='Daily Task'
        )

        # Calculate next run after processing
        scheduled.last_run_at = timezone.now()
        scheduled.calculate_next_run()

        assert scheduled.next_run_at is not None
        # Next run should be approximately 24 hours from last run
        expected_next_run = scheduled.last_run_at + timedelta(days=1)
        time_diff = abs((scheduled.next_run_at - expected_next_run).total_seconds())
        assert time_diff < 60  # Within 1 minute


# ============================================================================
# NOTIFICATION DELIVERY LOG TESTS
# ============================================================================

@pytest.mark.django_db
class TestNotificationDeliveryLog:
    """Test notification delivery logging."""

    @pytest.fixture
    def notification(self, user_factory):
        """Create a notification for testing."""
        recipient = user_factory()
        channel = NotificationChannel.objects.create(
            name='Email',
            channel_type='email',
            is_active=True
        )

        return Notification.objects.create(
            recipient=recipient,
            channel=channel,
            title='Test Notification',
            message='Test message'
        )

    def test_create_delivery_log(self, notification):
        """Test creating a delivery log."""
        log = NotificationDeliveryLog.objects.create(
            notification=notification,
            attempt_number=1,
            status='success',
            request_payload={
                'to': 'user@example.com',
                'subject': 'Test',
                'body': 'Test message'
            },
            response_payload={
                'message_id': 'msg_123',
                'status': 'queued'
            },
            response_code=200,
            duration_ms=150,
            external_id='msg_123'
        )

        assert log.id is not None
        assert log.notification == notification
        assert log.attempt_number == 1
        assert log.status == 'success'
        assert log.response_code == 200
        assert log.duration_ms == 150
        assert log.external_id == 'msg_123'

    def test_delivery_log_with_error(self, notification):
        """Test logging a failed delivery attempt."""
        log = NotificationDeliveryLog.objects.create(
            notification=notification,
            attempt_number=1,
            status='failed',
            request_payload={'to': 'user@example.com'},
            response_payload={'error': 'Connection timeout'},
            response_code=500,
            error_type='ConnectionError',
            error_message='Failed to connect to SMTP server',
            error_traceback='Traceback...',
            duration_ms=5000
        )

        assert log.status == 'failed'
        assert log.error_type == 'ConnectionError'
        assert 'SMTP' in log.error_message
        assert log.response_code == 500

    def test_multiple_delivery_attempts(self, notification):
        """Test logging multiple delivery attempts."""
        for attempt in range(1, 4):
            NotificationDeliveryLog.objects.create(
                notification=notification,
                attempt_number=attempt,
                status='failed' if attempt < 3 else 'success',
                request_payload={},
                response_payload={},
                response_code=500 if attempt < 3 else 200
            )

        logs = NotificationDeliveryLog.objects.filter(notification=notification).order_by('attempt_number')
        assert logs.count() == 3
        assert logs[0].status == 'failed'
        assert logs[1].status == 'failed'
        assert logs[2].status == 'success'


# ============================================================================
# TENANT ISOLATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestNotificationTenantIsolation:
    """Test that notifications are properly isolated between tenants."""

    @pytest.fixture
    def two_tenants_setup(self, user_factory):
        """Create two tenants with users and notifications."""
        from tenants.models import Tenant, Plan
        from conftest import tenant_context

        plan = Plan.objects.create(
            name='Test Plan',
            slug='test-plan',
            price_monthly=Decimal('0.00')
        )

        # Tenant A
        tenant_a = Tenant.objects.create(
            name='Tenant A',
            slug='tenant-a',
            schema_name='tenant_a',
            plan=plan
        )

        # Tenant B
        tenant_b = Tenant.objects.create(
            name='Tenant B',
            slug='tenant-b',
            schema_name='tenant_b',
            plan=plan
        )

        # Create users and notifications in each tenant
        with tenant_context(tenant_a):
            user_a = user_factory(email='user_a@tenanta.com')
            channel_a = NotificationChannel.objects.create(
                name='Channel A',
                channel_type='in_app'
            )
            notification_a = Notification.objects.create(
                recipient=user_a,
                channel=channel_a,
                title='Notification for Tenant A',
                message='This is for Tenant A only'
            )

        with tenant_context(tenant_b):
            user_b = user_factory(email='user_b@tenantb.com')
            channel_b = NotificationChannel.objects.create(
                name='Channel B',
                channel_type='in_app'
            )
            notification_b = Notification.objects.create(
                recipient=user_b,
                channel=channel_b,
                title='Notification for Tenant B',
                message='This is for Tenant B only'
            )

        return {
            'tenant_a': tenant_a,
            'tenant_b': tenant_b,
            'user_a': user_a,
            'user_b': user_b,
            'notification_a': notification_a,
            'notification_b': notification_b
        }

    def test_tenant_notifications_isolated(self, two_tenants_setup):
        """Test that tenants cannot access each other's notifications."""
        from conftest import tenant_context

        tenant_a = two_tenants_setup['tenant_a']
        tenant_b = two_tenants_setup['tenant_b']

        # In Tenant A, should only see Tenant A notifications
        with tenant_context(tenant_a):
            notifications_a = Notification.objects.all()
            assert notifications_a.count() == 1
            assert notifications_a.first().title == 'Notification for Tenant A'

        # In Tenant B, should only see Tenant B notifications
        with tenant_context(tenant_b):
            notifications_b = Notification.objects.all()
            assert notifications_b.count() == 1
            assert notifications_b.first().title == 'Notification for Tenant B'


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestNotificationIntegration:
    """Integration tests for end-to-end notification workflows."""

    def test_complete_notification_workflow(self, user_factory):
        """Test complete workflow: channel -> template -> preference -> notification -> delivery."""
        # Step 1: Create channel
        channel = NotificationChannel.objects.create(
            name='Test Email Channel',
            channel_type='email',
            is_active=True,
            config={'smtp_host': 'smtp.test.com'}
        )

        # Step 2: Create template
        creator = user_factory()
        template = NotificationTemplate.objects.create(
            name='Welcome Template',
            template_type='welcome_email',
            channel=channel,
            subject='Welcome {{ user_name }}!',
            body='Hi {{ user_name }}, welcome to our platform!',
            created_by=creator
        )

        # Step 3: Create user and preferences
        recipient = user_factory()
        preferences = NotificationPreference.objects.create(
            user=recipient,
            notifications_enabled=True,
            channel_preferences={'email': True},
            type_preferences={'welcome_email': {'email': True}}
        )

        # Step 4: Create notification
        notification = Notification.objects.create(
            recipient=recipient,
            channel=channel,
            template=template,
            notification_type='welcome_email',
            title='Welcome to Zumodra',
            message=template.render_body({'user_name': recipient.first_name}),
            priority='normal',
            status='pending'
        )

        # Step 5: Simulate delivery
        notification.status = 'sending'
        notification.save()

        delivery_log = NotificationDeliveryLog.objects.create(
            notification=notification,
            attempt_number=1,
            status='success',
            request_payload={'to': recipient.email},
            response_payload={'message_id': 'test_123'},
            response_code=200,
            duration_ms=120
        )

        notification.mark_as_sent()
        notification.mark_as_delivered()

        # Verify complete workflow
        assert channel.is_active
        assert template.is_active
        assert preferences.notifications_enabled
        assert notification.status == 'delivered'
        assert delivery_log.status == 'success'
        assert Notification.objects.filter(recipient=recipient).count() == 1

    def test_notification_with_all_features(self, user_factory):
        """Test notification with all optional features enabled."""
        from jobs.models import JobPosting, Pipeline, PipelineStage, JobCategory
        from tenants.models import Tenant, Plan

        # Create dependencies
        plan = Plan.objects.create(name='Test', slug='test', price_monthly=Decimal('0'))
        tenant = Tenant.objects.create(
            name='Test',
            slug='test',
            schema_name='test',
            plan=plan
        )
        category = JobCategory.objects.create(name='Tech', slug='tech')
        pipeline = Pipeline.objects.create(name='Default', is_default=True)
        PipelineStage.objects.create(pipeline=pipeline, name='New', stage_type='new', order=0)

        job = JobPosting.objects.create(
            title='Engineer',
            description='Test',
            category=category,
            pipeline=pipeline
        )

        recipient = user_factory()
        sender = user_factory()
        creator = user_factory()

        channel = NotificationChannel.objects.create(
            name='Multi-Channel',
            channel_type='in_app'
        )

        template = NotificationTemplate.objects.create(
            name='Rich Template',
            template_type='custom',
            channel=channel,
            subject='Test',
            body='Test',
            html_body='<p>Test</p>',
            created_by=creator
        )

        import uuid
        batch_id = uuid.uuid4()
        content_type = ContentType.objects.get_for_model(JobPosting)

        notification = Notification.objects.create(
            recipient=recipient,
            sender=sender,
            channel=channel,
            template=template,
            notification_type='custom',
            title='Complete Notification',
            message='This has all features',
            html_message='<p>Rich HTML content</p>',
            action_url='/app/jobs/1/',
            action_text='View Job',
            content_type=content_type,
            object_id=job.id,
            context_data={'job_id': job.id, 'custom_field': 'value'},
            status='pending',
            priority='high',
            batch_id=batch_id,
            expires_at=timezone.now() + timedelta(days=30),
            max_retries=5
        )

        # Verify all fields are set correctly
        assert notification.recipient == recipient
        assert notification.sender == sender
        assert notification.template == template
        assert notification.action_url == '/app/jobs/1/'
        assert notification.content_type == content_type
        assert notification.object_id == job.id
        assert notification.context_data['job_id'] == job.id
        assert notification.priority == 'high'
        assert notification.batch_id == batch_id
        assert notification.expires_at is not None
        assert notification.max_retries == 5
