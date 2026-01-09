"""
Webhook Signal Handlers

Connects Django model signals to outbound webhook dispatch.
When models change, webhooks are automatically sent to subscribers.
"""

import logging
from functools import wraps
from typing import Any, Dict, Optional

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

logger = logging.getLogger(__name__)


def get_tenant_id(instance) -> Optional[int]:
    """Extract tenant_id from a model instance."""
    # Direct tenant_id
    if hasattr(instance, 'tenant_id') and instance.tenant_id:
        return instance.tenant_id

    # Via tenant FK
    if hasattr(instance, 'tenant') and instance.tenant:
        return instance.tenant.id

    # Via user -> tenant_user
    if hasattr(instance, 'user') and instance.user:
        tenant_users = getattr(instance.user, 'tenantuser_set', None)
        if tenant_users and tenant_users.exists():
            return tenant_users.first().tenant_id

    # Via application -> tenant
    if hasattr(instance, 'application') and instance.application:
        return getattr(instance.application, 'tenant_id', None)

    return None


def serialize_instance(instance, fields: list = None) -> Dict[str, Any]:
    """Serialize a model instance to a dictionary."""
    data = {
        'id': str(instance.pk) if instance.pk else None,
    }

    # Add common fields
    for field in ['uuid', 'name', 'title', 'email', 'status', 'created_at', 'updated_at']:
        if hasattr(instance, field):
            val = getattr(instance, field)
            if val is not None:
                data[field] = str(val) if not isinstance(val, (str, int, float, bool, type(None))) else val

    # Add specified fields
    if fields:
        for field in fields:
            if hasattr(instance, field):
                val = getattr(instance, field)
                if val is not None:
                    data[field] = str(val) if not isinstance(val, (str, int, float, bool, type(None), list, dict)) else val

    return data


def dispatch_webhook_for_model(
    instance,
    app_name: str,
    event_type: str,
    extra_data: Dict = None
):
    """Dispatch webhook for a model change."""
    from .outbound_webhooks import dispatch_webhook

    tenant_id = get_tenant_id(instance)
    if not tenant_id:
        logger.debug(f"No tenant_id for webhook {app_name}.{event_type}")
        return

    data = serialize_instance(instance)
    if extra_data:
        data.update(extra_data)

    try:
        dispatch_webhook(
            tenant_id=tenant_id,
            app_name=app_name,
            event_type=event_type,
            data=data,
            event_id=str(instance.pk) if instance.pk else None
        )
    except Exception as e:
        logger.error(f"Failed to dispatch webhook {app_name}.{event_type}: {e}")


# =============================================================================
# ACCOUNTS APP WEBHOOKS
# =============================================================================

def connect_accounts_webhooks():
    """Connect webhook signals for accounts app."""
    try:
        from accounts.models import TenantUser
        from django.contrib.auth import get_user_model
        User = get_user_model()

        @receiver(post_save, sender=User)
        def user_saved(sender, instance, created, **kwargs):
            event = 'user.created' if created else 'user.updated'
            dispatch_webhook_for_model(instance, 'accounts', event, {
                'email': instance.email,
                'username': getattr(instance, 'username', None),
                'is_active': instance.is_active,
            })

        @receiver(post_delete, sender=User)
        def user_deleted(sender, instance, **kwargs):
            dispatch_webhook_for_model(instance, 'accounts', 'user.deleted')

        @receiver(post_save, sender=TenantUser)
        def tenant_user_saved(sender, instance, created, **kwargs):
            event = 'tenant_user.created' if created else 'tenant_user.updated'
            dispatch_webhook_for_model(instance, 'accounts', event, {
                'role': instance.role,
                'user_id': str(instance.user_id) if instance.user_id else None,
            })

        @receiver(post_delete, sender=TenantUser)
        def tenant_user_deleted(sender, instance, **kwargs):
            dispatch_webhook_for_model(instance, 'accounts', 'tenant_user.deleted')

        logger.info("Accounts webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect accounts webhooks: {e}")


# =============================================================================
# ATS APP WEBHOOKS
# =============================================================================

def connect_ats_webhooks():
    """Connect webhook signals for ATS app."""
    try:
        from ats.models import JobPosting, Candidate, Application, Interview, Offer

        @receiver(post_save, sender=JobPosting)
        def job_saved(sender, instance, created, **kwargs):
            event = 'job.created' if created else 'job.updated'
            dispatch_webhook_for_model(instance, 'ats', event, {
                'title': instance.title,
                'status': instance.status,
                'department': getattr(instance, 'department', None),
            })

        @receiver(post_delete, sender=JobPosting)
        def job_deleted(sender, instance, **kwargs):
            dispatch_webhook_for_model(instance, 'ats', 'job.deleted')

        @receiver(post_save, sender=Candidate)
        def candidate_saved(sender, instance, created, **kwargs):
            event = 'candidate.created' if created else 'candidate.updated'
            dispatch_webhook_for_model(instance, 'ats', event, {
                'first_name': getattr(instance, 'first_name', None),
                'last_name': getattr(instance, 'last_name', None),
                'email': getattr(instance, 'email', None),
            })

        @receiver(post_delete, sender=Candidate)
        def candidate_deleted(sender, instance, **kwargs):
            dispatch_webhook_for_model(instance, 'ats', 'candidate.deleted')

        @receiver(post_save, sender=Application)
        def application_saved(sender, instance, created, **kwargs):
            event = 'application.created' if created else 'application.updated'
            dispatch_webhook_for_model(instance, 'ats', event, {
                'status': instance.status,
                'job_id': str(instance.job_id) if hasattr(instance, 'job_id') else None,
                'candidate_id': str(instance.candidate_id) if hasattr(instance, 'candidate_id') else None,
            })

        @receiver(post_delete, sender=Application)
        def application_deleted(sender, instance, **kwargs):
            dispatch_webhook_for_model(instance, 'ats', 'application.deleted')

        @receiver(post_save, sender=Interview)
        def interview_saved(sender, instance, created, **kwargs):
            event = 'interview.scheduled' if created else 'interview.updated'
            dispatch_webhook_for_model(instance, 'ats', event, {
                'status': getattr(instance, 'status', None),
                'scheduled_start': str(getattr(instance, 'scheduled_start', None)),
            })

        @receiver(post_save, sender=Offer)
        def offer_saved(sender, instance, created, **kwargs):
            event = 'offer.created' if created else 'offer.updated'
            dispatch_webhook_for_model(instance, 'ats', event, {
                'status': getattr(instance, 'status', None),
            })

        logger.info("ATS webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect ATS webhooks: {e}")


# =============================================================================
# HR_CORE APP WEBHOOKS
# =============================================================================

def connect_hr_core_webhooks():
    """Connect webhook signals for HR core app."""
    try:
        from hr_core.models import Employee, TimeOffRequest, EmployeeOnboarding

        @receiver(post_save, sender=Employee)
        def employee_saved(sender, instance, created, **kwargs):
            event = 'employee.created' if created else 'employee.updated'
            dispatch_webhook_for_model(instance, 'hr_core', event, {
                'status': getattr(instance, 'status', None),
                'department': getattr(instance, 'department', None),
            })

        @receiver(post_save, sender=TimeOffRequest)
        def timeoff_saved(sender, instance, created, **kwargs):
            if created:
                event = 'timeoff.requested'
            else:
                status = getattr(instance, 'status', '')
                if status == 'approved':
                    event = 'timeoff.approved'
                elif status == 'rejected':
                    event = 'timeoff.rejected'
                else:
                    event = 'timeoff.updated'
            dispatch_webhook_for_model(instance, 'hr_core', event, {
                'status': getattr(instance, 'status', None),
                'start_date': str(getattr(instance, 'start_date', None)),
                'end_date': str(getattr(instance, 'end_date', None)),
            })

        @receiver(post_save, sender=EmployeeOnboarding)
        def onboarding_saved(sender, instance, created, **kwargs):
            event = 'onboarding.started' if created else 'onboarding.updated'
            dispatch_webhook_for_model(instance, 'hr_core', event)

        logger.info("HR Core webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect HR Core webhooks: {e}")


# =============================================================================
# SERVICES APP WEBHOOKS
# =============================================================================

def connect_services_webhooks():
    """Connect webhook signals for services app."""
    try:
        from services.models import (
            Service, ServiceProvider, ServiceContract,
            ServiceProposal, ServiceReview
        )

        @receiver(post_save, sender=Service)
        def service_saved(sender, instance, created, **kwargs):
            event = 'service.created' if created else 'service.updated'
            dispatch_webhook_for_model(instance, 'services', event, {
                'title': getattr(instance, 'title', None),
                'status': getattr(instance, 'status', None),
            })

        @receiver(post_delete, sender=Service)
        def service_deleted(sender, instance, **kwargs):
            dispatch_webhook_for_model(instance, 'services', 'service.deleted')

        @receiver(post_save, sender=ServiceProvider)
        def provider_saved(sender, instance, created, **kwargs):
            event = 'provider.created' if created else 'provider.updated'
            dispatch_webhook_for_model(instance, 'services', event, {
                'is_verified': getattr(instance, 'is_verified', None),
            })

        @receiver(post_save, sender=ServiceContract)
        def contract_saved(sender, instance, created, **kwargs):
            event = 'contract.created' if created else 'contract.updated'
            dispatch_webhook_for_model(instance, 'services', event, {
                'status': getattr(instance, 'status', None),
            })

        @receiver(post_save, sender=ServiceProposal)
        def proposal_saved(sender, instance, created, **kwargs):
            if created:
                event = 'proposal.submitted'
            else:
                status = getattr(instance, 'status', '')
                if status == 'accepted':
                    event = 'proposal.accepted'
                elif status == 'rejected':
                    event = 'proposal.rejected'
                else:
                    event = 'proposal.updated'
            dispatch_webhook_for_model(instance, 'services', event, {
                'status': getattr(instance, 'status', None),
            })

        @receiver(post_save, sender=ServiceReview)
        def review_saved(sender, instance, created, **kwargs):
            if created:
                dispatch_webhook_for_model(instance, 'services', 'review.created', {
                    'rating': getattr(instance, 'rating', None),
                })

        logger.info("Services webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect Services webhooks: {e}")


# =============================================================================
# FINANCE APP WEBHOOKS
# =============================================================================

def connect_finance_webhooks():
    """Connect webhook signals for finance app."""
    try:
        from finance.models import PaymentTransaction, Invoice, UserSubscription

        @receiver(post_save, sender=PaymentTransaction)
        def payment_saved(sender, instance, created, **kwargs):
            if created:
                event = 'payment.created'
            else:
                succeeded = getattr(instance, 'succeeded', False)
                if succeeded:
                    event = 'payment.completed'
                else:
                    event = 'payment.failed'
            dispatch_webhook_for_model(instance, 'finance', event, {
                'amount': str(getattr(instance, 'amount', None)),
                'succeeded': getattr(instance, 'succeeded', None),
            })

        @receiver(post_save, sender=Invoice)
        def invoice_saved(sender, instance, created, **kwargs):
            if created:
                event = 'invoice.created'
            else:
                status = getattr(instance, 'status', '')
                if status == 'paid':
                    event = 'invoice.paid'
                else:
                    event = 'invoice.updated'
            dispatch_webhook_for_model(instance, 'finance', event, {
                'total': str(getattr(instance, 'total_amount', None)),
                'status': getattr(instance, 'status', None),
            })

        @receiver(post_save, sender=UserSubscription)
        def subscription_saved(sender, instance, created, **kwargs):
            if created:
                event = 'subscription.created'
            else:
                status = getattr(instance, 'status', '')
                if status == 'cancelled':
                    event = 'subscription.cancelled'
                else:
                    event = 'subscription.updated'
            dispatch_webhook_for_model(instance, 'finance', event, {
                'plan_id': str(getattr(instance, 'plan_id', None)),
                'status': getattr(instance, 'status', None),
            })

        logger.info("Finance webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect Finance webhooks: {e}")


# =============================================================================
# APPOINTMENT APP WEBHOOKS
# =============================================================================

def connect_appointment_webhooks():
    """Connect webhook signals for appointment app."""
    try:
        from appointment.models import Appointment

        @receiver(post_save, sender=Appointment)
        def appointment_saved(sender, instance, created, **kwargs):
            if created:
                event = 'appointment.booked'
            else:
                status = getattr(instance, 'status', '')
                if status == 'cancelled':
                    event = 'appointment.cancelled'
                elif status == 'completed':
                    event = 'appointment.completed'
                elif status == 'no_show':
                    event = 'appointment.no_show'
                else:
                    event = 'appointment.updated'
            dispatch_webhook_for_model(instance, 'appointment', event, {
                'status': getattr(instance, 'status', None),
            })

        logger.info("Appointment webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect Appointment webhooks: {e}")


# =============================================================================
# MESSAGES_SYS APP WEBHOOKS
# =============================================================================

def connect_messages_webhooks():
    """Connect webhook signals for messages app."""
    try:
        from messages_sys.models import Message, Conversation

        @receiver(post_save, sender=Message)
        def message_saved(sender, instance, created, **kwargs):
            if created:
                dispatch_webhook_for_model(instance, 'messages_sys', 'message.created')

        @receiver(post_save, sender=Conversation)
        def conversation_saved(sender, instance, created, **kwargs):
            if created:
                dispatch_webhook_for_model(instance, 'messages_sys', 'conversation.created')

        logger.info("Messages webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect Messages webhooks: {e}")


# =============================================================================
# NOTIFICATIONS APP WEBHOOKS
# =============================================================================

def connect_notifications_webhooks():
    """Connect webhook signals for notifications app."""
    try:
        from notifications.models import Notification

        @receiver(post_save, sender=Notification)
        def notification_saved(sender, instance, created, **kwargs):
            if created:
                dispatch_webhook_for_model(instance, 'notifications', 'notification.created', {
                    'notification_type': getattr(instance, 'notification_type', None),
                })

        logger.info("Notifications webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect Notifications webhooks: {e}")


# =============================================================================
# BLOG APP WEBHOOKS
# =============================================================================

def connect_blog_webhooks():
    """Connect webhook signals for blog app."""
    try:
        from blog.models import BlogPostPage, Comment

        @receiver(post_save, sender=BlogPostPage)
        def blog_post_saved(sender, instance, created, **kwargs):
            if created:
                event = 'post.created'
            elif instance.live:
                event = 'post.published'
            else:
                event = 'post.updated'
            dispatch_webhook_for_model(instance, 'blog', event, {
                'title': instance.title,
                'live': instance.live,
            })

        @receiver(post_delete, sender=BlogPostPage)
        def blog_post_deleted(sender, instance, **kwargs):
            dispatch_webhook_for_model(instance, 'blog', 'post.deleted')

        @receiver(post_save, sender=Comment)
        def comment_saved(sender, instance, created, **kwargs):
            if created:
                dispatch_webhook_for_model(instance, 'blog', 'comment.created')

        logger.info("Blog webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect Blog webhooks: {e}")


# =============================================================================
# NEWSLETTER APP WEBHOOKS
# =============================================================================

def connect_newsletter_webhooks():
    """Connect webhook signals for newsletter app."""
    try:
        from newsletter.models import Newsletter, Subscription, Message

        @receiver(post_save, sender=Newsletter)
        def newsletter_saved(sender, instance, created, **kwargs):
            if created:
                dispatch_webhook_for_model(instance, 'newsletter', 'newsletter.created', {
                    'title': instance.title,
                })

        @receiver(post_save, sender=Subscription)
        def newsletter_subscription_saved(sender, instance, created, **kwargs):
            if created:
                event = 'subscription.created'
            elif not getattr(instance, 'subscribed', True):
                event = 'subscription.cancelled'
            else:
                return
            dispatch_webhook_for_model(instance, 'newsletter', event)

        @receiver(post_save, sender=Message)
        def newsletter_message_saved(sender, instance, created, **kwargs):
            if created:
                dispatch_webhook_for_model(instance, 'newsletter', 'message.sent')

        logger.info("Newsletter webhook signals connected")
    except ImportError as e:
        logger.warning(f"Could not connect Newsletter webhooks: {e}")


# =============================================================================
# MASTER CONNECTOR
# =============================================================================

def connect_all_webhook_signals():
    """Connect all webhook signals for all apps."""
    connect_accounts_webhooks()
    connect_ats_webhooks()
    connect_hr_core_webhooks()
    connect_services_webhooks()
    connect_finance_webhooks()
    connect_appointment_webhooks()
    connect_messages_webhooks()
    connect_notifications_webhooks()
    connect_blog_webhooks()
    connect_newsletter_webhooks()
    logger.info("All outbound webhook signals connected")
