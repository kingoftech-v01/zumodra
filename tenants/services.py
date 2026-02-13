"""
Tenant Services

Service layer for tenant business logic including audit logging,
invitation management, and usage tracking.
"""

import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

logger = logging.getLogger(__name__)


class AuditService:
    """Service for recording audit log entries."""

    @staticmethod
    def log(tenant, user=None, action='', resource_type='', resource_id='',
            description='', old_values=None, new_values=None, request=None):
        """Create an audit log entry for a tenant action."""
        from .models import AuditLog

        ip_address = None
        user_agent = ''

        if request:
            ip_address = (
                request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                or request.META.get('REMOTE_ADDR')
            )
            user_agent = request.META.get('HTTP_USER_AGENT', '')

        try:
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
        except Exception:
            logger.exception("Failed to create audit log entry")
            return None


class InvitationService:
    """Service for managing tenant invitations."""

    @staticmethod
    def create_invitation(tenant, email, invited_by, role='member'):
        """Create a new invitation for a user to join a tenant."""
        from .models import TenantInvitation

        token = secrets.token_urlsafe(48)
        invitation = TenantInvitation.objects.create(
            tenant=tenant,
            email=email,
            invited_by=invited_by,
            assigned_role=role,
            token=token,
            expires_at=timezone.now() + timedelta(days=7),
        )

        InvitationService.send_invitation_email(invitation)
        return invitation

    @staticmethod
    def send_invitation_email(invitation):
        """Send or re-send invitation email."""
        try:
            subject = f"You've been invited to join {invitation.tenant.name}"
            message = (
                f"You have been invited to join {invitation.tenant.name}.\n\n"
                f"Use token: {invitation.token} to accept this invitation.\n\n"
                f"This invitation expires on {invitation.expires_at.strftime('%Y-%m-%d')}."
            )
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[invitation.email],
                fail_silently=True,
            )
        except Exception:
            logger.exception(f"Failed to send invitation email to {invitation.email}")

    @staticmethod
    def accept_invitation(token, user):
        """Accept an invitation by token."""
        from .models import TenantInvitation

        try:
            invitation = TenantInvitation.objects.get(
                token=token,
                status=TenantInvitation.InvitationStatus.PENDING,
            )
        except TenantInvitation.DoesNotExist:
            return None

        if invitation.is_expired:
            invitation.status = TenantInvitation.InvitationStatus.EXPIRED
            invitation.save(update_fields=['status'])
            return None

        invitation.accept(user)
        return invitation


class TenantService:
    """Service for tenant management operations."""

    @staticmethod
    def check_limit(tenant, resource_type):
        """Check if a tenant has reached its plan limit for a resource."""
        if not tenant or not tenant.plan:
            return True

        plan = tenant.plan

        from .models import TenantUsage
        usage, _ = TenantUsage.objects.get_or_create(tenant=tenant)

        limit_map = {
            'users': (usage.user_count, getattr(plan, 'max_users', None)),
            'jobs': (usage.active_job_count, getattr(plan, 'max_active_jobs', None)),
        }

        if resource_type in limit_map:
            current, limit = limit_map[resource_type]
            if limit is not None and limit > 0:
                return current < limit

        return True

    @staticmethod
    def update_usage(tenant):
        """Recalculate and update tenant usage statistics."""
        from .models import TenantUsage

        usage, _ = TenantUsage.objects.get_or_create(tenant=tenant)

        try:
            from tenant_profiles.models import TenantUser
            usage.user_count = TenantUser.objects.filter(
                tenant=tenant, is_active=True
            ).count()
        except Exception:
            pass

        try:
            from jobs.models import JobPosting
            usage.active_job_count = JobPosting.objects.filter(
                tenant=tenant, status='active'
            ).count()
            usage.total_job_count = JobPosting.objects.filter(
                tenant=tenant
            ).count()
        except Exception:
            pass

        usage.last_calculated_at = timezone.now()
        usage.save()

        return usage
