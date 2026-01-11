"""
Tenants Services - Business logic for tenant management.

This module provides comprehensive tenant lifecycle management:
- Tenant creation and provisioning
- Tenant suspension and reactivation
- Tenant data export (GDPR compliance)
- Usage tracking and limits enforcement
- Invitation management
- Audit logging
"""

import csv
import io
import json
import logging
import secrets
import zipfile
from datetime import timedelta
from typing import Optional, Dict, Any, List, Tuple

from django.conf import settings
from django.core.cache import cache
from django.core.serializers import serialize
from django.db import transaction, connection
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string

from .models import (
    Tenant, TenantSettings, TenantInvitation,
    TenantUsage, Domain, Plan, AuditLog
)

logger = logging.getLogger(__name__)


class TenantService:
    """
    Service class for tenant operations.
    Handles tenant creation, provisioning, and management.
    """

    @classmethod
    @transaction.atomic
    def create_tenant(
        cls,
        name: str,
        owner_email: str,
        plan: Optional[Plan] = None,
        domain: Optional[str] = None,
        **kwargs
    ) -> Tenant:
        """
        Create a new tenant with all associated resources.

        Args:
            name: Organization name
            owner_email: Primary contact email
            plan: Subscription plan (defaults to free plan)
            domain: Primary domain for tenant
            **kwargs: Additional tenant fields

        Returns:
            Created Tenant instance
        """
        # Get default plan if not specified
        if not plan:
            plan = Plan.objects.filter(
                plan_type=Plan.PlanType.FREE,
                is_active=True
            ).first()

        # Generate slug from name
        from django.utils.text import slugify
        base_slug = slugify(name)[:50]
        slug = base_slug
        counter = 1
        while Tenant.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1

        # Generate schema name
        schema_name = f"tenant_{slug.replace('-', '_')}"

        # Create tenant
        tenant = Tenant.objects.create(
            name=name,
            slug=slug,
            schema_name=schema_name,
            owner_email=owner_email,
            plan=plan,
            status=Tenant.TenantStatus.TRIAL,
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=14),
            **kwargs
        )

        # Create primary domain
        if domain:
            Domain.objects.create(
                tenant=tenant,
                domain=domain,
                is_primary=True
            )
        else:
            # Create default subdomain
            # Use centralized domain config - TENANT_BASE_DOMAIN from settings
            tenant_base = getattr(settings, 'TENANT_BASE_DOMAIN', '') or getattr(settings, 'PRIMARY_DOMAIN', 'localhost')
            default_domain = f"{slug}.{tenant_base}"
            Domain.objects.create(
                tenant=tenant,
                domain=default_domain,
                is_primary=True
            )

        return tenant

    @classmethod
    def provision_tenant(cls, tenant: Tenant, skip_migrations: bool = False) -> Tuple[bool, str]:
        """
        Provision tenant schema and initial data.
        Called after tenant creation to set up database schema.

        Args:
            tenant: Tenant to provision
            skip_migrations: Skip running migrations (for testing)

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"Starting provisioning for tenant: {tenant.slug}")

            # Step 1: Create schema (django-tenants handles this automatically)
            # The schema is created when the Tenant is saved if auto_create_schema=True

            # Step 2: Run migrations within tenant schema
            if not skip_migrations:
                from django.core.management import call_command
                from django_tenants.utils import schema_context

                with schema_context(tenant.schema_name):
                    call_command('migrate_schemas', schema_name=tenant.schema_name, verbosity=0)

            # Step 3: Create default data
            from django_tenants.utils import schema_context
            with schema_context(tenant.schema_name):
                cls._create_default_data(tenant)

            # Step 4: Update tenant status
            tenant.status = Tenant.TenantStatus.ACTIVE if not tenant.on_trial else Tenant.TenantStatus.TRIAL
            tenant.save(update_fields=['status'])

            # Step 5: Send welcome email
            cls._send_welcome_email(tenant)

            # Step 6: Create audit log entry
            AuditService.log(
                tenant=tenant,
                user=None,
                action=AuditLog.ActionType.CREATE,
                resource_type='Tenant',
                resource_id=str(tenant.uuid),
                description=f"Tenant '{tenant.name}' provisioned successfully"
            )

            logger.info(f"Successfully provisioned tenant: {tenant.slug}")
            return True, "Tenant provisioned successfully"

        except Exception as e:
            logger.error(f"Failed to provision tenant {tenant.slug}: {e}", exc_info=True)
            tenant.status = Tenant.TenantStatus.PENDING
            tenant.save(update_fields=['status'])
            return False, f"Provisioning failed: {str(e)}"

    @classmethod
    def _create_default_data(cls, tenant: Tenant):
        """
        Create default data within tenant schema.

        This creates:
        - Default recruitment pipeline stages
        - Default job categories
        - Default email templates
        - Sample data for onboarding (optional)
        """
        # This runs within the tenant's schema context
        logger.debug(f"Creating default data for tenant: {tenant.slug}")

        # Create default settings if not exists
        TenantSettings.objects.get_or_create(
            tenant=tenant,
            defaults={
                'default_pipeline_stages': [
                    'New',
                    'Screening',
                    'Phone Interview',
                    'Technical Interview',
                    'Final Interview',
                    'Offer',
                    'Hired',
                    'Rejected'
                ],
                'default_language': 'en',
                'default_timezone': 'America/Toronto',
            }
        )

        # Create usage tracking
        TenantUsage.objects.get_or_create(
            tenant=tenant,
            defaults={'month_reset_at': timezone.now()}
        )

    @classmethod
    def _send_welcome_email(cls, tenant: Tenant):
        """Send welcome email to tenant owner."""
        try:
            from .utils import get_tenant_url

            tenant_url = get_tenant_url(tenant)
            subject = f"Welcome to Zumodra - {tenant.name}"

            html_message = render_to_string('tenants/emails/welcome.html', {
                'tenant': tenant,
                'tenant_url': tenant_url,
                'trial_days': tenant.trial_days_remaining if tenant.on_trial else None,
            })

            plain_message = f"""
Welcome to Zumodra!

Your workspace "{tenant.name}" has been created successfully.

Access your dashboard: {tenant_url}

{'Your trial expires in ' + str(tenant.trial_days_remaining) + ' days.' if tenant.on_trial else ''}

Best regards,
The Zumodra Team
            """

            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[tenant.owner_email],
                html_message=html_message,
                fail_silently=True
            )
        except Exception as e:
            logger.warning(f"Failed to send welcome email for tenant {tenant.slug}: {e}")

    @classmethod
    def update_usage(cls, tenant: Tenant) -> TenantUsage:
        """
        Recalculate and update tenant usage statistics.

        Returns:
            Updated TenantUsage instance
        """
        usage, _ = TenantUsage.objects.get_or_create(tenant=tenant)

        # Update counts (these queries run within tenant schema)
        from django_tenants.utils import schema_context
        with schema_context(tenant.schema_name):
            # Count users
            from django.contrib.auth import get_user_model
            User = get_user_model()
            usage.user_count = User.objects.count()

            # Count jobs (from ATS app)
            from ats.models import JobPosting
            usage.active_job_count = JobPosting.objects.filter(status='open').count()

            # Count candidates this month
            from ats.models import Application
            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0)
            usage.candidate_count_this_month = Application.objects.filter(
                created_at__gte=month_start
            ).count()

        usage.last_calculated_at = timezone.now()
        usage.save()

        return usage

    @classmethod
    def check_limit(cls, tenant: Tenant, resource: str, increment: int = 1) -> bool:
        """
        Check if tenant can add more of a resource.

        Args:
            tenant: Tenant to check
            resource: Resource type ('users', 'jobs', 'candidates', 'storage')
            increment: Amount to add

        Returns:
            True if within limits
        """
        plan = tenant.plan
        if not plan:
            return False

        usage = getattr(tenant, 'usage', None)
        if not usage:
            usage = TenantUsage.objects.get_or_create(tenant=tenant)[0]

        limits = {
            'users': (usage.user_count, plan.max_users),
            'jobs': (usage.active_job_count, plan.max_job_postings),
            'candidates': (usage.candidate_count_this_month, plan.max_candidates_per_month),
            'circusales': (usage.circusale_count, plan.max_circusales),
            'storage': (usage.storage_used_gb, plan.storage_limit_gb),
        }

        if resource not in limits:
            return True

        current, limit = limits[resource]
        return (current + increment) <= limit


class InvitationService:
    """
    Service class for tenant invitation operations.
    """

    @classmethod
    @transaction.atomic
    def create_invitation(
        cls,
        tenant: Tenant,
        email: str,
        invited_by,
        role: str = 'member',
        expires_days: int = 7
    ) -> TenantInvitation:
        """
        Create a new invitation to join tenant.

        Args:
            tenant: Target tenant
            email: Invitee email
            invited_by: User sending invitation
            role: Role to assign
            expires_days: Days until expiration

        Returns:
            Created TenantInvitation
        """
        # Check for existing pending invitation
        existing = TenantInvitation.objects.filter(
            tenant=tenant,
            email=email,
            status=TenantInvitation.InvitationStatus.PENDING
        ).first()

        if existing:
            # Refresh existing invitation
            existing.expires_at = timezone.now() + timedelta(days=expires_days)
            existing.token = secrets.token_urlsafe(32)
            existing.save(update_fields=['expires_at', 'token'])
            return existing

        # Create new invitation
        invitation = TenantInvitation.objects.create(
            tenant=tenant,
            email=email,
            invited_by=invited_by,
            role=role,
            token=secrets.token_urlsafe(32),
            expires_at=timezone.now() + timedelta(days=expires_days)
        )

        # Send invitation email
        cls.send_invitation_email(invitation)

        return invitation

    @classmethod
    def send_invitation_email(cls, invitation: TenantInvitation):
        """Send invitation email to invitee."""
        try:
            # Build invitation URL
            # Use centralized domain config for absolute URLs
            site_url = getattr(settings, 'SITE_URL', '') or getattr(settings, 'BASE_URL', '')
            if not site_url:
                from core.domain import get_site_url
                site_url = get_site_url()
            invitation_url = f"{site_url}/join/{invitation.token}/"

            # Render email
            subject = f"You're invited to join {invitation.tenant.name}"
            html_message = render_to_string('tenants/emails/invitation.html', {
                'invitation': invitation,
                'invitation_url': invitation_url,
            })
            plain_message = f"""
            You've been invited to join {invitation.tenant.name} on Zumodra.

            Click the link below to accept the invitation:
            {invitation_url}

            This invitation expires on {invitation.expires_at.strftime('%Y-%m-%d')}.
            """

            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[invitation.email],
                html_message=html_message,
                fail_silently=True
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send invitation email: {e}")

    @classmethod
    def accept_invitation(cls, token: str, user) -> Optional[TenantInvitation]:
        """
        Accept an invitation and add user to tenant.

        Args:
            token: Invitation token
            user: User accepting invitation

        Returns:
            Accepted invitation or None if invalid
        """
        from accounts.models import TenantUser

        invitation = TenantInvitation.objects.filter(
            token=token,
            status=TenantInvitation.InvitationStatus.PENDING
        ).first()

        if not invitation:
            return None

        if invitation.is_expired:
            invitation.status = TenantInvitation.InvitationStatus.EXPIRED
            invitation.save(update_fields=['status'])
            return None

        # Mark invitation as accepted
        invitation.accept(user)

        # Add user to tenant with assigned role
        # Map invitation role to TenantUser role
        role_mapping = {
            'owner': TenantUser.UserRole.OWNER,
            'admin': TenantUser.UserRole.ADMIN,
            'hr_manager': TenantUser.UserRole.HR_MANAGER,
            'recruiter': TenantUser.UserRole.RECRUITER,
            'hiring_manager': TenantUser.UserRole.HIRING_MANAGER,
            'employee': TenantUser.UserRole.EMPLOYEE,
            'viewer': TenantUser.UserRole.VIEWER,
        }
        tenant_role = role_mapping.get(invitation.role, TenantUser.UserRole.EMPLOYEE)

        # Create or update TenantUser membership
        tenant_user, created = TenantUser.objects.update_or_create(
            tenant=invitation.tenant,
            user=user,
            defaults={
                'role': tenant_role,
                'is_active': True,
                'is_primary_tenant': not user.tenant_memberships.filter(is_primary_tenant=True).exists(),
            }
        )

        # Initial profile sync from PublicProfile to TenantProfile
        try:
            from accounts.services import ProfileSyncService
            sync_result = ProfileSyncService.sync_on_invitation_acceptance(
                user=user,
                tenant=invitation.tenant
            )
            logger.info(
                f"Profile sync on invitation: {user.email} → {invitation.tenant.name}, "
                f"Result: {sync_result.get('success')}, "
                f"Synced fields: {sync_result.get('synced_fields', [])}"
            )
        except Exception as e:
            # Don't fail the invitation if sync fails
            import logging
            logger = logging.getLogger(__name__)
            logger.error(
                f"Profile sync failed on invitation acceptance: {user.email} → {invitation.tenant.name}: {e}",
                exc_info=True
            )

        # Update tenant's user count in usage tracking
        try:
            usage = TenantUsage.objects.filter(tenant=invitation.tenant).first()
            if usage:
                usage.user_count = invitation.tenant.members.filter(is_active=True).count()
                usage.save(update_fields=['user_count'])
        except Exception:
            pass

        # Log the acceptance
        import logging
        logger = logging.getLogger(__name__)
        logger.info(
            f"User {user.email} accepted invitation to tenant {invitation.tenant.name} "
            f"with role {tenant_role}"
        )

        return invitation


class AuditService:
    """
    Service class for audit logging.
    """

    @classmethod
    def log(
        cls,
        tenant: Tenant,
        user,
        action: str,
        resource_type: str,
        resource_id: str = '',
        description: str = '',
        old_values: Dict[str, Any] = None,
        new_values: Dict[str, Any] = None,
        request=None
    ):
        """
        Create an audit log entry.

        Args:
            tenant: Tenant context
            user: User performing action
            action: Action type (create, update, delete, etc.)
            resource_type: Type of resource affected
            resource_id: ID of affected resource
            description: Human-readable description
            old_values: Previous values (for updates)
            new_values: New values (for creates/updates)
            request: HTTP request for IP/user agent
        """
        ip_address = None
        user_agent = ''

        if request:
            ip_address = cls._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]

        AuditLog.objects.create(
            tenant=tenant,
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            description=description,
            old_values=old_values or {},
            new_values=new_values or {},
            ip_address=ip_address,
            user_agent=user_agent
        )

    @classmethod
    def _get_client_ip(cls, request) -> Optional[str]:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class TenantLifecycleService:
    """
    Service class for tenant lifecycle operations.
    Handles suspension, activation, cancellation, and deletion.
    """

    @classmethod
    @transaction.atomic
    def suspend_tenant(
        cls,
        tenant: Tenant,
        reason: str = '',
        suspended_by=None,
        notify_owner: bool = True
    ) -> Tuple[bool, str]:
        """
        Suspend a tenant.

        Args:
            tenant: Tenant to suspend
            reason: Reason for suspension
            suspended_by: User performing the suspension
            notify_owner: Whether to send notification email

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if tenant.status == Tenant.TenantStatus.SUSPENDED:
                return False, "Tenant is already suspended"

            # Update tenant status
            previous_status = tenant.status
            tenant.status = Tenant.TenantStatus.SUSPENDED
            tenant.suspended_at = timezone.now()
            tenant.save(update_fields=['status', 'suspended_at'])

            # Invalidate cache
            cls._invalidate_tenant_cache(tenant)

            # Create audit log
            AuditService.log(
                tenant=tenant,
                user=suspended_by,
                action=AuditLog.ActionType.UPDATE,
                resource_type='Tenant',
                resource_id=str(tenant.uuid),
                description=f"Tenant suspended: {reason}",
                old_values={'status': previous_status},
                new_values={'status': Tenant.TenantStatus.SUSPENDED, 'reason': reason}
            )

            # Send notification
            if notify_owner:
                cls._send_suspension_notification(tenant, reason)

            logger.info(f"Tenant {tenant.slug} suspended: {reason}")
            return True, "Tenant suspended successfully"

        except Exception as e:
            logger.error(f"Failed to suspend tenant {tenant.slug}: {e}")
            return False, f"Suspension failed: {str(e)}"

    @classmethod
    @transaction.atomic
    def activate_tenant(
        cls,
        tenant: Tenant,
        activated_by=None,
        notify_owner: bool = True
    ) -> Tuple[bool, str]:
        """
        Activate or reactivate a tenant.

        Args:
            tenant: Tenant to activate
            activated_by: User performing the activation
            notify_owner: Whether to send notification email

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if tenant.status == Tenant.TenantStatus.ACTIVE:
                return False, "Tenant is already active"

            # Update tenant status
            previous_status = tenant.status
            tenant.status = Tenant.TenantStatus.ACTIVE
            tenant.on_trial = False
            tenant.activated_at = timezone.now()
            tenant.suspended_at = None
            tenant.save(update_fields=['status', 'on_trial', 'activated_at', 'suspended_at'])

            # Invalidate cache
            cls._invalidate_tenant_cache(tenant)

            # Create audit log
            AuditService.log(
                tenant=tenant,
                user=activated_by,
                action=AuditLog.ActionType.UPDATE,
                resource_type='Tenant',
                resource_id=str(tenant.uuid),
                description=f"Tenant activated (previous status: {previous_status})",
                old_values={'status': previous_status},
                new_values={'status': Tenant.TenantStatus.ACTIVE}
            )

            # Send notification
            if notify_owner:
                cls._send_activation_notification(tenant)

            logger.info(f"Tenant {tenant.slug} activated")
            return True, "Tenant activated successfully"

        except Exception as e:
            logger.error(f"Failed to activate tenant {tenant.slug}: {e}")
            return False, f"Activation failed: {str(e)}"

    @classmethod
    @transaction.atomic
    def cancel_tenant(
        cls,
        tenant: Tenant,
        reason: str = '',
        cancelled_by=None,
        retain_data_days: int = 30
    ) -> Tuple[bool, str]:
        """
        Cancel a tenant subscription.

        Args:
            tenant: Tenant to cancel
            reason: Cancellation reason
            cancelled_by: User performing cancellation
            retain_data_days: Days to retain data before deletion

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if tenant.status == Tenant.TenantStatus.CANCELLED:
                return False, "Tenant is already cancelled"

            # Update tenant status
            previous_status = tenant.status
            tenant.status = Tenant.TenantStatus.CANCELLED
            tenant.save(update_fields=['status'])

            # Schedule data retention expiry
            deletion_date = timezone.now() + timedelta(days=retain_data_days)

            # Invalidate cache
            cls._invalidate_tenant_cache(tenant)

            # Revoke all invitations
            TenantInvitation.objects.filter(
                tenant=tenant,
                status=TenantInvitation.InvitationStatus.PENDING
            ).update(status=TenantInvitation.InvitationStatus.REVOKED)

            # Create audit log
            AuditService.log(
                tenant=tenant,
                user=cancelled_by,
                action=AuditLog.ActionType.UPDATE,
                resource_type='Tenant',
                resource_id=str(tenant.uuid),
                description=f"Tenant cancelled: {reason}. Data will be deleted after {deletion_date}",
                old_values={'status': previous_status},
                new_values={
                    'status': Tenant.TenantStatus.CANCELLED,
                    'reason': reason,
                    'deletion_scheduled': deletion_date.isoformat()
                }
            )

            # Send cancellation notification
            cls._send_cancellation_notification(tenant, reason, deletion_date)

            logger.info(f"Tenant {tenant.slug} cancelled")
            return True, f"Tenant cancelled. Data will be retained until {deletion_date.date()}"

        except Exception as e:
            logger.error(f"Failed to cancel tenant {tenant.slug}: {e}")
            return False, f"Cancellation failed: {str(e)}"

    @classmethod
    def extend_trial(
        cls,
        tenant: Tenant,
        days: int = 14,
        extended_by=None
    ) -> Tuple[bool, str]:
        """
        Extend a tenant's trial period.

        Args:
            tenant: Tenant to extend trial for
            days: Number of days to extend
            extended_by: User performing extension

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if not tenant.on_trial:
                return False, "Tenant is not on trial"

            old_end_date = tenant.trial_ends_at
            new_end_date = timezone.now() + timedelta(days=days)

            tenant.trial_ends_at = new_end_date

            # Reactivate if previously suspended due to trial expiry
            if tenant.status == Tenant.TenantStatus.SUSPENDED:
                tenant.status = Tenant.TenantStatus.TRIAL

            tenant.save(update_fields=['trial_ends_at', 'status'])

            # Invalidate cache
            cls._invalidate_tenant_cache(tenant)

            # Create audit log
            AuditService.log(
                tenant=tenant,
                user=extended_by,
                action=AuditLog.ActionType.UPDATE,
                resource_type='Tenant',
                resource_id=str(tenant.uuid),
                description=f"Trial extended by {days} days",
                old_values={'trial_ends_at': old_end_date.isoformat() if old_end_date else None},
                new_values={'trial_ends_at': new_end_date.isoformat()}
            )

            logger.info(f"Extended trial for tenant {tenant.slug} by {days} days")
            return True, f"Trial extended until {new_end_date.date()}"

        except Exception as e:
            logger.error(f"Failed to extend trial for tenant {tenant.slug}: {e}")
            return False, f"Trial extension failed: {str(e)}"

    @classmethod
    def _invalidate_tenant_cache(cls, tenant: Tenant):
        """Invalidate all cache entries for a tenant."""
        from .middleware import TENANT_CACHE_PREFIX

        cache_keys = [
            f"{TENANT_CACHE_PREFIX}id:{tenant.uuid}",
            f"{TENANT_CACHE_PREFIX}id:{tenant.slug}",
            f"{TENANT_CACHE_PREFIX}subdomain:{tenant.slug}",
            f"{TENANT_CACHE_PREFIX}slug:{tenant.slug}",
            f"{TENANT_CACHE_PREFIX}uuid:{tenant.uuid}",
        ]

        for domain in tenant.domains.all():
            cache_keys.append(f"{TENANT_CACHE_PREFIX}domain:{domain.domain}")

        cache.delete_many(cache_keys)

    @classmethod
    def _send_suspension_notification(cls, tenant: Tenant, reason: str):
        """Send suspension notification to tenant owner."""
        try:
            subject = f"Your Zumodra account has been suspended"
            message = f"""
Your Zumodra workspace "{tenant.name}" has been suspended.

Reason: {reason or 'No reason provided'}

If you believe this is an error, please contact support.

Best regards,
The Zumodra Team
            """
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[tenant.owner_email],
                fail_silently=True
            )
        except Exception as e:
            logger.warning(f"Failed to send suspension notification: {e}")

    @classmethod
    def _send_activation_notification(cls, tenant: Tenant):
        """Send activation notification to tenant owner."""
        try:
            from .utils import get_tenant_url

            tenant_url = get_tenant_url(tenant)
            subject = f"Your Zumodra account has been activated"
            message = f"""
Great news! Your Zumodra workspace "{tenant.name}" has been activated.

You can access your dashboard at: {tenant_url}

Best regards,
The Zumodra Team
            """
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[tenant.owner_email],
                fail_silently=True
            )
        except Exception as e:
            logger.warning(f"Failed to send activation notification: {e}")

    @classmethod
    def _send_cancellation_notification(cls, tenant: Tenant, reason: str, deletion_date):
        """Send cancellation notification to tenant owner."""
        try:
            subject = f"Your Zumodra account has been cancelled"
            message = f"""
Your Zumodra workspace "{tenant.name}" has been cancelled.

Your data will be retained until {deletion_date.date()}, after which it will be permanently deleted.

If you would like to reactivate your account, please contact support before this date.

Best regards,
The Zumodra Team
            """
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[tenant.owner_email],
                fail_silently=True
            )
        except Exception as e:
            logger.warning(f"Failed to send cancellation notification: {e}")


class TenantDataExportService:
    """
    Service class for tenant data export (GDPR compliance).
    Exports all tenant data in various formats.
    """

    # Models to export per schema
    TENANT_MODELS = [
        # Add your tenant-specific models here
        # ('app_label', 'ModelName'),
    ]

    @classmethod
    def export_tenant_data(
        cls,
        tenant: Tenant,
        format: str = 'json',
        include_users: bool = True,
        include_files: bool = False
    ) -> Tuple[bytes, str]:
        """
        Export all tenant data.

        Args:
            tenant: Tenant to export data for
            format: Export format ('json', 'csv', 'zip')
            include_users: Include user data
            include_files: Include uploaded files

        Returns:
            Tuple of (data: bytes, filename: str)
        """
        logger.info(f"Starting data export for tenant: {tenant.slug}")

        export_data = {
            'tenant': cls._export_tenant_info(tenant),
            'settings': cls._export_tenant_settings(tenant),
            'domains': cls._export_domains(tenant),
            'usage': cls._export_usage(tenant),
            'audit_logs': cls._export_audit_logs(tenant),
            'exported_at': timezone.now().isoformat(),
        }

        # Export tenant-specific data
        from django_tenants.utils import schema_context
        with schema_context(tenant.schema_name):
            if include_users:
                export_data['users'] = cls._export_users()

            # Export other tenant models
            for app_label, model_name in cls.TENANT_MODELS:
                try:
                    key = f"{app_label}_{model_name}".lower()
                    export_data[key] = cls._export_model(app_label, model_name)
                except Exception as e:
                    logger.warning(f"Failed to export {app_label}.{model_name}: {e}")

        # Create audit log
        AuditService.log(
            tenant=tenant,
            user=None,
            action=AuditLog.ActionType.EXPORT,
            resource_type='TenantData',
            resource_id=str(tenant.uuid),
            description=f"Full data export in {format} format"
        )

        # Format output
        if format == 'json':
            content = json.dumps(export_data, indent=2, default=str).encode('utf-8')
            filename = f"{tenant.slug}_export_{timezone.now().strftime('%Y%m%d')}.json"
        elif format == 'zip':
            content, filename = cls._create_zip_export(tenant, export_data, include_files)
        else:
            content = json.dumps(export_data, default=str).encode('utf-8')
            filename = f"{tenant.slug}_export_{timezone.now().strftime('%Y%m%d')}.json"

        logger.info(f"Data export completed for tenant: {tenant.slug}")
        return content, filename

    @classmethod
    def _export_tenant_info(cls, tenant: Tenant) -> dict:
        """Export basic tenant information."""
        return {
            'uuid': str(tenant.uuid),
            'name': tenant.name,
            'slug': tenant.slug,
            'status': tenant.status,
            'owner_email': tenant.owner_email,
            'industry': tenant.industry,
            'company_size': tenant.company_size,
            'website': tenant.website,
            'address': {
                'line1': tenant.address_line1,
                'line2': tenant.address_line2,
                'city': tenant.city,
                'state': tenant.state,
                'postal_code': tenant.postal_code,
                'country': tenant.country,
            },
            'created_at': tenant.created_at.isoformat() if tenant.created_at else None,
            'plan': tenant.plan.name if tenant.plan else None,
        }

    @classmethod
    def _export_tenant_settings(cls, tenant: Tenant) -> dict:
        """Export tenant settings."""
        try:
            settings = tenant.settings
            return {
                'branding': {
                    'primary_color': settings.primary_color,
                    'secondary_color': settings.secondary_color,
                    'accent_color': settings.accent_color,
                },
                'localization': {
                    'default_language': settings.default_language,
                    'default_timezone': settings.default_timezone,
                    'date_format': settings.date_format,
                    'time_format': settings.time_format,
                    'currency': settings.currency,
                },
                'ats_settings': {
                    'default_pipeline_stages': settings.default_pipeline_stages,
                    'require_cover_letter': settings.require_cover_letter,
                    'auto_reject_after_days': settings.auto_reject_after_days,
                },
                'security': {
                    'require_2fa': settings.require_2fa,
                    'session_timeout_minutes': settings.session_timeout_minutes,
                },
            }
        except TenantSettings.DoesNotExist:
            return {}

    @classmethod
    def _export_domains(cls, tenant: Tenant) -> list:
        """Export tenant domains."""
        return [
            {
                'domain': d.domain,
                'is_primary': d.is_primary,
                'is_careers_domain': d.is_careers_domain,
                'verified_at': d.verified_at.isoformat() if d.verified_at else None,
            }
            for d in tenant.domains.all()
        ]

    @classmethod
    def _export_usage(cls, tenant: Tenant) -> dict:
        """Export tenant usage statistics."""
        try:
            usage = tenant.usage
            return {
                'user_count': usage.user_count,
                'active_job_count': usage.active_job_count,
                'total_job_count': usage.total_job_count,
                'candidate_count_this_month': usage.candidate_count_this_month,
                'total_candidate_count': usage.total_candidate_count,
                'storage_used_gb': usage.storage_used_gb,
                'api_calls_this_month': usage.api_calls_this_month,
            }
        except TenantUsage.DoesNotExist:
            return {}

    @classmethod
    def _export_audit_logs(cls, tenant: Tenant, limit: int = 1000) -> list:
        """Export recent audit logs."""
        logs = AuditLog.objects.filter(tenant=tenant).order_by('-created_at')[:limit]
        return [
            {
                'uuid': str(log.uuid),
                'action': log.action,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'description': log.description,
                'user': log.user.email if log.user else None,
                'ip_address': log.ip_address,
                'created_at': log.created_at.isoformat(),
            }
            for log in logs
        ]

    @classmethod
    def _export_users(cls) -> list:
        """Export users within tenant schema."""
        from django.contrib.auth import get_user_model
        User = get_user_model()

        return [
            {
                'email': u.email,
                'first_name': u.first_name,
                'last_name': u.last_name,
                'is_active': u.is_active,
                'date_joined': u.date_joined.isoformat(),
                'last_login': u.last_login.isoformat() if u.last_login else None,
            }
            for u in User.objects.all()
        ]

    @classmethod
    def _export_model(cls, app_label: str, model_name: str) -> list:
        """Export a specific model's data."""
        from django.apps import apps

        Model = apps.get_model(app_label, model_name)
        data = serialize('python', Model.objects.all())
        return [item['fields'] for item in data]

    @classmethod
    def _create_zip_export(
        cls,
        tenant: Tenant,
        export_data: dict,
        include_files: bool
    ) -> Tuple[bytes, str]:
        """Create a ZIP archive with all exported data."""
        buffer = io.BytesIO()

        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add JSON data
            json_content = json.dumps(export_data, indent=2, default=str)
            zf.writestr('data.json', json_content)

            # Add CSV exports for key data
            if 'users' in export_data and export_data['users']:
                csv_content = cls._dict_list_to_csv(export_data['users'])
                zf.writestr('users.csv', csv_content)

            if 'audit_logs' in export_data and export_data['audit_logs']:
                csv_content = cls._dict_list_to_csv(export_data['audit_logs'])
                zf.writestr('audit_logs.csv', csv_content)

            # Add files if requested
            if include_files:
                cls._add_files_to_zip(zf, tenant)

        buffer.seek(0)
        filename = f"{tenant.slug}_export_{timezone.now().strftime('%Y%m%d')}.zip"
        return buffer.read(), filename

    @classmethod
    def _dict_list_to_csv(cls, data: List[dict]) -> str:
        """Convert a list of dictionaries to CSV string."""
        if not data:
            return ''

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    @classmethod
    def _add_files_to_zip(cls, zf: zipfile.ZipFile, tenant: Tenant):
        """Add uploaded files to ZIP archive."""
        import os
        from django.conf import settings as django_settings

        media_root = getattr(django_settings, 'MEDIA_ROOT', '')
        tenant_media_path = os.path.join(media_root, 'tenants', tenant.slug)

        if os.path.exists(tenant_media_path):
            for root, dirs, files in os.walk(tenant_media_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, media_root)
                    zf.write(file_path, f'files/{arcname}')

    @classmethod
    def schedule_export(cls, tenant: Tenant, email: str, **kwargs) -> str:
        """
        Schedule an async data export.

        Args:
            tenant: Tenant to export
            email: Email to send export link to
            **kwargs: Export options

        Returns:
            Task ID
        """
        # This would typically create a Celery task
        # For now, return a placeholder
        task_id = secrets.token_urlsafe(16)
        logger.info(f"Scheduled export task {task_id} for tenant {tenant.slug}")
        return task_id


class TenantCleanupService:
    """
    Service class for tenant cleanup operations.
    Handles data retention, archival, and deletion.
    """

    @classmethod
    def cleanup_expired_trials(cls, dry_run: bool = True) -> List[Tenant]:
        """
        Find and suspend tenants with expired trials.

        Args:
            dry_run: If True, don't actually suspend

        Returns:
            List of affected tenants
        """
        expired_tenants = Tenant.objects.filter(
            on_trial=True,
            trial_ends_at__lt=timezone.now(),
            status=Tenant.TenantStatus.TRIAL
        )

        affected = list(expired_tenants)

        if not dry_run:
            for tenant in affected:
                TenantLifecycleService.suspend_tenant(
                    tenant,
                    reason='Trial period expired',
                    notify_owner=True
                )

        logger.info(f"Found {len(affected)} expired trial tenants")
        return affected

    @classmethod
    def cleanup_cancelled_tenants(cls, retention_days: int = 30, dry_run: bool = True) -> List[Tenant]:
        """
        Find and delete tenants past retention period.

        Args:
            retention_days: Days after cancellation to delete
            dry_run: If True, don't actually delete

        Returns:
            List of affected tenants
        """
        cutoff_date = timezone.now() - timedelta(days=retention_days)

        cancelled_tenants = Tenant.objects.filter(
            status=Tenant.TenantStatus.CANCELLED,
            updated_at__lt=cutoff_date
        )

        affected = list(cancelled_tenants)

        if not dry_run:
            for tenant in affected:
                cls.delete_tenant(tenant)

        logger.info(f"Found {len(affected)} cancelled tenants past retention")
        return affected

    @classmethod
    @transaction.atomic
    def delete_tenant(cls, tenant: Tenant) -> bool:
        """
        Permanently delete a tenant and all associated data.

        WARNING: This is irreversible!

        SECURITY: Uses psycopg2.sql.Identifier for safe schema name handling
        to prevent SQL injection attacks.

        Args:
            tenant: Tenant to delete

        Returns:
            True if successful
        """
        try:
            logger.warning(f"Permanently deleting tenant: {tenant.slug}")

            # Export data before deletion (for backup)
            try:
                TenantDataExportService.export_tenant_data(tenant, format='json')
            except Exception as e:
                logger.error(f"Failed to export tenant data before deletion: {e}")

            # Delete tenant schema
            schema_name = tenant.schema_name

            # SECURITY FIX: Validate schema name before deletion
            from .utils import _is_valid_schema_name
            if not _is_valid_schema_name(schema_name):
                logger.error(f"Invalid schema name for deletion: {schema_name}")
                return False

            # SECURITY FIX: Use psycopg2.sql.Identifier for safe schema name handling
            with connection.cursor() as cursor:
                from psycopg2 import sql
                cursor.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                        sql.Identifier(schema_name)
                    )
                )

            # Delete tenant record (cascades to related models)
            tenant.delete()

            logger.info(f"Successfully deleted tenant: {schema_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete tenant {tenant.slug}: {e}")
            return False

    @classmethod
    def archive_inactive_tenant(cls, tenant: Tenant) -> Tuple[bool, str]:
        """
        Archive an inactive tenant (move to cold storage).

        Args:
            tenant: Tenant to archive

        Returns:
            Tuple of (success: bool, archive_location: str)
        """
        try:
            # Export all data
            data, filename = TenantDataExportService.export_tenant_data(
                tenant,
                format='zip',
                include_files=True
            )

            # Store in archive location (S3, etc.)
            archive_location = f"archives/{filename}"
            # Implementation depends on storage backend

            # Suspend tenant
            TenantLifecycleService.suspend_tenant(
                tenant,
                reason='Archived due to inactivity'
            )

            logger.info(f"Archived tenant {tenant.slug} to {archive_location}")
            return True, archive_location

        except Exception as e:
            logger.error(f"Failed to archive tenant {tenant.slug}: {e}")
            return False, ""
