"""
Signal handlers for core_identity app.

Auto-creates UserIdentity when CustomUser is created.
MarketplaceProfile is NOT auto-created - user must explicitly activate it.

Author: Zumodra Team
Date: 2026-01-17
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from .models import UserIdentity


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_identity(sender, instance, created, **kwargs):
    """
    Automatically create UserIdentity when a new CustomUser is created.

    UserIdentity is ALWAYS created for every user.
    MarketplaceProfile is NOT auto-created - user must opt-in via activation.
    """
    if created:
        # Generate display_name from user's name or email
        display_name = f"{instance.first_name} {instance.last_name}".strip()
        if not display_name:
            display_name = instance.email.split('@')[0]  # Use email username

        UserIdentity.objects.get_or_create(
            user=instance,
            defaults={
                'display_name': display_name,
            }
        )


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def update_user_identity_display_name(sender, instance, **kwargs):
    """
    Update UserIdentity display_name when CustomUser's name changes.

    Only updates if user has changed their first_name or last_name.
    """
    if hasattr(instance, 'identity'):
        # Update display_name if user's name changed
        new_display_name = f"{instance.first_name} {instance.last_name}".strip()

        # Only update if we have a valid new name and it's different
        if new_display_name and instance.identity.display_name != new_display_name:
            instance.identity.display_name = new_display_name
            instance.identity.save(update_fields=['display_name', 'updated_at'])


# ==================== POST-SIGNUP ROUTING ====================

from allauth.account.signals import user_signed_up
import logging

logger = logging.getLogger(__name__)


@receiver(user_signed_up)
def handle_post_signup_routing(sender, request, user, **kwargs):
    """
    Route user to appropriate setup flow based on selected type.

    User Types:
    - 'public': Free user, browse/apply to jobs (no tenant)
    - 'company': Organization needing tenant workspace (paid)
    - 'freelancer': Marketplace provider needing tenant + Stripe Connect (paid)

    The user_type is stored in session during signup form submission.
    """
    user_type = request.session.get('selected_user_type', 'public')

    logger.info(f"User {user.email} signed up as type: {user_type}")

    # Store in session for next view (will be used by redirect)
    request.session['post_signup_user_type'] = user_type
    request.session['post_signup_complete'] = False

    # Signal handled - actual redirect happens in custom allauth adapter
    # See core_identity/adapter.py get_signup_redirect_url()
