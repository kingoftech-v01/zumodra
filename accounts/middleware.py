"""
MFA Enforcement Middleware

Enforces Two-Factor Authentication after a grace period (30 days).
Allows new users time to set up MFA while ensuring long-term security.

Author: Rhematek Solutions
"""

from django.shortcuts import redirect
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.urls import reverse


class MFAEnforcementMiddleware:
    """
    Enforce MFA setup after 30-day grace period.

    This middleware ensures that all users set up two-factor authentication
    within 30 days of account creation. It provides a grace period for new
    users to familiarize themselves with the platform before requiring MFA.

    Exempt URLs:
    - /accounts/two-factor/ (MFA setup pages)
    - /accounts/logout/
    - /static/, /media/
    - /api/ (uses JWT, not sessions)
    - /health/ (health checks)

    Grace Period: 30 days from account creation
    Reminder: Shows info message 7 days before MFA becomes required
    """

    EXEMPT_PATHS = [
        '/accounts/two-factor/',
        '/accounts/mfa/',
        '/accounts/logout/',
        '/accounts/password/reset/',
        '/static/',
        '/media/',
        '/api/',
        '/health/',
        '/.well-known/',
    ]

    GRACE_PERIOD_DAYS = 30
    REMINDER_DAYS = 7  # Show reminder when X days remaining

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only check authenticated users
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Skip exempt paths
        if any(request.path.startswith(path) for path in self.EXEMPT_PATHS):
            return self.get_response(request)

        # Skip for superusers (admins need emergency access)
        if request.user.is_superuser:
            return self.get_response(request)

        # Check if user has MFA enabled
        if self._user_has_mfa(request.user):
            return self.get_response(request)

        # Check if grace period has expired
        if self._grace_period_expired(request.user):
            messages.warning(
                request,
                'Two-factor authentication is required for your account security. '
                'Please set it up now to continue using the platform.'
            )
            # Redirect to MFA setup page
            try:
                return redirect('mfa_index')
            except Exception:
                # Fallback if mfa_index URL not found
                return redirect('/accounts/two-factor/')

        # Grace period active - show reminder if close to deadline
        days_remaining = self._days_until_mfa_required(request.user)
        if days_remaining <= self.REMINDER_DAYS:
            # Only show reminder once per session to avoid annoyance
            session_key = f'mfa_reminder_shown_{request.user.id}'
            if not request.session.get(session_key):
                messages.info(
                    request,
                    f'Please set up two-factor authentication. '
                    f'It will be required in {days_remaining} day{"s" if days_remaining != 1 else ""}.'
                )
                request.session[session_key] = True

        return self.get_response(request)

    def _user_has_mfa(self, user):
        """
        Check if user has any MFA method enabled.

        Supports django-allauth MFA (TOTP and WebAuthn).
        """
        try:
            # Check for allauth MFA authenticators
            if hasattr(user, 'mfa_authenticators'):
                return user.mfa_authenticators.filter(is_active=True).exists()
        except Exception:
            pass

        return False

    def _grace_period_expired(self, user):
        """
        Check if 30-day grace period has expired.

        Returns:
            bool: True if user has exceeded the grace period, False otherwise
        """
        if not user.date_joined:
            # Safety check - if no date_joined, don't enforce
            return False

        cutoff_date = timezone.now() - timedelta(days=self.GRACE_PERIOD_DAYS)
        return user.date_joined < cutoff_date

    def _days_until_mfa_required(self, user):
        """
        Calculate days remaining in grace period.

        Returns:
            int: Number of days until MFA is required (minimum 0)
        """
        if not user.date_joined:
            return self.GRACE_PERIOD_DAYS

        required_date = user.date_joined + timedelta(days=self.GRACE_PERIOD_DAYS)
        delta = required_date - timezone.now()
        return max(0, delta.days)
