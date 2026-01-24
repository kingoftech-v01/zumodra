"""
Waitlist Views - Platform Launch Countdown

Provides:
- WaitlistCountdownView: Displays countdown page to waitlisted users
- WaitlistStatusAPIView: JSON API for live countdown updates
"""

from django.views.generic import TemplateView
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from core_identity.models import PlatformLaunch, CustomUser


class WaitlistCountdownView(LoginRequiredMixin, TemplateView):
    """
    Display countdown page to waitlisted users.

    Shows:
    - Days/hours/minutes until launch
    - User's waitlist position
    - Total number of early adopters
    - What to expect after launch
    """
    template_name = 'core_identity/waitlist_countdown.html'

    def dispatch(self, request, *args, **kwargs):
        """Redirect non-waitlisted users to dashboard."""
        # If user is not waitlisted, they shouldn't see this page
        if not request.user.is_waitlisted:
            return redirect(reverse('frontend:dashboard:index'))

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get launch configuration
        launch_config = PlatformLaunch.get_config()

        # Add launch information
        context['launch_date'] = launch_config.launch_date
        context['time_until_launch'] = launch_config.time_until_launch
        context['waitlist_message'] = launch_config.waitlist_message
        context['is_launched'] = launch_config.is_platform_launched

        # Add user waitlist information
        context['waitlist_position'] = self.request.user.waitlist_position
        context['waitlist_joined_at'] = self.request.user.waitlist_joined_at

        # Get total waitlist count
        context['total_waitlist_users'] = CustomUser.objects.filter(
            is_waitlisted=True
        ).count()

        # Calculate progress percentage if position is available
        if self.request.user.waitlist_position and context['total_waitlist_users'] > 0:
            context['progress_percentage'] = int(
                (self.request.user.waitlist_position / context['total_waitlist_users']) * 100
            )
        else:
            context['progress_percentage'] = 0

        return context


class WaitlistStatusAPIView(LoginRequiredMixin, View):
    """
    API endpoint to check waitlist status.

    Returns JSON with:
    - is_waitlisted: Whether user is still on waitlist
    - is_launched: Whether platform has launched
    - time_until_launch: Remaining time breakdown
    - launch_date: ISO format launch date

    Used for:
    - Live countdown updates (JavaScript polling)
    - Automatic redirect when platform launches
    """

    def get(self, request):
        """Return current waitlist status."""
        launch_config = PlatformLaunch.get_config()

        data = {
            'is_waitlisted': request.user.is_waitlisted,
            'is_launched': launch_config.is_platform_launched,
            'waitlist_enabled': launch_config.waitlist_enabled,
            'time_until_launch': launch_config.time_until_launch,
            'launch_date': launch_config.launch_date.isoformat() if launch_config.launch_date else None,
            'waitlist_position': request.user.waitlist_position,
        }

        return JsonResponse(data)
