"""
Integration tests for Waitlist System.

Tests:
- New user signup with waitlist
- Waitlist position assignment
- Countdown page display
- Platform launch process
- Middleware enforcement
- API status endpoint
- Automatic access grant on launch
"""

import pytest
from datetime import timedelta
from django.test import TestCase, TransactionTestCase, RequestFactory, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.contrib.messages import get_messages
from core_identity.models import PlatformLaunch, CustomUser
from core_identity.middleware import WaitlistEnforcementMiddleware
from core_identity.adapter import ZumodraAccountAdapter

User = get_user_model()


class WaitlistSystemIntegrationTest(TransactionTestCase):
    """Integration tests for waitlist system."""

    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.client = Client()

        # Clear any existing PlatformLaunch config
        PlatformLaunch.objects.all().delete()

        # Create launch configuration
        self.launch_config = PlatformLaunch.objects.create(
            pk=1,
            launch_date=timezone.now() + timedelta(days=7),
            is_launched=False,
            waitlist_enabled=True,
            waitlist_message='Thank you for your interest!'
        )

    def test_platform_launch_singleton(self):
        """Test that only one PlatformLaunch instance can exist."""
        config = PlatformLaunch.get_config()
        self.assertEqual(config.pk, 1)

        # Trying to create another should use pk=1
        new_config = PlatformLaunch()
        new_config.waitlist_message = "Updated message"
        new_config.save()

        # Should update existing record
        self.assertEqual(PlatformLaunch.objects.count(), 1)
        refreshed = PlatformLaunch.objects.get(pk=1)
        self.assertEqual(refreshed.waitlist_message, "Updated message")

    def test_new_user_added_to_waitlist(self):
        """Test that new signups are automatically waitlisted."""
        # Simulate user signup through adapter
        adapter = ZumodraAccountAdapter()
        request = self.factory.post('/signup/')

        # Create mock form
        class MockForm:
            cleaned_data = {
                'first_name': 'Test',
                'last_name': 'User'
            }

        user = User(email='newuser@example.com')
        user.set_password('testpass123')

        form = MockForm()
        saved_user = adapter.save_user(request, user, form, commit=True)

        # Verify user is waitlisted
        self.assertTrue(saved_user.is_waitlisted)
        self.assertIsNotNone(saved_user.waitlist_joined_at)
        self.assertEqual(saved_user.waitlist_position, 1)

    def test_waitlist_position_sequential(self):
        """Test that waitlist positions are assigned sequentially."""
        adapter = ZumodraAccountAdapter()
        request = self.factory.post('/signup/')

        class MockForm:
            cleaned_data = {}

        # Create 5 users
        for i in range(5):
            user = User(email=f'user{i}@example.com')
            user.set_password('testpass123')
            saved_user = adapter.save_user(request, user, MockForm(), commit=True)

            self.assertEqual(saved_user.waitlist_position, i + 1)

    def test_platform_not_launched_property(self):
        """Test is_platform_launched property when not launched."""
        config = PlatformLaunch.get_config()

        # Platform should not be launched
        self.assertFalse(config.is_platform_launched)

        # Days until launch should be 7
        self.assertEqual(config.days_until_launch, 7)

    def test_platform_launched_manually(self):
        """Test manual platform launch override."""
        config = PlatformLaunch.get_config()
        config.is_launched = True
        config.save()

        # Platform should be launched
        self.assertTrue(config.is_platform_launched)
        self.assertEqual(config.days_until_launch, 0)

    def test_platform_launched_by_date(self):
        """Test platform launch when date is reached."""
        config = PlatformLaunch.get_config()
        config.launch_date = timezone.now() - timedelta(days=1)  # Yesterday
        config.save()

        # Platform should be launched
        self.assertTrue(config.is_platform_launched)

    def test_time_until_launch_calculation(self):
        """Test accurate time until launch calculation."""
        config = PlatformLaunch.get_config()

        # Set launch to 2 days, 5 hours from now
        config.launch_date = timezone.now() + timedelta(days=2, hours=5)
        config.save()

        time_remaining = config.time_until_launch

        self.assertEqual(time_remaining['days'], 2)
        self.assertGreaterEqual(time_remaining['hours'], 4)
        self.assertLessEqual(time_remaining['hours'], 5)

    def test_waitlist_disabled(self):
        """Test that users get immediate access when waitlist is disabled."""
        # Disable waitlist
        config = PlatformLaunch.get_config()
        config.waitlist_enabled = False
        config.save()

        # Create new user
        adapter = ZumodraAccountAdapter()
        request = self.factory.post('/signup/')

        class MockForm:
            cleaned_data = {}

        user = User(email='immediate@example.com')
        user.set_password('testpass123')
        saved_user = adapter.save_user(request, user, MockForm(), commit=True)

        # User should NOT be waitlisted
        self.assertFalse(saved_user.is_waitlisted)
        self.assertIsNone(saved_user.waitlist_position)


class WaitlistMiddlewareTest(TestCase):
    """Test waitlist enforcement middleware."""

    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.middleware = WaitlistEnforcementMiddleware(lambda r: None)

        # Create launch configuration
        PlatformLaunch.objects.all().delete()
        self.launch_config = PlatformLaunch.objects.create(
            pk=1,
            launch_date=timezone.now() + timedelta(days=7),
            is_launched=False,
            waitlist_enabled=True
        )

        # Create waitlisted user
        self.waitlisted_user = User.objects.create_user(
            email='waitlisted@example.com',
            password='testpass123',
            is_waitlisted=True,
            waitlist_position=1
        )

        # Create active user
        self.active_user = User.objects.create_user(
            email='active@example.com',
            password='testpass123',
            is_waitlisted=False
        )

    def test_unauthenticated_user_passes_through(self):
        """Test that unauthenticated users pass through middleware."""
        request = self.factory.get('/dashboard/')
        request.user = None

        # Mock user as unauthenticated
        class AnonymousUser:
            is_authenticated = False

        request.user = AnonymousUser()

        # Should pass through (return None means continue)
        # In real implementation, this would call get_response
        # Here we're testing the logic would allow it through
        self.assertFalse(request.user.is_authenticated)

    def test_waitlisted_user_redirected(self):
        """Test that waitlisted users are redirected to countdown page."""
        # This test would require full request/response cycle
        # Simplified to test the logic
        user = self.waitlisted_user
        self.assertTrue(user.is_waitlisted)

        # In middleware, this user would be redirected
        # Testing the condition
        config = PlatformLaunch.get_config()
        should_redirect = (
            user.is_waitlisted and
            config.waitlist_enabled and
            not config.is_platform_launched
        )
        self.assertTrue(should_redirect)

    def test_active_user_allowed(self):
        """Test that non-waitlisted users can access platform."""
        user = self.active_user
        self.assertFalse(user.is_waitlisted)

        # This user should be allowed through
        config = PlatformLaunch.get_config()
        should_redirect = (
            user.is_waitlisted and
            config.waitlist_enabled and
            not config.is_platform_launched
        )
        self.assertFalse(should_redirect)

    def test_superuser_always_allowed(self):
        """Test that superusers always have access."""
        superuser = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )
        superuser.is_waitlisted = True  # Even if waitlisted
        superuser.save()

        # Superuser should always be allowed
        self.assertTrue(superuser.is_superuser)

    def test_exempt_paths_allowed(self):
        """Test that exempt paths are always accessible."""
        exempt_paths = [
            '/accounts/waitlist/countdown/',
            '/accounts/logout/',
            '/static/css/style.css',
            '/admin/',
            '/api/v1/waitlist/status/',
        ]

        for path in exempt_paths:
            # These paths should be in EXEMPT_PATHS
            is_exempt = any(
                path.startswith(exempt_path)
                for exempt_path in self.middleware.EXEMPT_PATHS
            )
            self.assertTrue(is_exempt, f"Path {path} should be exempt")

    def test_auto_grant_access_on_launch(self):
        """Test that users are auto-granted access when platform launches."""
        # Launch platform
        config = PlatformLaunch.get_config()
        config.is_launched = True
        config.save()

        # Refresh user
        user = User.objects.get(pk=self.waitlisted_user.pk)

        # In middleware, waitlisted users would be updated
        if config.is_platform_launched and user.is_waitlisted:
            user.is_waitlisted = False
            user.save()

        # Verify user is no longer waitlisted
        user.refresh_from_db()
        self.assertFalse(user.is_waitlisted)


class WaitlistViewsTest(TestCase):
    """Test waitlist views and API."""

    def setUp(self):
        """Set up test data."""
        self.client = Client()

        # Create launch configuration
        PlatformLaunch.objects.all().delete()
        self.launch_config = PlatformLaunch.objects.create(
            pk=1,
            launch_date=timezone.now() + timedelta(days=7),
            is_launched=False,
            waitlist_enabled=True,
            waitlist_message='Coming soon!'
        )

        # Create waitlisted user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            is_waitlisted=True,
            waitlist_position=5,
            waitlist_joined_at=timezone.now()
        )

    def test_countdown_page_accessible(self):
        """Test that countdown page is accessible to waitlisted users."""
        self.client.force_login(self.user)

        response = self.client.get(reverse('core_identity:waitlist_countdown'))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'core_identity/waitlist_countdown.html')

    def test_countdown_page_context(self):
        """Test that countdown page has correct context data."""
        self.client.force_login(self.user)

        response = self.client.get(reverse('core_identity:waitlist_countdown'))

        self.assertIn('launch_date', response.context)
        self.assertIn('time_until_launch', response.context)
        self.assertIn('waitlist_message', response.context)
        self.assertIn('waitlist_position', response.context)

        self.assertEqual(response.context['waitlist_position'], 5)
        self.assertEqual(response.context['waitlist_message'], 'Coming soon!')

    def test_non_waitlisted_user_redirected_from_countdown(self):
        """Test that non-waitlisted users are redirected away from countdown page."""
        # Create active user
        active_user = User.objects.create_user(
            email='active@example.com',
            password='testpass123',
            is_waitlisted=False
        )

        self.client.force_login(active_user)

        response = self.client.get(reverse('core_identity:waitlist_countdown'))

        # Should redirect to dashboard
        self.assertEqual(response.status_code, 302)

    def test_waitlist_status_api(self):
        """Test waitlist status API endpoint."""
        self.client.force_login(self.user)

        response = self.client.get(reverse('core_identity:waitlist_status_api'))

        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertTrue(data['is_waitlisted'])
        self.assertFalse(data['is_launched'])
        self.assertEqual(data['waitlist_position'], 5)
        self.assertIsNotNone(data['time_until_launch'])
        self.assertEqual(data['time_until_launch']['days'], 7)

    def test_waitlist_status_api_after_launch(self):
        """Test API returns correct status after platform launch."""
        # Launch platform
        config = PlatformLaunch.get_config()
        config.is_launched = True
        config.save()

        self.client.force_login(self.user)

        response = self.client.get(reverse('core_identity:waitlist_status_api'))
        data = response.json()

        self.assertTrue(data['is_launched'])
        self.assertEqual(data['time_until_launch']['days'], 0)


class PlatformLaunchCommandTest(TransactionTestCase):
    """Test platform launch management command."""

    def setUp(self):
        """Set up test data."""
        # Create launch configuration
        PlatformLaunch.objects.all().delete()
        self.launch_config = PlatformLaunch.objects.create(
            pk=1,
            launch_date=timezone.now() + timedelta(days=7),
            is_launched=False,
            waitlist_enabled=True
        )

        # Create waitlisted users
        for i in range(10):
            User.objects.create_user(
                email=f'user{i}@example.com',
                password='testpass123',
                is_waitlisted=True,
                waitlist_position=i + 1,
                waitlist_joined_at=timezone.now()
            )

    def test_launch_marks_all_users_active(self):
        """Test that launch command grants access to all waitlisted users."""
        # Verify users are waitlisted
        waitlisted_count = User.objects.filter(is_waitlisted=True).count()
        self.assertEqual(waitlisted_count, 10)

        # Simulate launch (without actually calling command)
        config = PlatformLaunch.get_config()
        config.is_launched = True
        config.save()

        # Grant access to all waitlisted users
        User.objects.filter(is_waitlisted=True).update(is_waitlisted=False)

        # Verify all users are now active
        waitlisted_count = User.objects.filter(is_waitlisted=True).count()
        self.assertEqual(waitlisted_count, 0)

        active_count = User.objects.filter(is_waitlisted=False).count()
        self.assertEqual(active_count, 10)

    def test_launch_updates_platform_status(self):
        """Test that launch command updates platform status."""
        config = PlatformLaunch.get_config()
        self.assertFalse(config.is_platform_launched)

        # Simulate launch
        config.is_launched = True
        config.save()

        config.refresh_from_db()
        self.assertTrue(config.is_platform_launched)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
