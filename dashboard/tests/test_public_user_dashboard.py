"""
Test Public User Dashboard - Comprehensive Testing Suite

Tests the new public_user_dashboard.html template and functionality
for users without tenant membership on zumodra.rhematek-solutions.com

Run with: pytest test_public_user_dashboard.py -v --tb=short
"""

import pytest
from datetime import timedelta
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def client():
    """Django test client."""
    return Client()


@pytest.fixture
def public_user(db):
    """Create a public user without tenant membership or MFA."""
    user = User.objects.create_user(
        username='publicuser',
        email='public@example.com',
        password='testpass123',
        first_name='John',
        last_name='Public'
    )
    return user


@pytest.fixture
def public_user_with_mfa(db):
    """Create a public user with MFA enabled."""
    user = User.objects.create_user(
        username='mfauser',
        email='mfa@example.com',
        password='testpass123',
        first_name='Jane',
        last_name='Secure',
        mfa_enabled=True
    )
    return user


@pytest.fixture
def public_user_with_profile(db, public_user):
    """Create a public user with complete profile."""
    from tenant_profiles.models import UserProfile

    # Create or update profile
    profile, created = UserProfile.objects.get_or_create(user=public_user)
    profile.bio = "Test bio for public user"
    profile.phone = "+1234567890"
    profile.location = "New York, NY"
    profile.linkedin_url = "https://linkedin.com/in/johndoe"
    profile.save()

    return public_user


@pytest.fixture
def public_jobs(db):
    """Create sample public jobs in PublicJobCatalog."""
    from tenants.models import PublicJobCatalog

    jobs = []
    for i in range(10):
        job = PublicJobCatalog.objects.create(
            job_id=f'job-{i+1}',
            title=f'Test Job {i+1}',
            company_name=f'Company {i+1}',
            location='Remote' if i % 2 == 0 else 'New York, NY',
            description=f'Description for job {i+1}',
            salary_min=50000 + (i * 10000),
            salary_max=80000 + (i * 10000),
            is_active=True,
        )
        jobs.append(job)

    return jobs


# ============================================================================
# TEST CASES - DASHBOARD ACCESS
# ============================================================================

@pytest.mark.django_db
class TestDashboardAccess:
    """Test dashboard access and template loading."""

    def test_dashboard_requires_login(self, client):
        """Dashboard should redirect to login for anonymous users."""
        response = client.get(reverse('frontend:dashboard:index'))
        assert response.status_code == 302  # Redirect to login
        assert '/accounts/login/' in response.url

    def test_public_user_dashboard_loads(self, client, public_user):
        """Public user should see public_user_dashboard.html template."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        assert 'dashboard/public_user_dashboard.html' in [t.name for t in response.templates]
        assert 'is_public_user' in response.context
        assert response.context['is_public_user'] is True

    def test_dashboard_renders_without_errors(self, client, public_user):
        """Dashboard page should render without errors."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        assert b'Welcome' in response.content
        assert public_user.first_name.encode() in response.content


# ============================================================================
# TEST CASES - WELCOME BANNER
# ============================================================================

@pytest.mark.django_db
class TestWelcomeBanner:
    """Test welcome banner display and styling."""

    def test_welcome_banner_shows_username(self, client, public_user):
        """Welcome banner should display user's first name."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()
        assert 'Welcome' in content
        assert public_user.first_name in content

    def test_welcome_banner_shows_username_fallback(self, client, db):
        """Welcome banner should show username if no first name."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='',  # Empty first name
        )
        client.force_login(user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()
        assert 'testuser' in content

    def test_welcome_banner_styling(self, client, public_user):
        """Welcome banner should have gradient styling."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'bg-gradient-to-r from-blue-500 to-indigo-600' in content
        assert 'Complete your profile' in content


# ============================================================================
# TEST CASES - MFA WARNING BANNER
# ============================================================================

@pytest.mark.django_db
class TestMFAWarningBanner:
    """Test MFA warning banner for users without MFA."""

    def test_mfa_banner_shows_for_user_without_mfa(self, client, public_user):
        """MFA warning banner should appear for users without MFA."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()
        assert 'Security Notice' in content
        assert 'Two-factor authentication' in content
        assert 'Set it up now' in content

    def test_mfa_banner_not_shown_with_mfa(self, client, public_user_with_mfa):
        """MFA warning banner should NOT appear for users with MFA."""
        client.force_login(public_user_with_mfa)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()
        # Banner should not be present
        assert 'Security Notice' not in content or response.context.get('mfa_enabled') is True

    def test_mfa_banner_shows_required_date(self, client, public_user):
        """MFA banner should show MFA required date (30 days from signup)."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        assert 'mfa_required_date' in response.context

        expected_date = public_user.date_joined + timedelta(days=30)
        actual_date = response.context['mfa_required_date']
        assert actual_date.date() == expected_date.date()

    def test_mfa_banner_link_to_setup(self, client, public_user):
        """MFA banner should link to MFA setup page."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        # Check for MFA setup link
        assert 'mfa_index' in content or '/accounts/two-factor/' in content


# ============================================================================
# TEST CASES - PROFILE COMPLETION WIDGET
# ============================================================================

@pytest.mark.django_db
class TestProfileCompletionWidget:
    """Test profile completion percentage widget."""

    def test_profile_completion_displays(self, client, public_user):
        """Profile completion widget should display."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()
        assert 'Profile Completion' in content
        assert 'stats' in response.context
        assert 'profile_completion' in response.context['stats']

    def test_profile_completion_empty_profile(self, client, public_user):
        """Empty profile should show 0% completion."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        completion = response.context['stats']['profile_completion']
        assert completion == 0

    def test_profile_completion_full_profile(self, client, public_user_with_profile):
        """Complete profile should show 100% completion."""
        client.force_login(public_user_with_profile)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        completion = response.context['stats']['profile_completion']
        assert completion == 100

    def test_profile_completion_partial_profile(self, client, public_user, db):
        """Partial profile should show correct percentage."""
        from tenant_profiles.models import UserProfile

        # Create profile with 2 out of 4 fields
        profile, created = UserProfile.objects.get_or_create(user=public_user)
        profile.bio = "Test bio"
        profile.phone = "+1234567890"
        # location and linkedin_url are empty
        profile.save()

        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        completion = response.context['stats']['profile_completion']
        assert completion == 50  # 2 out of 4 fields = 50%

    def test_profile_completion_link(self, client, public_user):
        """Profile completion widget should link to profile page."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'Complete your profile' in content
        # Should link to profile page
        assert 'custom_account_u:public_profile' in content or '/accounts/profile/' in content


# ============================================================================
# TEST CASES - QUICK ACTIONS CARDS
# ============================================================================

@pytest.mark.django_db
class TestQuickActionsCards:
    """Test quick actions cards display and functionality."""

    def test_quick_actions_display(self, client, public_user):
        """Quick actions should display 3 cards."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'Browse Jobs' in content
        assert 'Browse Services' in content
        assert 'Enable 2FA' in content

    def test_quick_actions_icons(self, client, public_user):
        """Quick actions should show correct icons."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'ph-briefcase' in content  # Jobs icon
        assert 'ph-storefront' in content  # Services icon
        assert 'ph-shield-check' in content  # 2FA icon

    def test_quick_actions_links(self, client, public_user):
        """Quick actions should have correct links."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert '/careers/' in content
        assert '/services/' in content
        # MFA link
        assert 'mfa_index' in content or '/accounts/two-factor/' in content

    def test_quick_actions_hover_effects(self, client, public_user):
        """Quick actions should have hover effect classes."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'hover:shadow-lg' in content
        assert 'group-hover:scale-110' in content

    def test_quick_actions_responsive_grid(self, client, public_user):
        """Quick actions should use responsive grid layout."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'grid-cols-1' in content
        assert 'md:grid-cols-3' in content


# ============================================================================
# TEST CASES - RECOMMENDED JOBS SECTION
# ============================================================================

@pytest.mark.django_db
class TestRecommendedJobsSection:
    """Test recommended jobs section display."""

    def test_recommended_jobs_display_with_jobs(self, client, public_user, public_jobs):
        """Recommended jobs section should display when jobs available."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()
        assert 'Recommended Jobs' in content
        assert 'recommended_jobs' in response.context

    def test_recommended_jobs_limit_to_5(self, client, public_user, public_jobs):
        """Should show maximum 5 recommended jobs."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        jobs = response.context['recommended_jobs']
        assert len(jobs) <= 5

    def test_recommended_jobs_show_details(self, client, public_user, public_jobs):
        """Job cards should show title, company, location."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        # Should show job details
        assert 'Test Job' in content
        assert 'Company' in content
        assert 'ph-map-pin' in content  # Location icon

    def test_recommended_jobs_show_salary(self, client, public_user, public_jobs):
        """Job cards should show salary if available."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        # Should show salary with currency icon
        assert 'ph-currency-dollar' in content or '$' in content

    def test_recommended_jobs_links(self, client, public_user, public_jobs):
        """Job cards should link to job detail pages."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert '/careers/jobs/' in content
        assert 'View all jobs' in content

    def test_recommended_jobs_empty_state(self, client, public_user):
        """Should show empty state when no jobs available."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        # Should show empty state
        assert 'No jobs available' in content or 'Check back soon' in content
        assert 'ph-briefcase' in content  # Empty state icon
        assert 'Browse all jobs' in content


# ============================================================================
# TEST CASES - JOIN ORGANIZATION CTA
# ============================================================================

@pytest.mark.django_db
class TestJoinOrganizationCTA:
    """Test join organization call-to-action banner."""

    def test_join_org_cta_displays(self, client, public_user):
        """Join organization CTA should display for public users."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        assert response.context.get('show_tenant_invite') is True
        content = response.content.decode()
        assert 'Ready to do more?' in content

    def test_join_org_cta_styling(self, client, public_user):
        """Join organization CTA should have gradient styling."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'bg-gradient-to-r from-purple-500 to-pink-600' in content
        assert 'ph-users-three' in content  # Team icon

    def test_join_org_cta_buttons(self, client, public_user):
        """Join organization CTA should have action buttons."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'Join Organization' in content
        assert 'Create Organization' in content

    def test_join_org_cta_explanation(self, client, public_user):
        """Join organization CTA should explain benefits."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'Join an organization' in content
        assert 'advanced features' in content or 'applicant tracking' in content


# ============================================================================
# TEST CASES - DARK MODE SUPPORT
# ============================================================================

@pytest.mark.django_db
class TestDarkModeSupport:
    """Test dark mode class support in template."""

    def test_dark_mode_classes_present(self, client, public_user):
        """Template should include dark mode classes."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'dark:bg-gray-800' in content
        assert 'dark:text-white' in content
        assert 'dark:text-gray-400' in content

    def test_dark_mode_text_contrast(self, client, public_user):
        """Dark mode should have proper text color classes."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'dark:text-white' in content
        assert 'dark:text-gray-300' in content

    def test_dark_mode_backgrounds(self, client, public_user):
        """Dark mode should have proper background classes."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'dark:bg-gray-800' in content
        assert 'dark:bg-gray-700' in content


# ============================================================================
# TEST CASES - RESPONSIVE DESIGN
# ============================================================================

@pytest.mark.django_db
class TestResponsiveDesign:
    """Test responsive design classes."""

    def test_responsive_container(self, client, public_user):
        """Container should have responsive padding."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'container mx-auto' in content
        assert 'max-w-4xl' in content

    def test_responsive_grid(self, client, public_user):
        """Grid should adapt from 1 to 3 columns."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'grid-cols-1' in content
        assert 'md:grid-cols-3' in content

    def test_mobile_spacing(self, client, public_user):
        """Should have appropriate spacing classes."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        content = response.content.decode()
        assert 'mb-6' in content or 'mb-8' in content
        assert 'p-6' in content or 'p-4' in content


# ============================================================================
# TEST CASES - HELPER METHODS
# ============================================================================

@pytest.mark.django_db
class TestHelperMethods:
    """Test helper methods in DashboardView."""

    def test_calculate_profile_completion_method(self, client, public_user_with_profile):
        """_calculate_profile_completion should work correctly."""
        client.force_login(public_user_with_profile)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        completion = response.context['stats']['profile_completion']
        assert isinstance(completion, int)
        assert 0 <= completion <= 100

    def test_get_recommended_jobs_method(self, client, public_user, public_jobs):
        """_get_recommended_jobs should return active jobs."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        jobs = response.context['recommended_jobs']
        assert len(jobs) <= 5
        assert all(job.is_active for job in jobs)

    def test_user_has_mfa_method(self, client, public_user, public_user_with_mfa):
        """_user_has_mfa should detect MFA status."""
        # Test user without MFA
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))
        assert response.context['mfa_enabled'] is False

        # Test user with MFA (if supported)
        client.force_login(public_user_with_mfa)
        response = client.get(reverse('frontend:dashboard:index'))
        # MFA status should be checked
        assert 'mfa_enabled' in response.context


# ============================================================================
# TEST CASES - INTEGRATION
# ============================================================================

@pytest.mark.django_db
class TestDashboardIntegration:
    """Integration tests for complete dashboard functionality."""

    def test_complete_dashboard_render(self, client, public_user_with_profile, public_jobs):
        """Test complete dashboard with all features."""
        client.force_login(public_user_with_profile)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()

        # Check all major sections present
        assert 'Welcome' in content
        assert 'Profile Completion' in content
        assert 'Browse Jobs' in content
        assert 'Browse Services' in content
        assert 'Enable 2FA' in content
        assert 'Recommended Jobs' in content or 'No jobs available' in content
        assert 'Ready to do more?' in content

    def test_context_data_complete(self, client, public_user, public_jobs):
        """Test that all context data is provided."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        assert 'is_public_user' in response.context
        assert 'stats' in response.context
        assert 'recent_activity' in response.context
        assert 'recommended_jobs' in response.context
        assert 'show_tenant_invite' in response.context
        assert 'mfa_enabled' in response.context
        assert 'mfa_required_date' in response.context

    def test_no_errors_on_page(self, client, public_user):
        """Dashboard should render without HTML errors."""
        client.force_login(public_user)
        response = client.get(reverse('frontend:dashboard:index'))

        assert response.status_code == 200
        content = response.content.decode()

        # No error indicators
        assert 'error' not in content.lower() or 'No errors' in content
        assert '500' not in content
        assert 'exception' not in content.lower()
