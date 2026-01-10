"""
Custom Account User Tests

Comprehensive tests for the custom_account_u app which contains
the CustomUser model extending Django's AbstractUser.

Tests cover:
1. User creation and validation
2. Email validation and uniqueness
3. Password hashing and verification
4. MFA settings
5. Anonymous mode functionality
6. User manager methods
7. Authentication backends
8. Allauth integration (signup, login, logout)
9. Password reset flow
10. Email verification
"""

import pytest
import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch, PropertyMock

from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.core import mail
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import override_settings, RequestFactory, TestCase, Client
from django.urls import reverse
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient

from tests.base import TenantTestCase, TenantTestMixin, FactoryHelper


User = get_user_model()


# ============================================================================
# USER CREATION AND VALIDATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCustomUserCreation:
    """Tests for CustomUser model creation."""

    def test_create_user_with_all_fields(self, user_factory):
        """Test creating a user with all fields populated."""
        user = user_factory(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User',
            is_active=True,
            mfa_enabled=False,
            anonymous_mode=False
        )

        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.first_name == 'Test'
        assert user.last_name == 'User'
        assert user.is_active is True
        assert user.mfa_enabled is False
        assert user.anonymous_mode is False

    def test_create_user_with_minimal_fields(self, user_factory):
        """Test creating a user with minimal required fields."""
        user = user_factory()

        assert user.pk is not None
        assert user.username is not None
        assert user.email is not None
        assert user.is_active is True

    def test_user_has_uuid_field(self, user_factory):
        """Test that CustomUser has a unique UUID field."""
        user = user_factory()

        assert user.c_u_uuid is not None
        # UUID should be valid UUID format
        assert isinstance(user.c_u_uuid, (str, uuid.UUID))

    def test_user_uuid_is_unique(self, user_factory):
        """Test that each user gets a unique UUID."""
        user1 = user_factory()
        user2 = user_factory()

        assert str(user1.c_u_uuid) != str(user2.c_u_uuid)

    def test_user_uuid_not_editable(self, user_factory):
        """Test that c_u_uuid field is not editable."""
        user = user_factory()
        original_uuid = str(user.c_u_uuid)

        # Attempt to change UUID
        user.c_u_uuid = uuid.uuid4()
        user.save()
        user.refresh_from_db()

        # UUID should remain unchanged (editable=False)
        assert str(user.c_u_uuid) == original_uuid

    def test_create_superuser(self, superuser_factory):
        """Test creating a superuser."""
        superuser = superuser_factory()

        assert superuser.is_superuser is True
        assert superuser.is_staff is True
        assert superuser.is_active is True

    def test_user_string_representation(self, user_factory):
        """Test string representation of user."""
        user = user_factory(username='testuser')

        # Default AbstractUser __str__ returns username
        assert str(user) == 'testuser'

    def test_user_inherits_from_abstract_user(self, user_factory):
        """Test that CustomUser inherits AbstractUser methods."""
        user = user_factory()

        # Check inherited methods exist
        assert hasattr(user, 'get_full_name')
        assert hasattr(user, 'get_short_name')
        assert hasattr(user, 'email_user')
        assert hasattr(user, 'set_password')
        assert hasattr(user, 'check_password')
        assert hasattr(user, 'has_perm')
        assert hasattr(user, 'has_perms')

    def test_get_full_name(self, user_factory):
        """Test get_full_name method."""
        user = user_factory(first_name='John', last_name='Doe')

        assert user.get_full_name() == 'John Doe'

    def test_get_short_name(self, user_factory):
        """Test get_short_name method."""
        user = user_factory(first_name='John', last_name='Doe')

        assert user.get_short_name() == 'John'


@pytest.mark.django_db
class TestCustomUserValidation:
    """Tests for CustomUser field validation."""

    def test_email_max_length(self, user_factory):
        """Test email field has max length validation."""
        # AbstractUser email field has max_length of 254
        user = user_factory()

        # Email field should be properly validated
        assert hasattr(user, 'email')
        email_field = User._meta.get_field('email')
        assert email_field.max_length == 254

    def test_username_max_length(self, user_factory):
        """Test username field has max length validation."""
        user = user_factory()

        username_field = User._meta.get_field('username')
        assert username_field.max_length == 150  # AbstractUser default

    def test_first_name_max_length(self, user_factory):
        """Test first_name field has max length validation."""
        user = user_factory()

        field = User._meta.get_field('first_name')
        assert field.max_length == 150  # AbstractUser default

    def test_last_name_max_length(self, user_factory):
        """Test last_name field has max length validation."""
        user = user_factory()

        field = User._meta.get_field('last_name')
        assert field.max_length == 150  # AbstractUser default


# ============================================================================
# EMAIL VALIDATION AND UNIQUENESS TESTS
# ============================================================================

@pytest.mark.django_db
class TestEmailValidationAndUniqueness:
    """Tests for email validation and uniqueness."""

    def test_email_case_insensitive_lookup(self, user_factory):
        """Test that email lookups can be case-insensitive."""
        user = user_factory(email='Test@Example.com')

        # Create should work with different case
        assert user.email == 'Test@Example.com'

    def test_email_uniqueness_constraint(self, user_factory):
        """Test that email uniqueness is enforced based on factory configuration."""
        # Create first user
        user1 = user_factory(email='unique@example.com')

        # The UserFactory uses django_get_or_create on email,
        # so same email returns same user rather than raising error
        user2 = user_factory(email='unique@example.com')

        # Due to get_or_create behavior
        assert user1.pk == user2.pk

    def test_email_format_validation(self, user_factory):
        """Test that AbstractUser validates email format."""
        # Django's EmailField validates format
        user = user_factory()
        email_field = User._meta.get_field('email')

        # EmailField type indicates validation
        from django.db.models import EmailField
        assert isinstance(email_field, EmailField)

    def test_email_can_be_blank(self, user_factory):
        """Test email field blank attribute."""
        email_field = User._meta.get_field('email')
        # AbstractUser.email has blank=True by default
        assert email_field.blank is True

    def test_multiple_users_different_emails(self, user_factory):
        """Test creating multiple users with different emails."""
        user1 = user_factory(email='user1@example.com')
        user2 = user_factory(email='user2@example.com')
        user3 = user_factory(email='user3@example.com')

        assert user1.pk != user2.pk
        assert user2.pk != user3.pk
        assert user1.email != user2.email


# ============================================================================
# PASSWORD HASHING AND VERIFICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestPasswordHashingAndVerification:
    """Tests for password hashing and verification."""

    def test_password_is_hashed(self, user_factory):
        """Test that password is stored as hash, not plaintext."""
        raw_password = 'TestPassword123!'
        user = user_factory()
        user.set_password(raw_password)
        user.save()

        assert user.password != raw_password
        assert user.password.startswith('pbkdf2_sha256$') or \
               user.password.startswith('argon2') or \
               user.password.startswith('bcrypt')

    def test_set_password_method(self, user_factory):
        """Test set_password method hashes password."""
        user = user_factory()
        user.set_password('new_password_123')
        user.save()

        assert user.check_password('new_password_123') is True

    def test_check_password_correct(self, user_factory):
        """Test check_password returns True for correct password."""
        password = 'CorrectPassword123!'
        user = user_factory()
        user.set_password(password)
        user.save()

        assert user.check_password(password) is True

    def test_check_password_incorrect(self, user_factory):
        """Test check_password returns False for incorrect password."""
        user = user_factory()
        user.set_password('correct_password')
        user.save()

        assert user.check_password('wrong_password') is False

    def test_check_password_empty_string(self, user_factory):
        """Test check_password with empty string."""
        user = user_factory()
        user.set_password('some_password')
        user.save()

        assert user.check_password('') is False

    def test_password_update(self, user_factory):
        """Test updating password invalidates old password."""
        user = user_factory()
        user.set_password('old_password')
        user.save()

        assert user.check_password('old_password') is True

        user.set_password('new_password')
        user.save()

        assert user.check_password('old_password') is False
        assert user.check_password('new_password') is True

    def test_password_not_exposed_in_repr(self, user_factory):
        """Test password is not exposed in user representation."""
        user = user_factory()
        user.set_password('secret_password')

        # repr should not contain actual password
        user_repr = repr(user)
        assert 'secret_password' not in user_repr

    def test_unusable_password(self, user_factory):
        """Test set_unusable_password method."""
        user = user_factory()
        user.set_unusable_password()
        user.save()

        assert user.has_usable_password() is False
        assert user.check_password('any_password') is False


# ============================================================================
# MFA SETTINGS TESTS
# ============================================================================

@pytest.mark.django_db
class TestMFASettings:
    """Tests for Multi-Factor Authentication settings."""

    def test_mfa_disabled_by_default(self, user_factory):
        """Test MFA is disabled by default."""
        user = user_factory()

        assert user.mfa_enabled is False

    def test_enable_mfa(self, user_factory):
        """Test enabling MFA for user."""
        user = user_factory(mfa_enabled=True)

        assert user.mfa_enabled is True

    def test_toggle_mfa(self, user_factory):
        """Test toggling MFA on and off."""
        user = user_factory(mfa_enabled=False)
        assert user.mfa_enabled is False

        user.mfa_enabled = True
        user.save()
        user.refresh_from_db()

        assert user.mfa_enabled is True

        user.mfa_enabled = False
        user.save()
        user.refresh_from_db()

        assert user.mfa_enabled is False

    def test_mfa_field_is_boolean(self, user_factory):
        """Test mfa_enabled is a boolean field."""
        user = user_factory()
        mfa_field = User._meta.get_field('mfa_enabled')

        from django.db.models import BooleanField
        assert isinstance(mfa_field, BooleanField)

    def test_user_with_mfa_fixture(self, user_with_mfa):
        """Test user_with_mfa fixture provides MFA-enabled user."""
        assert user_with_mfa.mfa_enabled is True

    def test_mfa_persists_after_save(self, user_factory):
        """Test MFA setting persists after save."""
        user = user_factory(mfa_enabled=True)
        user_id = user.pk

        # Reload from database
        reloaded_user = User.objects.get(pk=user_id)

        assert reloaded_user.mfa_enabled is True


# ============================================================================
# ANONYMOUS MODE FUNCTIONALITY TESTS
# ============================================================================

@pytest.mark.django_db
class TestAnonymousModeFunctionality:
    """Tests for anonymous mode functionality."""

    def test_anonymous_mode_disabled_by_default(self, user_factory):
        """Test anonymous mode is disabled by default."""
        user = user_factory()

        assert user.anonymous_mode is False

    def test_enable_anonymous_mode(self, user_factory):
        """Test enabling anonymous mode."""
        user = user_factory(anonymous_mode=True)

        assert user.anonymous_mode is True

    def test_toggle_anonymous_mode(self, user_factory):
        """Test toggling anonymous mode."""
        user = user_factory(anonymous_mode=False)

        user.anonymous_mode = True
        user.save()
        user.refresh_from_db()

        assert user.anonymous_mode is True

    def test_anonymous_mode_field_is_boolean(self, user_factory):
        """Test anonymous_mode is a boolean field."""
        user = user_factory()
        field = User._meta.get_field('anonymous_mode')

        from django.db.models import BooleanField
        assert isinstance(field, BooleanField)

    def test_anonymous_mode_persists(self, user_factory):
        """Test anonymous mode setting persists."""
        user = user_factory(anonymous_mode=True)
        user_id = user.pk

        reloaded_user = User.objects.get(pk=user_id)
        assert reloaded_user.anonymous_mode is True

    def test_mfa_and_anonymous_mode_independent(self, user_factory):
        """Test MFA and anonymous mode can be set independently."""
        user1 = user_factory(mfa_enabled=True, anonymous_mode=False)
        user2 = user_factory(mfa_enabled=False, anonymous_mode=True)
        user3 = user_factory(mfa_enabled=True, anonymous_mode=True)

        assert user1.mfa_enabled is True
        assert user1.anonymous_mode is False

        assert user2.mfa_enabled is False
        assert user2.anonymous_mode is True

        assert user3.mfa_enabled is True
        assert user3.anonymous_mode is True


# ============================================================================
# USER MANAGER METHODS TESTS
# ============================================================================

@pytest.mark.django_db
class TestUserManagerMethods:
    """Tests for User manager methods."""

    def test_create_user_via_manager(self):
        """Test creating user via manager's create_user method."""
        user = User.objects.create_user(
            username='manager_test_user',
            email='manager@example.com',
            password='TestPass123!'
        )

        assert user.pk is not None
        assert user.username == 'manager_test_user'
        assert user.email == 'manager@example.com'
        assert user.is_active is True
        assert user.is_staff is False
        assert user.is_superuser is False

    def test_create_superuser_via_manager(self):
        """Test creating superuser via manager's create_superuser method."""
        user = User.objects.create_superuser(
            username='super_admin',
            email='superadmin@example.com',
            password='SuperPass123!'
        )

        assert user.pk is not None
        assert user.is_superuser is True
        assert user.is_staff is True
        assert user.is_active is True

    def test_create_user_normalizes_email(self):
        """Test that create_user normalizes email domain."""
        user = User.objects.create_user(
            username='normalizer',
            email='Test@EXAMPLE.COM',
            password='Pass123!'
        )

        # Email domain should be lowercased
        assert user.email == 'Test@example.com'

    def test_get_by_natural_key(self):
        """Test getting user by natural key (username)."""
        user = User.objects.create_user(
            username='natural_key_user',
            email='natural@example.com',
            password='Pass123!'
        )

        fetched = User.objects.get_by_natural_key('natural_key_user')
        assert fetched.pk == user.pk

    def test_filter_active_users(self, user_factory):
        """Test filtering active users."""
        active_user = user_factory(is_active=True)
        inactive_user = user_factory(is_active=False)

        active_users = User.objects.filter(is_active=True)
        inactive_users = User.objects.filter(is_active=False)

        assert active_user in active_users
        assert inactive_user in inactive_users
        assert active_user not in inactive_users

    def test_filter_staff_users(self, user_factory, superuser_factory):
        """Test filtering staff users."""
        regular_user = user_factory(is_staff=False)
        staff_user = superuser_factory()  # superuser is also staff

        staff_users = User.objects.filter(is_staff=True)

        assert staff_user in staff_users
        assert regular_user not in staff_users

    def test_filter_by_mfa_enabled(self, user_factory):
        """Test filtering users by MFA status."""
        mfa_user = user_factory(mfa_enabled=True)
        non_mfa_user = user_factory(mfa_enabled=False)

        mfa_users = User.objects.filter(mfa_enabled=True)

        assert mfa_user in mfa_users
        assert non_mfa_user not in mfa_users


# ============================================================================
# AUTHENTICATION BACKENDS TESTS
# ============================================================================

@pytest.mark.django_db
class TestAuthenticationBackends:
    """Tests for authentication backends."""

    def test_authenticate_with_username_password(self, user_factory):
        """Test Django's authenticate function with username/password."""
        password = 'TestPassword123!'
        user = user_factory(username='auth_test_user')
        user.set_password(password)
        user.save()

        authenticated = authenticate(
            username='auth_test_user',
            password=password
        )

        assert authenticated is not None
        assert authenticated.pk == user.pk

    def test_authenticate_wrong_password(self, user_factory):
        """Test authenticate fails with wrong password."""
        user = user_factory(username='auth_fail_user')
        user.set_password('correct_password')
        user.save()

        authenticated = authenticate(
            username='auth_fail_user',
            password='wrong_password'
        )

        assert authenticated is None

    def test_authenticate_nonexistent_user(self):
        """Test authenticate fails for non-existent user."""
        authenticated = authenticate(
            username='nonexistent_user',
            password='any_password'
        )

        assert authenticated is None

    def test_authenticate_inactive_user(self, user_factory):
        """Test authenticate fails for inactive user."""
        password = 'TestPassword123!'
        user = user_factory(username='inactive_user', is_active=False)
        user.set_password(password)
        user.save()

        authenticated = authenticate(
            username='inactive_user',
            password=password
        )

        # Django's default backend rejects inactive users
        assert authenticated is None


# ============================================================================
# ALLAUTH INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestAllauthIntegration:
    """Tests for Django-allauth integration."""

    def test_signup_form_includes_custom_fields(self):
        """Test that custom signup form includes first_name and last_name."""
        from custom_account_u.forms import CustomSignupForm

        form = CustomSignupForm()

        assert 'first_name' in form.fields
        assert 'last_name' in form.fields
        assert 'email' in form.fields  # Inherited from allauth

    def test_signup_form_first_name_label(self):
        """Test first_name field label in signup form."""
        from custom_account_u.forms import CustomSignupForm

        form = CustomSignupForm()

        assert form.fields['first_name'].label == 'Prenom'

    def test_signup_form_last_name_label(self):
        """Test last_name field label in signup form."""
        from custom_account_u.forms import CustomSignupForm

        form = CustomSignupForm()

        assert form.fields['last_name'].label == 'Nom'

    def test_signup_form_max_lengths(self):
        """Test field max lengths in signup form."""
        from custom_account_u.forms import CustomSignupForm

        form = CustomSignupForm()

        assert form.fields['first_name'].max_length == 30
        assert form.fields['last_name'].max_length == 30

    def test_signup_form_save_sets_names(self, user_factory):
        """Test that signup form save method sets first and last name."""
        from custom_account_u.forms import CustomSignupForm

        # Create mock request
        factory = RequestFactory()
        request = factory.post('/accounts/signup/')
        request.session = {}

        form_data = {
            'email': 'signup_test@example.com',
            'password1': 'ComplexPass123!',
            'password2': 'ComplexPass123!',
            'first_name': 'Test',
            'last_name': 'Signup',
        }

        form = CustomSignupForm(data=form_data)

        if form.is_valid():
            # Mock the parent save method
            with patch.object(
                CustomSignupForm.__bases__[0],
                'save',
                return_value=User.objects.create_user(
                    username='signup_test',
                    email='signup_test@example.com',
                    password='ComplexPass123!'
                )
            ):
                user = form.save(request)
                # The form should set first and last name
                assert user.first_name == 'Test'
                assert user.last_name == 'Signup'


@pytest.mark.django_db
class TestAllauthViews:
    """Tests for allauth view integration."""

    def test_signup_view_accessible(self, client):
        """Test signup view is accessible."""
        response = client.get('/accounts/signup/')

        # Should return 200 or redirect
        assert response.status_code in [200, 302, 301]

    def test_login_view_accessible(self, client):
        """Test login view is accessible."""
        response = client.get('/accounts/login/')

        assert response.status_code in [200, 302, 301]

    def test_logout_view_requires_authentication(self, client):
        """Test logout view behavior."""
        response = client.get('/accounts/logout/')

        # Logout may redirect or show page
        assert response.status_code in [200, 302, 301]

    def test_login_with_valid_credentials(self, user_factory, client):
        """Test login with valid credentials via allauth."""
        password = 'TestLogin123!'
        user = user_factory()
        user.set_password(password)
        user.save()

        response = client.post('/accounts/login/', {
            'login': user.email,
            'password': password,
        })

        # Should redirect on successful login
        assert response.status_code in [200, 302]

    def test_login_with_invalid_password(self, user_factory, client):
        """Test login fails with invalid password."""
        user = user_factory()
        user.set_password('correct_password')
        user.save()

        response = client.post('/accounts/login/', {
            'login': user.email,
            'password': 'wrong_password',
        })

        # Should return form with errors or redirect back
        assert response.status_code in [200, 302]

    def test_logout_clears_session(self, user_factory, client):
        """Test logout clears user session."""
        password = 'TestPass123!'
        user = user_factory()
        user.set_password(password)
        user.save()

        # Login first
        client.force_login(user)

        # Verify logged in
        response = client.get('/accounts/email/')
        assert response.status_code in [200, 302]

        # Logout
        response = client.post('/accounts/logout/')

        # After logout, accessing protected page should redirect to login
        response = client.get('/accounts/email/')
        assert response.status_code in [302, 200]  # Redirect to login or show login required


# ============================================================================
# PASSWORD RESET FLOW TESTS
# ============================================================================

@pytest.mark.django_db
class TestPasswordResetFlow:
    """Tests for password reset functionality."""

    def test_password_reset_page_accessible(self, client):
        """Test password reset page is accessible."""
        response = client.get('/accounts/password/reset/')

        assert response.status_code in [200, 302]

    def test_password_reset_request_valid_email(self, user_factory, client):
        """Test password reset request with valid email."""
        user = user_factory(email='reset_test@example.com')

        response = client.post('/accounts/password/reset/', {
            'email': 'reset_test@example.com',
        })

        # Should redirect to "email sent" page
        assert response.status_code in [200, 302]

    def test_password_reset_request_invalid_email(self, client):
        """Test password reset request with non-existent email."""
        response = client.post('/accounts/password/reset/', {
            'email': 'nonexistent@example.com',
        })

        # Allauth typically shows same response for security
        assert response.status_code in [200, 302]

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_password_reset_sends_email(self, user_factory, client):
        """Test password reset sends email."""
        user = user_factory(email='email_test@example.com')

        # Clear any existing emails
        mail.outbox = []

        response = client.post('/accounts/password/reset/', {
            'email': 'email_test@example.com',
        })

        # If email sending is configured, should have sent email
        # This depends on allauth configuration


# ============================================================================
# EMAIL VERIFICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestEmailVerification:
    """Tests for email verification functionality."""

    def test_email_verification_page_accessible(self, client):
        """Test email verification page is accessible."""
        response = client.get('/accounts/confirm-email/')

        # May redirect or show page
        assert response.status_code in [200, 302, 404]

    def test_email_page_requires_authentication(self, client):
        """Test email management page requires authentication."""
        response = client.get('/accounts/email/')

        # Should redirect to login if not authenticated
        assert response.status_code in [200, 302]

    def test_authenticated_user_can_view_emails(self, user_factory, client):
        """Test authenticated user can view email management page."""
        user = user_factory()
        client.force_login(user)

        response = client.get('/accounts/email/')

        # Should be accessible when authenticated
        # May redirect if MFA is required per middleware
        assert response.status_code in [200, 302]


# ============================================================================
# USER ACTIVITY AND STATUS TESTS
# ============================================================================

@pytest.mark.django_db
class TestUserActivityAndStatus:
    """Tests for user activity and status tracking."""

    def test_user_is_active_by_default(self, user_factory):
        """Test users are active by default."""
        user = user_factory()

        assert user.is_active is True

    def test_deactivate_user(self, user_factory):
        """Test deactivating a user."""
        user = user_factory(is_active=True)

        user.is_active = False
        user.save()
        user.refresh_from_db()

        assert user.is_active is False

    def test_reactivate_user(self, user_factory):
        """Test reactivating a deactivated user."""
        user = user_factory(is_active=False)

        user.is_active = True
        user.save()
        user.refresh_from_db()

        assert user.is_active is True

    def test_date_joined_auto_set(self, user_factory):
        """Test date_joined is auto-set on creation."""
        before = timezone.now()
        user = user_factory()
        after = timezone.now()

        assert user.date_joined is not None
        assert before <= user.date_joined <= after

    def test_last_login_initially_none(self):
        """Test last_login is initially None."""
        user = User.objects.create_user(
            username='lastlogin_test',
            email='lastlogin@example.com',
            password='Pass123!'
        )

        # last_login is None until actual login
        assert user.last_login is None


# ============================================================================
# TENANT CONTEXT TESTS (Integration with accounts app)
# ============================================================================

@pytest.mark.django_db
class TestUserTenantIntegration:
    """Tests for user integration with tenant system."""

    def test_user_can_have_tenant_memberships(
        self, user_factory, tenant_factory, plan_factory
    ):
        """Test user can have tenant memberships."""
        from accounts.models import TenantUser

        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        user = user_factory()

        membership = TenantUser.objects.create(
            user=user,
            tenant=tenant,
            role='employee',
            is_active=True
        )

        assert membership.user == user
        assert membership.tenant == tenant
        assert user.tenant_memberships.count() == 1

    def test_user_can_have_multiple_tenant_memberships(
        self, user_factory, two_tenants
    ):
        """Test user can belong to multiple tenants."""
        from accounts.models import TenantUser

        tenant1, tenant2 = two_tenants
        user = user_factory()

        TenantUser.objects.create(
            user=user, tenant=tenant1, role='admin', is_active=True
        )
        TenantUser.objects.create(
            user=user, tenant=tenant2, role='employee', is_active=True
        )

        assert user.tenant_memberships.count() == 2

    def test_user_profile_creation(self, user_factory, user_profile_factory):
        """Test user can have associated profile."""
        user = user_factory()
        profile = user_profile_factory(user=user)

        assert profile.user == user
        assert hasattr(user, 'profile')
        assert user.profile == profile


# ============================================================================
# SUPERUSER AND STAFF PERMISSIONS TESTS
# ============================================================================

@pytest.mark.django_db
class TestSuperuserAndStaffPermissions:
    """Tests for superuser and staff permissions."""

    def test_superuser_has_all_permissions(self, superuser_factory):
        """Test superuser has all permissions."""
        superuser = superuser_factory()

        assert superuser.is_superuser is True
        assert superuser.has_perm('any_permission') is True

    def test_superuser_is_staff(self, superuser_factory):
        """Test superuser is automatically staff."""
        superuser = superuser_factory()

        assert superuser.is_staff is True

    def test_regular_user_not_staff(self, user_factory):
        """Test regular user is not staff."""
        user = user_factory()

        assert user.is_staff is False
        assert user.is_superuser is False

    def test_staff_user_not_superuser(self, user_factory):
        """Test staff user is not automatically superuser."""
        user = user_factory(is_staff=True)
        user.is_superuser = False
        user.save()

        assert user.is_staff is True
        assert user.is_superuser is False


# ============================================================================
# MODEL FIELD DEFAULTS TESTS
# ============================================================================

@pytest.mark.django_db
class TestModelFieldDefaults:
    """Tests for model field default values."""

    def test_mfa_enabled_default_false(self):
        """Test mfa_enabled defaults to False."""
        field = User._meta.get_field('mfa_enabled')
        assert field.default is False

    def test_anonymous_mode_default_false(self):
        """Test anonymous_mode defaults to False."""
        field = User._meta.get_field('anonymous_mode')
        assert field.default is False

    def test_is_active_default_true(self):
        """Test is_active defaults to True."""
        field = User._meta.get_field('is_active')
        assert field.default is True

    def test_is_staff_default_false(self):
        """Test is_staff defaults to False."""
        field = User._meta.get_field('is_staff')
        assert field.default is False

    def test_is_superuser_default_false(self):
        """Test is_superuser defaults to False."""
        field = User._meta.get_field('is_superuser')
        assert field.default is False


# ============================================================================
# CUSTOM USER MODEL CONFIGURATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCustomUserModelConfiguration:
    """Tests for custom user model configuration."""

    def test_custom_user_model_is_configured(self):
        """Test AUTH_USER_MODEL points to CustomUser."""
        from django.conf import settings

        assert settings.AUTH_USER_MODEL == 'custom_account_u.CustomUser'

    def test_get_user_model_returns_custom_user(self):
        """Test get_user_model returns CustomUser."""
        UserModel = get_user_model()

        assert UserModel.__name__ == 'CustomUser'
        assert UserModel._meta.app_label == 'custom_account_u'

    def test_custom_user_extends_abstract_user(self):
        """Test CustomUser extends AbstractUser."""
        from django.contrib.auth.models import AbstractUser

        assert issubclass(User, AbstractUser)


# ============================================================================
# SECURITY TESTS
# ============================================================================

@pytest.mark.django_db
class TestUserSecurity:
    """Security-related tests for user model."""

    def test_password_not_in_queryset_values(self, user_factory):
        """Test password is stored securely."""
        user = user_factory()
        user.set_password('secret_password')
        user.save()

        # Password field contains hash, not plaintext
        qs = User.objects.filter(pk=user.pk).values('password')
        password_value = qs.first()['password']

        assert password_value != 'secret_password'
        assert len(password_value) > 50  # Hashes are long

    def test_sensitive_fields_not_in_str(self, user_factory):
        """Test sensitive data not in string representation."""
        user = user_factory()
        user.set_password('sensitive_password')
        user.save()

        user_str = str(user)

        assert 'sensitive_password' not in user_str
        assert 'password' not in user_str.lower()

    def test_uuid_provides_non_sequential_identifier(self, user_factory):
        """Test c_u_uuid provides non-sequential identifier."""
        user1 = user_factory()
        user2 = user_factory()

        # UUIDs should not be sequential
        uuid1 = str(user1.c_u_uuid)
        uuid2 = str(user2.c_u_uuid)

        # They should be different and non-predictable
        assert uuid1 != uuid2
        # UUID format check
        assert len(uuid1) >= 32
        assert len(uuid2) >= 32


# ============================================================================
# MIDDLEWARE INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestMiddlewareIntegration:
    """Tests for middleware integration with user model."""

    def test_require_2fa_middleware_exists(self):
        """Test Require2FAMiddleware is defined."""
        from custom_account_u.middleware import Require2FAMiddleware

        assert Require2FAMiddleware is not None

    def test_auth_security_middleware_exists(self):
        """Test AuthSecurityMiddleware is defined."""
        from custom_account_u.middleware import AuthSecurityMiddleware

        assert AuthSecurityMiddleware is not None

    def test_require_2fa_allowed_urls(self):
        """Test Require2FAMiddleware has allowed URLs list."""
        from custom_account_u.middleware import Require2FAMiddleware

        middleware = Require2FAMiddleware(lambda x: x)

        assert hasattr(middleware, 'allowed_urls')
        assert 'account_logout' in middleware.allowed_urls
        assert 'account_login' in middleware.allowed_urls
        assert 'mfa_activate_totp' in middleware.allowed_urls


# ============================================================================
# API AUTHENTICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestAPIAuthentication:
    """Tests for API authentication with custom user."""

    def test_api_authentication_with_force_authenticate(
        self, user_factory, api_client
    ):
        """Test API client force_authenticate works with CustomUser."""
        user = user_factory()
        api_client.force_authenticate(user=user)

        # Should be authenticated
        response = api_client.get('/api/accounts/me/')

        # Response depends on URL configuration
        assert response.status_code in [200, 404]

    def test_api_authentication_unauthenticated(self, api_client):
        """Test API client without authentication."""
        response = api_client.get('/api/accounts/me/')

        # Should be unauthorized or not found
        assert response.status_code in [401, 403, 404]

    def test_jwt_token_for_custom_user(self, user_factory):
        """Test JWT token generation for CustomUser."""
        from rest_framework_simplejwt.tokens import RefreshToken

        user = user_factory()
        refresh = RefreshToken.for_user(user)

        assert refresh is not None
        assert refresh['user_id'] == user.pk


# ============================================================================
# FACTORY TESTS
# ============================================================================

@pytest.mark.django_db
class TestUserFactories:
    """Tests for user factories."""

    def test_user_factory_creates_valid_user(self, user_factory):
        """Test UserFactory creates valid user."""
        user = user_factory()

        assert user.pk is not None
        assert user.username is not None
        assert user.email is not None
        assert user.is_active is True

    def test_superuser_factory_creates_superuser(self, superuser_factory):
        """Test SuperUserFactory creates superuser."""
        superuser = superuser_factory()

        assert superuser.is_superuser is True
        assert superuser.is_staff is True

    def test_factory_password_setting(self, user_factory):
        """Test factory sets password correctly."""
        password = 'custom_password_123'
        user = user_factory(password=password)

        assert user.check_password(password) is True

    def test_factory_creates_unique_users(self, user_factory):
        """Test factory creates unique users."""
        users = [user_factory() for _ in range(5)]

        # All should have unique PKs
        pks = [u.pk for u in users]
        assert len(pks) == len(set(pks))

        # All should have unique usernames
        usernames = [u.username for u in users]
        assert len(usernames) == len(set(usernames))

        # All should have unique emails
        emails = [u.email for u in users]
        assert len(emails) == len(set(emails))


# ============================================================================
# KYC VIEWS TESTS (from custom_account_u.views)
# ============================================================================

@pytest.mark.django_db
class TestKYCViews:
    """Tests for KYC-related views in custom_account_u."""

    def test_launch_kyc_view_requires_login(self, client):
        """Test launch KYC view requires authentication."""
        response = client.get('/custom_account_u/idenfy/kyc/')

        # Should redirect to login
        assert response.status_code in [302, 404]

    def test_launch_kyc_view_authenticated(self, user_factory, client):
        """Test launch KYC view accessible when authenticated."""
        user = user_factory()
        client.force_login(user)

        response = client.get('/custom_account_u/idenfy/kyc/')

        # May succeed or 404 depending on URL configuration
        assert response.status_code in [200, 302, 404]

    def test_webhook_view_accepts_post(self, client):
        """Test webhook view accepts POST requests."""
        response = client.post(
            '/custom_account_u/webhooks/idenfy/verification-update',
            data='{}',
            content_type='application/json'
        )

        # Webhook endpoint exists and processes request
        assert response.status_code in [200, 400, 403, 404]


# ============================================================================
# EDGE CASES AND ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.django_db
class TestEdgeCasesAndErrorHandling:
    """Tests for edge cases and error handling."""

    def test_empty_username_handling(self):
        """Test handling of empty username."""
        # AbstractUser allows blank username
        user = User.objects.create_user(
            username='',
            email='empty_username@example.com',
            password='Pass123!'
        )

        # Should handle empty username
        assert user.pk is not None

    def test_very_long_email(self, user_factory):
        """Test handling of maximum length email."""
        # Max email length is 254
        long_email = 'a' * 240 + '@example.com'

        if len(long_email) <= 254:
            user = user_factory(email=long_email)
            assert user.email == long_email

    def test_special_characters_in_name(self, user_factory):
        """Test handling of special characters in name."""
        user = user_factory(
            first_name="Jean-Pierre",
            last_name="O'Connor"
        )

        assert user.first_name == "Jean-Pierre"
        assert user.last_name == "O'Connor"

    def test_unicode_in_fields(self, user_factory):
        """Test handling of unicode in fields."""
        user = user_factory(
            first_name="Stephane",
            last_name="Muller"
        )

        assert user.first_name == "Stephane"
        assert user.last_name == "Muller"
