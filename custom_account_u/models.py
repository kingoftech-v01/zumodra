from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.db.models.signals import pre_save
from django.dispatch import receiver
from phonenumber_field.modelfields import PhoneNumberField
import random
import string
import uuid

# Create your models here.

class CustomUser(AbstractUser):
    mfa_enabled = models.BooleanField(default=False)
    anonymous_mode = models.BooleanField(default=False)
    c_u_uuid = models.CharField(default=uuid.uuid4, editable=False, unique=True)

    # USER VERIFICATION (GLOBAL, NOT TENANT-SPECIFIC)
    cv_verified = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('User CV/professional credentials verified')
    )
    cv_verified_at = models.DateTimeField(null=True, blank=True)

    kyc_verified = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('User identity (KYC) verified')
    )
    kyc_verified_at = models.DateTimeField(null=True, blank=True)


class PublicProfile(models.Model):
    """
    Global public profile for marketplace/freelance activities.
    Lives in PUBLIC schema (shared across all tenants).
    Used for portfolio, CV, skills, and public marketplace identity.
    """
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='public_profile'
    )

    # Identity
    display_name = models.CharField(
        max_length=100,
        help_text=_('Public display name for marketplace')
    )
    professional_title = models.CharField(
        max_length=150,
        blank=True,
        help_text=_('Professional title or headline')
    )
    avatar = models.ImageField(
        upload_to='public_avatars/',
        blank=True,
        null=True,
        help_text=_('Profile picture')
    )
    bio = models.TextField(
        max_length=2000,
        blank=True,
        help_text=_('Professional bio or summary')
    )

    # Contact (privacy-controlled)
    public_email = models.EmailField(
        blank=True,
        help_text=_('Public contact email (can be different from login email)')
    )
    phone = PhoneNumberField(
        blank=True,
        null=True,
        help_text=_('Contact phone number')
    )

    # Location
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True, default='CA')
    timezone = models.CharField(max_length=50, default='America/Toronto')

    # Professional Links
    linkedin_url = models.URLField(blank=True, help_text=_('LinkedIn profile URL'))
    github_url = models.URLField(blank=True, help_text=_('GitHub profile URL'))
    portfolio_url = models.URLField(blank=True, help_text=_('Portfolio website URL'))
    personal_website = models.URLField(blank=True, help_text=_('Personal website URL'))

    # CV/Resume
    cv_file = models.FileField(
        upload_to='cvs/',
        blank=True,
        null=True,
        help_text=_('Latest CV/resume file')
    )
    cv_last_updated = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When CV was last updated')
    )

    # Skills & Certifications (JSON)
    skills = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of skills as JSON array')
    )
    languages = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of languages as JSON array')
    )
    certifications = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of certifications as JSON array')
    )

    # Marketplace
    available_for_work = models.BooleanField(
        default=False,
        help_text=_('Available for freelance work')
    )
    hourly_rate_min = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Minimum hourly rate')
    )
    hourly_rate_max = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Maximum hourly rate')
    )
    currency = models.CharField(max_length=3, default='CAD')

    # Privacy
    VISIBILITY_PUBLIC = 'public'
    VISIBILITY_TENANTS_ONLY = 'tenants_only'
    VISIBILITY_PRIVATE = 'private'

    VISIBILITY_CHOICES = [
        (VISIBILITY_PUBLIC, _('Public - Anyone can view')),
        (VISIBILITY_TENANTS_ONLY, _('Tenants Only - Only orgs I joined')),
        (VISIBILITY_PRIVATE, _('Private - Hidden')),
    ]

    profile_visibility = models.CharField(
        max_length=20,
        choices=VISIBILITY_CHOICES,
        default=VISIBILITY_TENANTS_ONLY,
        help_text=_('Who can view this profile')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Public Profile')
        verbose_name_plural = _('Public Profiles')
        ordering = ['-created_at']

    def __str__(self):
        return f"PublicProfile: {self.display_name} ({self.user.email})"

    @property
    def completion_percentage(self):
        """Calculate profile completion percentage."""
        fields_to_check = [
            'display_name', 'professional_title', 'avatar', 'bio',
            'city', 'country', 'linkedin_url', 'github_url',
            'cv_file', 'skills', 'languages'
        ]

        filled_fields = sum(
            1 for field in fields_to_check
            if getattr(self, field, None) and (
                not isinstance(getattr(self, field), list) or len(getattr(self, field)) > 0
            )
        )

        return int((filled_fields / len(fields_to_check)) * 100)

    @property
    def verification_badges(self):
        """Get verification badges from CustomUser."""
        badges = []
        if self.user.cv_verified:
            badges.append({'type': 'cv', 'verified_at': self.user.cv_verified_at})
        if self.user.kyc_verified:
            badges.append({'type': 'kyc', 'verified_at': self.user.kyc_verified_at})
        return badges


class ProfileFieldSync(models.Model):
    """
    Per-user, per-tenant privacy controls for field-level synchronization.
    Lives in PUBLIC schema. Controls which PublicProfile fields sync to TenantProfile.
    """
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='profile_sync_settings'
    )
    tenant_uuid = models.UUIDField(
        help_text=_('UUID of tenant (not FK to avoid cross-schema issues)'),
        db_index=True
    )

    # Per-field sync toggles (privacy controls)
    sync_display_name = models.BooleanField(
        default=True,
        help_text=_('Sync display name to tenant profile')
    )
    sync_avatar = models.BooleanField(
        default=True,
        help_text=_('Sync avatar to tenant profile')
    )
    sync_bio = models.BooleanField(
        default=True,
        help_text=_('Sync bio to tenant profile')
    )
    sync_public_email = models.BooleanField(
        default=False,  # Privacy: OFF by default
        help_text=_('Sync public email to tenant profile')
    )
    sync_phone = models.BooleanField(
        default=False,  # Privacy: OFF by default
        help_text=_('Sync phone to tenant profile')
    )
    sync_city = models.BooleanField(
        default=True,
        help_text=_('Sync city to tenant profile')
    )
    sync_state = models.BooleanField(
        default=True,
        help_text=_('Sync state/province to tenant profile')
    )
    sync_country = models.BooleanField(
        default=True,
        help_text=_('Sync country to tenant profile')
    )
    sync_linkedin = models.BooleanField(
        default=True,
        help_text=_('Sync LinkedIn URL to tenant profile')
    )
    sync_github = models.BooleanField(
        default=True,
        help_text=_('Sync GitHub URL to tenant profile')
    )
    sync_portfolio = models.BooleanField(
        default=True,
        help_text=_('Sync portfolio URL to tenant profile')
    )
    sync_skills = models.BooleanField(
        default=True,
        help_text=_('Sync skills to tenant profile')
    )
    sync_languages = models.BooleanField(
        default=True,
        help_text=_('Sync languages to tenant profile')
    )

    # Auto-sync disabled (manual only)
    auto_sync = models.BooleanField(
        default=False,
        help_text=_('Automatically sync when public profile changes (NOT recommended)')
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Profile Field Sync Settings')
        verbose_name_plural = _('Profile Field Sync Settings')
        unique_together = ['user', 'tenant_uuid']
        ordering = ['-created_at']

    def __str__(self):
        return f"Sync settings: {self.user.email} → Tenant {self.tenant_uuid}"

    def get_enabled_fields(self):
        """Returns list of enabled field names for sync."""
        enabled_fields = []
        sync_fields = [
            'display_name', 'avatar', 'bio', 'public_email', 'phone',
            'city', 'state', 'country', 'linkedin', 'github', 'portfolio',
            'skills', 'languages'
        ]

        for field in sync_fields:
            if getattr(self, f'sync_{field}', False):
                enabled_fields.append(field)

        return enabled_fields

    @classmethod
    def get_or_create_defaults(cls, user, tenant_uuid):
        """Get or create ProfileFieldSync with privacy-friendly defaults."""
        sync_settings, created = cls.objects.get_or_create(
            user=user,
            tenant_uuid=tenant_uuid,
            defaults={
                'sync_display_name': True,
                'sync_avatar': True,
                'sync_bio': True,
                'sync_public_email': False,  # Privacy: OFF
                'sync_phone': False,  # Privacy: OFF
                'sync_city': True,
                'sync_state': True,
                'sync_country': True,
                'sync_linkedin': True,
                'sync_github': True,
                'sync_portfolio': True,
                'sync_skills': True,
                'sync_languages': True,
                'auto_sync': False,  # Manual only
            }
        )
        return sync_settings, created


# # Common Profile Information shared by all users
# class Profile(models.Model):
#     """
#     Base profile linked to CustomUser holding common personal info.
#     """
#     user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')
#     phone_number = models.CharField(max_length=20, blank=True)  # Store in e164 format recommended
#     address = models.CharField(max_length=200, blank=True)
#     postal_code = models.CharField(max_length=20, blank=True)
#     city = models.CharField(max_length=100, blank=True)
#     country = models.CharField(max_length=100, blank=True)
#     date_of_birth = models.DateField(null=True, blank=True)  # can be used for age restrictions
#     photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True)

#     # Tracking verification and KYC statuses – important for compliance
#     verification_status = models.CharField(max_length=50, blank=True)
#     verification_date = models.DateTimeField(null=True, blank=True)

#     # Tracking verification and KYC statuses – important for compliance
#     kyc_status = models.CharField(max_length=50, blank=True)
#     kyc_completed = models.BooleanField(default=False)
#     kyc_date = models.DateTimeField(null=True, blank=True)

#     # GDPR compliance: store consent and data processing info
#     gdpr_consent = models.BooleanField(default=False)
#     gdpr_consent_date = models.DateTimeField(null=True, blank=True)

#     def __str__(self):
#         return f'Profile of {self.user.email}'


# # Distinct profiles for user roles for role-specific info and permissions

# class ClientProfile(models.Model):
#     """
#     Profile for clients who request services.
#     """

#     # For matching preferences
#     preferred_service_types = models.ManyToManyField('ServiceCategory', blank=True)
#     preferred_location = models.CharField(max_length=100, blank=True)

#     def __str__(self):
#         return f'ClientProfile: {self.user.email}'


# class ServiceProviderProfile(models.Model):
#     """
#     Profile for service providers offering services.
#     Includes professional verification data.
#     """
#     user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='provider_profile')

#     # Professional info
#     company_name = models.CharField(max_length=200, blank=True)
#     company_registration_number = models.CharField(max_length=100, blank=True)  # For legal verification
#     website = models.URLField(blank=True)
#     specialties = models.ManyToManyField('ServiceCategory', blank=True)

#     # Certification badges (links to certification model)
#     certifications = models.ManyToManyField('CertificationBadge', blank=True)

#     # Ratings and reviews will be handled via related models

#     def __str__(self):
#         return f'ServiceProviderProfile: {self.user.email}'


# class EmployerProfile(models.Model):
#     """
#     Profile for employers who hire candidates.
#     """
#     user = models.ManyToManyField(CustomUser, related_name='employer_profile')
#     company_name = models.CharField(max_length=200)
#     company_industry = models.CharField(max_length=100, blank=True)
#     company_website = models.URLField(blank=True)
#     company_registration_number = models.CharField(max_length=100, blank=True)  # Legal compliance info

#     def __str__(self):
#         return f'EmployerProfile: {self.company_name}'


# class CandidateProfile(models.Model):
#     """
#     Profile for candidates searching for job opportunities.
#     Includes validated education and experience.
#     """
#     user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='candidate_profile')

#     resume = models.FileField(upload_to='resumes/', blank=True, null=True)
#     portfolio_link = models.URLField(blank=True)
#     education_verified = models.BooleanField(default=False)
#     experience_verified = models.BooleanField(default=False)

#     # Optionally track anonymized job search
#     anonymous_mode = models.BooleanField(default=False)

#     def __str__(self):
#         return f'CandidateProfile: {self.user.email}'


# class StaffProfile(models.Model):
#     """
#     Internal staff managing the platform, with elevated permissions.
#     """
#     user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='staff_profile')
#     is_superuser = models.BooleanField(default=False)
#     department = models.CharField(max_length=100, blank=True)
#     position = models.CharField(max_length=100, blank=True)

#     def __str__(self):
#         return f'StaffProfile: {self.user.email} | Superuser: {self.is_superuser}'


# # Supporting models

# class ServiceCategory(models.Model):
#     """
#     Categories or sectors of services for filtering and matching.
#     """
#     name = models.CharField(max_length=100, unique=True)
#     description = models.TextField(blank=True)

#     def __str__(self):
#         return self.name


# class CertificationBadge(models.Model):
#     """
#     Digital badges/titles that validate certifications or KYC approval.
#     """
#     name = models.CharField(max_length=100)
#     description = models.TextField(blank=True)
#     issued_date = models.DateTimeField(auto_now_add=True)
#     # Possibly add image/icon
#     icon = models.ImageField(upload_to='badges/', blank=True, null=True)

#     def __str__(self):
#         return self.name

# class Rating(models.Model):
#     """
#     Ratings and reviews for service providers and employers.
#     """
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
#     rating = models.IntegerField()
#     comment = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)



# @receiver(pre_save, sender=CustomUser)
# def generate_username(sender, instance, **kwargs):
#     if not instance.username:
#         base_username = (instance.first_name[0] + instance.last_name[2]).lower()
#         random_number = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
#         instance.username = f"{base_username}{random_number}"
