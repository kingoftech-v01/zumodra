from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.db.models.signals import pre_save
from django.dispatch import receiver
import random
import string
import uuid

# Create your models here.

class CustomUser(AbstractUser):
    mfa_enabled = models.BooleanField(default=False)
    anonymous_mode = models.BooleanField(default=False)
    c_u_uuid = models.CharField(default=uuid.uuid4, editable=False, unique=True)

# Common Profile Information shared by all users
class Profile(models.Model):
    """
    Base profile linked to CustomUser holding common personal info.
    """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=20, blank=True)  # Store in e164 format recommended
    address = models.CharField(max_length=200, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    city = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)  # can be used for age restrictions
    photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True)

    # Tracking verification and KYC statuses – important for compliance
    verification_status = models.CharField(max_length=50, blank=True)
    verification_date = models.DateTimeField(null=True, blank=True)

    # Tracking verification and KYC statuses – important for compliance
    kyc_status = models.CharField(max_length=50, blank=True)
    kyc_completed = models.BooleanField(default=False)
    kyc_date = models.DateTimeField(null=True, blank=True)

    # GDPR compliance: store consent and data processing info
    gdpr_consent = models.BooleanField(default=False)
    gdpr_consent_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'Profile of {self.user.email}'


# Distinct profiles for user roles for role-specific info and permissions

class ClientProfile(models.Model):
    """
    Profile for clients who request services.
    """

    # For matching preferences
    preferred_service_types = models.ManyToManyField('ServiceCategory', blank=True)
    preferred_location = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f'ClientProfile: {self.user.email}'


class ServiceProviderProfile(models.Model):
    """
    Profile for service providers offering services.
    Includes professional verification data.
    """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='provider_profile')

    # Professional info
    company_name = models.CharField(max_length=200, blank=True)
    company_registration_number = models.CharField(max_length=100, blank=True)  # For legal verification
    website = models.URLField(blank=True)
    specialties = models.ManyToManyField('ServiceCategory', blank=True)

    # Certification badges (links to certification model)
    certifications = models.ManyToManyField('CertificationBadge', blank=True)

    # Ratings and reviews will be handled via related models

    def __str__(self):
        return f'ServiceProviderProfile: {self.user.email}'


class EmployerProfile(models.Model):
    """
    Profile for employers who hire candidates.
    """
    user = models.ManyToManyField(CustomUser, related_name='employer_profile')
    company_name = models.CharField(max_length=200)
    company_industry = models.CharField(max_length=100, blank=True)
    company_website = models.URLField(blank=True)
    company_registration_number = models.CharField(max_length=100, blank=True)  # Legal compliance info

    def __str__(self):
        return f'EmployerProfile: {self.company_name}'


class CandidateProfile(models.Model):
    """
    Profile for candidates searching for job opportunities.
    Includes validated education and experience.
    """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='candidate_profile')

    resume = models.FileField(upload_to='resumes/', blank=True, null=True)
    portfolio_link = models.URLField(blank=True)
    education_verified = models.BooleanField(default=False)
    experience_verified = models.BooleanField(default=False)

    # Optionally track anonymized job search
    anonymous_mode = models.BooleanField(default=False)

    def __str__(self):
        return f'CandidateProfile: {self.user.email}'


class StaffProfile(models.Model):
    """
    Internal staff managing the platform, with elevated permissions.
    """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='staff_profile')
    is_superuser = models.BooleanField(default=False)
    department = models.CharField(max_length=100, blank=True)
    position = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f'StaffProfile: {self.user.email} | Superuser: {self.is_superuser}'


# Supporting models

class ServiceCategory(models.Model):
    """
    Categories or sectors of services for filtering and matching.
    """
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class CertificationBadge(models.Model):
    """
    Digital badges/titles that validate certifications or KYC approval.
    """
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    issued_date = models.DateTimeField(auto_now_add=True)
    # Possibly add image/icon
    icon = models.ImageField(upload_to='badges/', blank=True, null=True)

    def __str__(self):
        return self.name

class Rating(models.Model):
    """
    Ratings and reviews for service providers and employers.
    """
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    rating = models.IntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)



@receiver(pre_save, sender=CustomUser)
def generate_username(sender, instance, **kwargs):
    if not instance.username:
        base_username = (instance.first_name[0] + instance.last_name[2]).lower()
        random_number = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        instance.username = f"{base_username}{random_number}"
