"""
Verification Models - PUBLIC Schema

These models handle global user verification and trust scoring.
Moved from accounts/ app to PUBLIC schema where they belong.

Models:
- KYCVerification: Identity verification (ONE per user globally)
- TrustScore: Platform-wide reputation score (aggregates from all tenants)
- EducationVerification: Education credentials (global, doesn't change per employer)
- EmploymentHistory: Work history verification (PUBLIC for cross-tenant visibility)

Author: Zumodra Team
Date: 2026-01-17
"""

from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings


class KYCVerification(models.Model):
    """
    Global identity verification - ONE per user.

    Moved from accounts/ TENANT schema to core_identity/ PUBLIC schema.
    Reason: KYC verifies a PERSON, not their relationship to a tenant.

    Uses Onfido as the verification provider (production-ready).
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='kyc_verification',
        db_index=True,
        help_text=_('User being verified')
    )

    # Provider Information
    PROVIDER_ONFIDO = 'onfido'
    PROVIDER_MANUAL = 'manual'

    PROVIDER_CHOICES = [
        (PROVIDER_ONFIDO, _('Onfido')),
        (PROVIDER_MANUAL, _('Manual Verification')),
    ]

    provider = models.CharField(
        max_length=20,
        choices=PROVIDER_CHOICES,
        default=PROVIDER_ONFIDO,
        help_text=_('Verification provider')
    )

    # Provider-specific IDs
    provider_applicant_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('Onfido applicant ID')
    )
    provider_check_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('Onfido check ID')
    )

    # Verification Status
    STATUS_PENDING = 'pending'
    STATUS_IN_PROGRESS = 'in_progress'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_EXPIRED = 'expired'

    STATUS_CHOICES = [
        (STATUS_PENDING, _('Pending')),
        (STATUS_IN_PROGRESS, _('In Progress')),
        (STATUS_APPROVED, _('Approved')),
        (STATUS_REJECTED, _('Rejected')),
        (STATUS_EXPIRED, _('Expired')),
    ]

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
        help_text=_('Current verification status')
    )

    # Verification Level
    LEVEL_1 = 'level_1'
    LEVEL_2 = 'level_2'
    LEVEL_3 = 'level_3'

    LEVEL_CHOICES = [
        (LEVEL_1, _('Level 1 - Identity')),
        (LEVEL_2, _('Level 2 - Enhanced')),
        (LEVEL_3, _('Level 3 - AML')),
    ]

    level = models.CharField(
        max_length=20,
        choices=LEVEL_CHOICES,
        default=LEVEL_1,
        db_index=True,
        help_text=_('Verification level')
    )

    # Verification Data (encrypted sensitive data)
    verification_data = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Encrypted verification details from provider')
    )

    # Rejection Reason
    rejection_reason = models.TextField(
        blank=True,
        help_text=_('Reason for rejection (if applicable)')
    )

    # Timestamps
    submitted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When verification was submitted')
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text=_('When verification was approved')
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When verification expires (some levels expire)')
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('KYC Verification')
        verbose_name_plural = _('KYC Verifications')
        db_table = 'core_identity_kycverification'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['status']),
            models.Index(fields=['level']),
            models.Index(fields=['verified_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.get_status_display()} ({self.get_level_display()})"

    @property
    def is_verified(self):
        """Check if user is currently verified."""
        if self.status != self.STATUS_APPROVED:
            return False

        # Check expiration
        if self.expires_at and timezone.now() > self.expires_at:
            return False

        return True

    def approve(self):
        """Approve the verification."""
        self.status = self.STATUS_APPROVED
        self.verified_at = timezone.now()
        self.save(update_fields=['status', 'verified_at', 'updated_at'])

    def reject(self, reason=''):
        """Reject the verification."""
        self.status = self.STATUS_REJECTED
        self.rejection_reason = reason
        self.save(update_fields=['status', 'rejection_reason', 'updated_at'])


class TrustScore(models.Model):
    """
    Global platform trust score - ONE per user.

    Moved from accounts/ TENANT schema to core_identity/ PUBLIC schema.
    Reason: Trust score should aggregate data from ALL tenant memberships.

    Aggregates:
    - Identity verification (from KYCVerification)
    - Career verification (from EmploymentHistory across ALL tenants)
    - Platform activity (from all tenant interactions)
    - Dispute history
    - Completion rates
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='trust_score',
        db_index=True
    )

    # Overall Score (0-100)
    overall_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        db_index=True,
        help_text=_('Overall trust score (weighted average of components)')
    )

    # Component Scores (0-100 each)
    identity_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        help_text=_('Score from KYC verification')
    )
    career_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        help_text=_('Score from verified employment/education history')
    )
    platform_activity_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        help_text=_('Score from platform usage and engagement')
    )
    dispute_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=100,  # Starts at 100, decreases with disputes
        help_text=_('Score based on dispute history (100 = no disputes)')
    )
    completion_rate_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        help_text=_('Score from project/task completion rates')
    )

    # Score Metadata
    total_verifications = models.PositiveIntegerField(
        default=0,
        help_text=_('Number of verified credentials')
    )
    total_disputes = models.PositiveIntegerField(
        default=0,
        help_text=_('Number of disputes filed against user')
    )
    total_completions = models.PositiveIntegerField(
        default=0,
        help_text=_('Number of completed projects/tasks')
    )

    # Timestamps
    last_calculated = models.DateTimeField(
        auto_now=True,
        db_index=True,
        help_text=_('When score was last recalculated')
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        verbose_name = _('Trust Score')
        verbose_name_plural = _('Trust Scores')
        db_table = 'core_identity_trustscore'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['overall_score']),
            models.Index(fields=['last_calculated']),
        ]

    def __str__(self):
        return f"{self.user.email} - Trust Score: {self.overall_score:.1f}/100"

    def calculate_overall_score(self):
        """
        Calculate weighted overall score from component scores.

        Weights:
        - Identity: 25% (KYC verification is critical)
        - Career: 20% (verified work history)
        - Platform Activity: 20% (engagement)
        - Disputes: 15% (conflict resolution)
        - Completion Rate: 20% (reliability)
        """
        weights = {
            'identity': 0.25,
            'career': 0.20,
            'platform_activity': 0.20,
            'dispute': 0.15,
            'completion_rate': 0.20,
        }

        self.overall_score = (
            self.identity_score * weights['identity'] +
            self.career_score * weights['career'] +
            self.platform_activity_score * weights['platform_activity'] +
            self.dispute_score * weights['dispute'] +
            self.completion_rate_score * weights['completion_rate']
        )

        self.save(update_fields=['overall_score', 'last_calculated'])
        return self.overall_score

    def update_identity_score(self):
        """Update identity score based on KYC verification."""
        try:
            kyc = self.user.kyc_verification
            if kyc.is_verified:
                # Full score for level 1, bonus for higher levels
                base_score = 80.0
                level_bonus = {
                    KYCVerification.LEVEL_1: 0.0,
                    KYCVerification.LEVEL_2: 10.0,
                    KYCVerification.LEVEL_3: 20.0,
                }
                self.identity_score = base_score + level_bonus.get(kyc.level, 0.0)
            else:
                self.identity_score = 0.0

            self.save(update_fields=['identity_score', 'last_calculated'])
        except KYCVerification.DoesNotExist:
            self.identity_score = 0.0
            self.save(update_fields=['identity_score', 'last_calculated'])

    def update_career_score(self):
        """Update career score based on verified employment/education history."""
        verified_employment = self.user.employment_history.filter(verified=True).count()
        verified_education = self.user.education_verifications.filter(verified=True).count()

        total_verifications = verified_employment + verified_education
        self.total_verifications = total_verifications

        # Score increases with verifications (max 100)
        # 1 verification = 30 points, 2 = 50, 3 = 70, 4+ = 90-100
        if total_verifications == 0:
            self.career_score = 0.0
        elif total_verifications == 1:
            self.career_score = 30.0
        elif total_verifications == 2:
            self.career_score = 50.0
        elif total_verifications == 3:
            self.career_score = 70.0
        elif total_verifications == 4:
            self.career_score = 85.0
        else:
            self.career_score = min(100.0, 85.0 + (total_verifications - 4) * 3)

        self.save(update_fields=['career_score', 'total_verifications', 'last_calculated'])

    def record_dispute(self):
        """Record a dispute and recalculate dispute score."""
        self.total_disputes += 1

        # Dispute score decreases with more disputes
        # 0 disputes = 100, 1 = 85, 2 = 70, 3 = 55, 4+ = 40-0
        if self.total_disputes == 0:
            self.dispute_score = 100.0
        elif self.total_disputes == 1:
            self.dispute_score = 85.0
        elif self.total_disputes == 2:
            self.dispute_score = 70.0
        elif self.total_disputes == 3:
            self.dispute_score = 55.0
        else:
            self.dispute_score = max(0.0, 55.0 - (self.total_disputes - 3) * 15)

        self.save(update_fields=['total_disputes', 'dispute_score', 'last_calculated'])
        self.calculate_overall_score()


class EducationVerification(models.Model):
    """
    Education verification - GLOBAL (degree doesn't change per employer).

    Moved from accounts/ TENANT schema to core_identity/ PUBLIC schema.
    Reason: Education is global - when you apply to new company, they need
    to see your verified degrees from anywhere.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='education_verifications',
        db_index=True
    )

    # Institution Details
    institution_name = models.CharField(
        max_length=200,
        help_text=_('Name of educational institution')
    )
    institution_country = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Country where institution is located')
    )

    # Degree Information
    degree = models.CharField(
        max_length=200,
        help_text=_('Degree or certificate obtained')
    )
    field_of_study = models.CharField(
        max_length=200,
        help_text=_('Field of study or major')
    )
    degree_level = models.CharField(
        max_length=50,
        choices=[
            ('high_school', _('High School')),
            ('diploma', _('Diploma')),
            ('associate', _('Associate Degree')),
            ('bachelor', _('Bachelor Degree')),
            ('master', _('Master Degree')),
            ('doctorate', _('Doctorate')),
            ('certificate', _('Professional Certificate')),
        ],
        help_text=_('Level of degree')
    )

    # Dates
    start_date = models.DateField(
        help_text=_('When studies started')
    )
    end_date = models.DateField(
        null=True,
        blank=True,
        help_text=_('When degree was completed (null if in progress)')
    )
    is_current = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Currently pursuing this degree')
    )

    # Verification Status
    verified = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Whether degree has been verified')
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When verification was completed')
    )
    verification_method = models.CharField(
        max_length=100,
        blank=True,
        choices=[
            ('registrar', _('Registrar Verification')),
            ('document', _('Document Upload')),
            ('third_party', _('Third-Party Service')),
            ('manual', _('Manual Review')),
        ],
        help_text=_('How degree was verified')
    )
    verified_by_email = models.EmailField(
        blank=True,
        help_text=_('Email of verifier (if applicable)')
    )

    # Supporting Documents
    transcript = models.FileField(
        upload_to='education_docs/transcripts/',
        blank=True,
        null=True,
        help_text=_('Official transcript')
    )
    diploma = models.FileField(
        upload_to='education_docs/diplomas/',
        blank=True,
        null=True,
        help_text=_('Diploma or degree certificate')
    )

    # Additional Details
    grade_gpa = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('GPA or final grade')
    )
    honors = models.CharField(
        max_length=200,
        blank=True,
        help_text=_('Honors or distinctions received')
    )
    activities = models.TextField(
        blank=True,
        help_text=_('Relevant activities, societies, or achievements')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Education Verification')
        verbose_name_plural = _('Education Verifications')
        db_table = 'core_identity_educationverification'
        ordering = ['-end_date', '-start_date']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['verified']),
            models.Index(fields=['is_current']),
            models.Index(fields=['institution_name']),
        ]

    def __str__(self):
        status = "✓ Verified" if self.verified else "Pending"
        return f"{self.user.email} - {self.degree} from {self.institution_name} ({status})"

    def verify(self, method='manual', verifier_email=''):
        """Mark education as verified."""
        self.verified = True
        self.verified_at = timezone.now()
        self.verification_method = method
        self.verified_by_email = verifier_email
        self.save(update_fields=['verified', 'verified_at', 'verification_method', 'verified_by_email', 'updated_at'])

        # Update user's career score in TrustScore
        try:
            trust_score = self.user.trust_score
            trust_score.update_career_score()
            trust_score.calculate_overall_score()
        except TrustScore.DoesNotExist:
            pass


class EmploymentHistory(models.Model):
    """
    Work history verification - PUBLIC schema for cross-tenant visibility.

    NEW MODEL - moved from TENANT schema (was EmploymentVerification).
    Reason: When Marie applies to Google, Google needs to see her verified
    work history at Acme Corp (different tenant).

    This is global employment history that follows the user across tenants.
    Different from EmploymentProfile (TENANT schema) which is employment
    data for THIS specific tenant.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='employment_history',
        db_index=True
    )

    # Company Information
    company_name = models.CharField(
        max_length=200,
        help_text=_('Name of employer')
    )
    company_country = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Country where company is located')
    )

    # Position Details
    job_title = models.CharField(
        max_length=150,
        help_text=_('Job title or position held')
    )
    department = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Department or division')
    )

    # Employment Type
    employment_type = models.CharField(
        max_length=20,
        choices=[
            ('full_time', _('Full Time')),
            ('part_time', _('Part Time')),
            ('contract', _('Contract')),
            ('internship', _('Internship')),
            ('freelance', _('Freelance')),
        ],
        help_text=_('Type of employment')
    )

    # Dates
    start_date = models.DateField(
        help_text=_('Employment start date')
    )
    end_date = models.DateField(
        null=True,
        blank=True,
        help_text=_('Employment end date (null if current)')
    )
    is_current = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Currently employed at this company')
    )

    # Responsibilities & Achievements
    responsibilities = models.TextField(
        blank=True,
        help_text=_('Key responsibilities and duties')
    )
    achievements = models.TextField(
        blank=True,
        help_text=_('Notable achievements or accomplishments')
    )

    # Verification Status
    verified = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Whether employment has been verified')
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When verification was completed')
    )
    verification_method = models.CharField(
        max_length=100,
        blank=True,
        choices=[
            ('hr_contact', _('HR Department Contact')),
            ('manager_reference', _('Manager Reference')),
            ('employment_letter', _('Employment Letter')),
            ('payslip', _('Payslip/Tax Document')),
            ('third_party', _('Third-Party Verification Service')),
            ('manual', _('Manual Review')),
        ],
        help_text=_('How employment was verified')
    )
    verified_by_email = models.EmailField(
        blank=True,
        help_text=_('Email of verifier (HR contact, manager, etc.)')
    )

    # Supporting Documents
    employment_letter = models.FileField(
        upload_to='employment_docs/letters/',
        blank=True,
        null=True,
        help_text=_('Employment verification letter from HR')
    )
    reference_letter = models.FileField(
        upload_to='employment_docs/references/',
        blank=True,
        null=True,
        help_text=_('Reference letter from manager')
    )

    # Manager/Reference Contact (optional)
    reference_name = models.CharField(
        max_length=200,
        blank=True,
        help_text=_('Name of reference/manager')
    )
    reference_email = models.EmailField(
        blank=True,
        help_text=_('Email of reference/manager')
    )
    reference_phone = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Phone number of reference/manager')
    )

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Employment History')
        verbose_name_plural = _('Employment Histories')
        db_table = 'core_identity_employmenthistory'
        ordering = ['-end_date', '-start_date']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['verified']),
            models.Index(fields=['is_current']),
            models.Index(fields=['company_name']),
        ]

    def __str__(self):
        status = "✓ Verified" if self.verified else "Pending"
        dates = f"{self.start_date.year}"
        if self.is_current:
            dates += " - Present"
        elif self.end_date:
            dates += f" - {self.end_date.year}"
        return f"{self.user.email} - {self.job_title} at {self.company_name} ({dates}) [{status}]"

    def verify(self, method='manual', verifier_email=''):
        """Mark employment as verified."""
        self.verified = True
        self.verified_at = timezone.now()
        self.verification_method = method
        self.verified_by_email = verifier_email
        self.save(update_fields=['verified', 'verified_at', 'verification_method', 'verified_by_email', 'updated_at'])

        # Update user's career score in TrustScore
        try:
            trust_score = self.user.trust_score
            trust_score.update_career_score()
            trust_score.calculate_overall_score()
        except TrustScore.DoesNotExist:
            pass

    @property
    def duration_years(self):
        """Calculate employment duration in years."""
        end = self.end_date or timezone.now().date()
        delta = end - self.start_date
        return round(delta.days / 365.25, 1)
