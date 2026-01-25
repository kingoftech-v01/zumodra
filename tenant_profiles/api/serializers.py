"""
Accounts Serializers - DRF serializers for account management.

This module provides serializers for:
- TenantUser with nested UserProfile
- UserProfile with completion tracking
- KYC verification (read/write)
- Progressive consent management
- Data access logging (read-only audit)
- Login history (read-only security)
- User registration and authentication
- Trust System (TrustScore, EmploymentVerification, EducationVerification, Review)
- Multi-CV System (CandidateCV)
- Co-op/Student Ecosystem (StudentProfile, CoopTerm)
"""

from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from ..models import (
    TenantUser, UserProfile, KYCVerification,
    ProgressiveConsent, DataAccessLog, LoginHistory,
    SecurityQuestion, ROLE_PERMISSIONS,
    # Trust System Models
    TrustScore, EmploymentVerification, EducationVerification, Review,
    # Multi-CV System
    CandidateCV,
    # Co-op/Student Ecosystem
    StudentProfile, CoopTerm,
    # Freelancer Profiles
    FreelancerProfile,
    # Profile Sync System
    TenantProfile
)

User = get_user_model()


# ==================== USER SERIALIZERS ====================

class BasicUserSerializer(serializers.ModelSerializer):
    """Minimal user information for nested serialization."""

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'username']
        read_only_fields = ['id', 'email', 'username']


class UserProfileSerializer(serializers.ModelSerializer):
    """
    User profile serializer with completion tracking.

    Includes computed fields for profile completion status.
    """
    user = BasicUserSerializer(read_only=True)
    is_complete = serializers.ReadOnlyField()
    completion_percentage = serializers.ReadOnlyField()
    full_address = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            'uuid', 'user', 'profile_type',
            # Personal Info
            'phone', 'phone_verified', 'date_of_birth', 'nationality', 'languages',
            # Address
            'address_line1', 'address_line2', 'city', 'state', 'postal_code', 'country',
            'full_address',
            # Media
            'avatar', 'bio',
            # Social Links
            'linkedin_url', 'github_url', 'portfolio_url', 'twitter_url',
            # Preferences
            'preferred_language', 'timezone', 'notification_preferences',
            # Status
            'is_complete', 'completion_percentage',
            # Timestamps
            'created_at', 'updated_at', 'profile_completed_at'
        ]
        read_only_fields = [
            'uuid', 'user', 'phone_verified', 'is_complete', 'completion_percentage',
            'created_at', 'updated_at', 'profile_completed_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_full_address(self, obj):
        """Return formatted full address."""
        parts = filter(None, [
            obj.address_line1,
            obj.address_line2,
            obj.city,
            obj.state,
            obj.postal_code,
            obj.country
        ])
        return ', '.join(parts) if parts else None

    def update(self, instance, validated_data):
        """Mark profile as complete if all required fields are filled."""
        instance = super().update(instance, validated_data)

        # Check if profile became complete
        if instance.is_complete and not instance.profile_completed_at:
            instance.profile_completed_at = timezone.now()
            instance.save(update_fields=['profile_completed_at'])

        return instance


class TenantUserSerializer(serializers.ModelSerializer):
    """
    Tenant user membership serializer with nested profile.

    Includes user profile and role-based permissions.
    """
    user = BasicUserSerializer(read_only=True)
    user_profile = serializers.SerializerMethodField()
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    is_admin = serializers.ReadOnlyField()
    can_hire = serializers.ReadOnlyField()
    permissions = serializers.SerializerMethodField()
    department_name = serializers.CharField(
        source='department.name', read_only=True, allow_null=True
    )
    reports_to_name = serializers.SerializerMethodField()

    class Meta:
        model = TenantUser
        fields = [
            'uuid', 'user', 'user_profile', 'tenant',
            'role', 'role_display', 'is_admin', 'can_hire', 'permissions',
            'department', 'department_name', 'job_title',
            'reports_to', 'reports_to_name',
            'is_active', 'is_primary_tenant',
            'joined_at', 'last_active_at', 'deactivated_at'
        ]
        read_only_fields = [
            'uuid', 'user', 'tenant', 'is_admin', 'can_hire',
            'joined_at', 'last_active_at', 'deactivated_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_user_profile(self, obj):
        """Get nested user profile if exists."""
        try:
            profile = obj.user.profile
            return UserProfileSerializer(profile, context=self.context).data
        except UserProfile.DoesNotExist:
            return None

    @extend_schema_field(OpenApiTypes.STR)
    def get_permissions(self, obj):
        """Get list of permissions for this tenant user."""
        return list(obj.get_all_permissions())

    @extend_schema_field(OpenApiTypes.STR)
    def get_reports_to_name(self, obj):
        """Get the name of the supervisor."""
        if obj.reports_to:
            return f"{obj.reports_to.user.first_name} {obj.reports_to.user.last_name}"
        return None


class TenantUserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new tenant user memberships."""
    email = serializers.EmailField(write_only=True)

    class Meta:
        model = TenantUser
        fields = ['email', 'role', 'department', 'job_title', 'reports_to']

    def validate_email(self, value):
        """Validate that user with email exists."""
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                _("No user found with this email address.")
            )
        return value

    def create(self, validated_data):
        email = validated_data.pop('email')
        user = User.objects.get(email=email)
        tenant = self.context['request'].tenant

        # Check if already a member
        if TenantUser.objects.filter(user=user, tenant=tenant).exists():
            raise serializers.ValidationError(
                _("User is already a member of this organization.")
            )

        validated_data['user'] = user
        validated_data['tenant'] = tenant
        return super().create(validated_data)


# ==================== KYC SERIALIZERS ====================

class KYCVerificationSerializer(serializers.ModelSerializer):
    """
    KYC verification serializer for read operations.

    Hides sensitive document information and provider responses.
    """
    user = BasicUserSerializer(read_only=True)
    verified_by = BasicUserSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    type_display = serializers.CharField(source='get_verification_type_display', read_only=True)
    level_display = serializers.CharField(source='get_level_display', read_only=True)
    is_valid = serializers.ReadOnlyField()

    class Meta:
        model = KYCVerification
        fields = [
            'uuid', 'user',
            'verification_type', 'type_display',
            'status', 'status_display',
            'level', 'level_display',
            'provider', 'confidence_score',
            'document_type', 'document_country', 'document_expiry',
            'rejection_reason', 'notes',
            'verified_by', 'is_valid',
            'created_at', 'submitted_at', 'verified_at', 'expires_at'
        ]
        read_only_fields = [
            'uuid', 'user', 'provider', 'confidence_score',
            'verified_by', 'is_valid',
            'created_at', 'submitted_at', 'verified_at', 'expires_at'
        ]


class KYCSubmissionSerializer(serializers.ModelSerializer):
    """
    Serializer for submitting new KYC verification requests.

    Accepts document information for verification.
    """
    class Meta:
        model = KYCVerification
        fields = [
            'verification_type', 'level',
            'document_type', 'document_country', 'document_expiry'
        ]

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['user'] = request.user
        validated_data['status'] = KYCVerification.VerificationStatus.PENDING
        validated_data['submitted_at'] = timezone.now()
        return super().create(validated_data)


class KYCVerifyActionSerializer(serializers.Serializer):
    """Serializer for admin verification action."""
    confidence_score = serializers.DecimalField(
        max_digits=5, decimal_places=2,
        required=False, min_value=0, max_value=100
    )
    notes = serializers.CharField(required=False, allow_blank=True)
    verified_data = serializers.JSONField(required=False, default=dict)


class KYCRejectActionSerializer(serializers.Serializer):
    """Serializer for admin rejection action."""
    rejection_reason = serializers.CharField(required=True)
    notes = serializers.CharField(required=False, allow_blank=True)


# ==================== CONSENT SERIALIZERS ====================

class ProgressiveConsentSerializer(serializers.ModelSerializer):
    """
    Progressive consent serializer for consent management.

    Supports both grant and revoke operations.
    """
    grantor = BasicUserSerializer(read_only=True)
    grantee_user = BasicUserSerializer(read_only=True)
    category_display = serializers.CharField(source='get_data_category_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_active = serializers.ReadOnlyField()

    class Meta:
        model = ProgressiveConsent
        fields = [
            'uuid', 'grantor',
            'grantee_user', 'grantee_tenant',
            'data_category', 'category_display',
            'status', 'status_display', 'is_active',
            'context_type', 'context_id', 'purpose',
            'requested_at', 'responded_at', 'expires_at', 'revoked_at'
        ]
        read_only_fields = [
            'uuid', 'grantor', 'status', 'is_active',
            'requested_at', 'responded_at', 'revoked_at'
        ]


class ConsentRequestSerializer(serializers.Serializer):
    """Serializer for requesting consent from a user."""
    data_subject_id = serializers.IntegerField(
        help_text="User ID of the data subject"
    )
    data_category = serializers.ChoiceField(
        choices=ProgressiveConsent.DataCategory.choices
    )
    purpose = serializers.CharField(required=True)
    context_type = serializers.CharField(required=False, allow_blank=True)
    context_id = serializers.IntegerField(required=False, allow_null=True)
    expires_in_days = serializers.IntegerField(
        required=False, default=90, min_value=1, max_value=365
    )


class ConsentGrantSerializer(serializers.Serializer):
    """Serializer for granting or denying consent."""
    consent_uuid = serializers.UUIDField()
    action = serializers.ChoiceField(choices=['grant', 'deny'])


class ConsentRevokeSerializer(serializers.Serializer):
    """Serializer for revoking previously granted consent."""
    consent_uuid = serializers.UUIDField()


# ==================== AUDIT SERIALIZERS ====================

class DataAccessLogSerializer(serializers.ModelSerializer):
    """
    Data access log serializer (read-only audit trail).

    Records who accessed what data and when.
    """
    accessor = BasicUserSerializer(read_only=True)
    data_subject = BasicUserSerializer(read_only=True)

    class Meta:
        model = DataAccessLog
        fields = [
            'uuid', 'accessor', 'accessor_tenant', 'data_subject',
            'data_category', 'data_fields', 'consent',
            'access_reason', 'ip_address', 'endpoint', 'accessed_at'
        ]
        read_only_fields = fields  # All fields are read-only


class LoginHistorySerializer(serializers.ModelSerializer):
    """
    Login history serializer (read-only security log).

    Records login attempts and results.
    """
    user = BasicUserSerializer(read_only=True)
    result_display = serializers.CharField(source='get_result_display', read_only=True)

    class Meta:
        model = LoginHistory
        fields = [
            'user', 'result', 'result_display',
            'ip_address', 'user_agent', 'location',
            'device_fingerprint', 'failure_reason', 'timestamp'
        ]
        read_only_fields = fields  # All fields are read-only


# ==================== AUTHENTICATION SERIALIZERS ====================

class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    User registration serializer with password validation.

    Creates user and associated profile.
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    profile_type = serializers.ChoiceField(
        choices=UserProfile.ProfileType.choices,
        default=UserProfile.ProfileType.CANDIDATE
    )

    class Meta:
        model = User
        fields = [
            'email', 'username', 'first_name', 'last_name',
            'password', 'password_confirm', 'profile_type'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate_email(self, value):
        """Ensure email is unique."""
        if User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError(
                _("A user with this email already exists.")
            )
        return value.lower()

    def validate(self, attrs):
        """Validate passwords match."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': _("Passwords do not match.")
            })
        return attrs

    def create(self, validated_data):
        profile_type = validated_data.pop('profile_type')
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')

        # Create user
        user = User.objects.create_user(
            password=password,
            **validated_data
        )

        # Create profile
        UserProfile.objects.create(
            user=user,
            profile_type=profile_type
        )

        return user


class UserLoginSerializer(serializers.Serializer):
    """
    User login serializer with authentication.

    Supports email or username login.
    """
    email = serializers.CharField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Try to authenticate with email
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password
            )

            # If email auth fails, try username
            if not user:
                try:
                    user_obj = User.objects.get(email=email.lower())
                    user = authenticate(
                        request=self.context.get('request'),
                        username=user_obj.username,
                        password=password
                    )
                except User.DoesNotExist:
                    pass

            if not user:
                raise serializers.ValidationError(
                    _("Unable to log in with provided credentials."),
                    code='authorization'
                )

            if not user.is_active:
                raise serializers.ValidationError(
                    _("User account is disabled."),
                    code='authorization'
                )

            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError(
                _("Must include 'email' and 'password'."),
                code='authorization'
            )


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""
    old_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                _("Current password is incorrect.")
            )
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': _("New passwords do not match.")
            })
        return attrs


class CurrentUserSerializer(serializers.ModelSerializer):
    """
    Serializer for current authenticated user.

    Includes profile and tenant memberships.
    """
    profile = serializers.SerializerMethodField()
    tenant_memberships = serializers.SerializerMethodField()
    kyc_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'is_active', 'date_joined', 'last_login',
            'mfa_enabled', 'anonymous_mode',
            'profile', 'tenant_memberships', 'kyc_status'
        ]
        read_only_fields = ['id', 'email', 'date_joined', 'last_login']

    @extend_schema_field(OpenApiTypes.STR)
    def get_profile(self, obj):
        try:
            return UserProfileSerializer(obj.profile, context=self.context).data
        except UserProfile.DoesNotExist:
            return None

    @extend_schema_field(OpenApiTypes.STR)
    def get_tenant_memberships(self, obj):
        memberships = TenantUser.objects.filter(user=obj, is_active=True)
        return TenantUserSerializer(memberships, many=True, context=self.context).data

    @extend_schema_field(OpenApiTypes.STR)
    def get_kyc_status(self, obj):
        """Get overall KYC verification status."""
        verifications = KYCVerification.objects.filter(user=obj)
        if not verifications.exists():
            return {'status': 'none', 'verified_types': []}

        verified = verifications.filter(
            status=KYCVerification.VerificationStatus.VERIFIED,
            expires_at__gt=timezone.now()
        )

        if verified.exists():
            return {
                'status': 'verified',
                'verified_types': list(verified.values_list('verification_type', flat=True)),
                'highest_level': verified.order_by('-level').first().level
            }

        pending = verifications.filter(
            status__in=[
                KYCVerification.VerificationStatus.PENDING,
                KYCVerification.VerificationStatus.IN_PROGRESS
            ]
        )

        if pending.exists():
            return {'status': 'pending', 'verified_types': []}

        return {'status': 'incomplete', 'verified_types': []}


class SecurityQuestionSerializer(serializers.ModelSerializer):
    """Serializer for security questions (write-only answer)."""
    answer = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = SecurityQuestion
        fields = ['id', 'question', 'answer', 'created_at']
        read_only_fields = ['id', 'created_at']

    def create(self, validated_data):
        from django.contrib.auth.hashers import make_password
        answer = validated_data.pop('answer')
        validated_data['answer_hash'] = make_password(answer.lower().strip())
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


# ==================== TRUST SCORE SERIALIZERS ====================

class TrustScoreSerializer(serializers.ModelSerializer):
    """
    Trust score serializer with computed fields.

    Provides comprehensive trust information for users.
    """
    user = BasicUserSerializer(read_only=True)
    trust_level_display = serializers.CharField(source='get_trust_level_display', read_only=True)
    entity_type_display = serializers.CharField(source='get_entity_type_display', read_only=True)
    trust_explanation = serializers.ReadOnlyField()

    class Meta:
        model = TrustScore
        fields = [
            'uuid', 'user', 'entity_type', 'entity_type_display',
            'trust_level', 'trust_level_display',
            # Scores
            'overall_score', 'identity_score', 'career_score',
            'activity_score', 'review_score', 'dispute_score', 'payment_score',
            # Verification flags
            'is_id_verified', 'is_career_verified',
            'verified_employment_count', 'verified_education_count',
            'total_employment_count', 'total_education_count',
            # Activity metrics
            'completed_jobs', 'total_contracts', 'successful_hires', 'on_time_deliveries',
            # Review metrics
            'total_reviews', 'positive_reviews', 'negative_reviews', 'average_rating',
            # Dispute metrics
            'total_disputes', 'disputes_won', 'disputes_lost', 'disputes_pending',
            # Computed
            'trust_explanation',
            # Timestamps
            'created_at', 'updated_at', 'last_calculated_at'
        ]
        read_only_fields = fields  # All fields are read-only


# ==================== EMPLOYMENT VERIFICATION SERIALIZERS ====================

class EmploymentVerificationSerializer(serializers.ModelSerializer):
    """
    Employment verification serializer for CRUD operations.

    Hides sensitive token information from regular users.
    """
    user = BasicUserSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    employment_type_display = serializers.CharField(source='get_employment_type_display', read_only=True)

    class Meta:
        model = EmploymentVerification
        fields = [
            'uuid', 'user',
            # Employment details
            'company_name', 'job_title', 'start_date', 'end_date',
            'is_current', 'employment_type', 'employment_type_display', 'description',
            # Verification contact
            'hr_contact_email', 'hr_contact_name', 'hr_contact_phone', 'company_domain',
            # Status
            'status', 'status_display',
            # Verification details (only show confirmed fields, not response data)
            'dates_confirmed', 'title_confirmed', 'eligible_for_rehire',
            # Timestamps
            'created_at', 'updated_at', 'request_sent_at', 'verified_at', 'expires_at'
        ]
        read_only_fields = [
            'uuid', 'user', 'status', 'dates_confirmed', 'title_confirmed',
            'eligible_for_rehire', 'created_at', 'updated_at',
            'request_sent_at', 'verified_at', 'expires_at'
        ]

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class EmploymentVerificationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new employment verification entries."""

    class Meta:
        model = EmploymentVerification
        fields = [
            'company_name', 'job_title', 'start_date', 'end_date',
            'is_current', 'employment_type', 'description',
            'hr_contact_email', 'hr_contact_name', 'hr_contact_phone', 'company_domain'
        ]

    def validate(self, attrs):
        """Validate date range."""
        if attrs.get('end_date') and attrs.get('start_date'):
            if attrs['end_date'] < attrs['start_date']:
                raise serializers.ValidationError({
                    'end_date': _("End date cannot be before start date.")
                })
        if attrs.get('is_current') and attrs.get('end_date'):
            raise serializers.ValidationError({
                'end_date': _("Current employment should not have an end date.")
            })
        return attrs

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class EmploymentVerificationResponseSerializer(serializers.Serializer):
    """Serializer for handling verification response from HR contacts."""
    token = serializers.CharField(required=True)
    dates_confirmed = serializers.BooleanField(required=True)
    title_confirmed = serializers.BooleanField(required=True)
    eligible_for_rehire = serializers.BooleanField(required=False, allow_null=True)
    performance_rating = serializers.CharField(required=False, allow_blank=True)
    verifier_name = serializers.CharField(required=True)
    verifier_email = serializers.EmailField(required=True)
    notes = serializers.CharField(required=False, allow_blank=True)


# ==================== EDUCATION VERIFICATION SERIALIZERS ====================

class EducationVerificationSerializer(serializers.ModelSerializer):
    """
    Education verification serializer for CRUD operations.
    """
    user = BasicUserSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    degree_type_display = serializers.CharField(source='get_degree_type_display', read_only=True)
    institution_type_display = serializers.SerializerMethodField()
    verification_method_display = serializers.CharField(
        source='get_verification_method_display', read_only=True
    )

    class Meta:
        model = EducationVerification
        fields = [
            'uuid', 'user',
            # Education details
            'institution_name', 'institution_type', 'institution_type_display',
            'degree_type', 'degree_type_display', 'field_of_study',
            'start_date', 'end_date', 'is_current', 'graduated',
            'gpa', 'honors',
            # Institution contact
            'registrar_email', 'institution_domain', 'student_id',
            # Verification method
            'verification_method', 'verification_method_display',
            # Status
            'status', 'status_display',
            # Documents
            'transcript_file', 'diploma_file',
            # Verification details
            'degree_confirmed', 'dates_confirmed', 'graduation_confirmed',
            # Timestamps
            'created_at', 'updated_at', 'request_sent_at', 'verified_at', 'expires_at'
        ]
        read_only_fields = [
            'uuid', 'user', 'status', 'degree_confirmed', 'dates_confirmed',
            'graduation_confirmed', 'created_at', 'updated_at',
            'request_sent_at', 'verified_at', 'expires_at'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_institution_type_display(self, obj):
        """Get display name for institution type."""
        type_map = {
            'university': 'University',
            'college': 'College',
            'high_school': 'High School',
            'vocational': 'Vocational School',
            'online': 'Online Institution',
            'other': 'Other',
        }
        return type_map.get(obj.institution_type, obj.institution_type)

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class EducationVerificationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new education verification entries."""

    class Meta:
        model = EducationVerification
        fields = [
            'institution_name', 'institution_type', 'degree_type', 'field_of_study',
            'start_date', 'end_date', 'is_current', 'graduated',
            'gpa', 'honors',
            'registrar_email', 'institution_domain', 'student_id'
        ]

    def validate(self, attrs):
        """Validate date range and graduation status."""
        if attrs.get('end_date') and attrs.get('start_date'):
            if attrs['end_date'] < attrs['start_date']:
                raise serializers.ValidationError({
                    'end_date': _("End date cannot be before start date.")
                })
        if attrs.get('is_current') and attrs.get('graduated'):
            raise serializers.ValidationError({
                'graduated': _("Cannot be both currently enrolled and graduated.")
            })
        return attrs

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class TranscriptUploadSerializer(serializers.Serializer):
    """Serializer for uploading transcript documents."""
    transcript_file = serializers.FileField(required=True)

    def validate_transcript_file(self, value):
        """Validate file type and size."""
        allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
        if value.content_type not in allowed_types:
            raise serializers.ValidationError(
                _("File type not supported. Please upload PDF, JPEG, or PNG.")
            )
        if value.size > 10 * 1024 * 1024:  # 10MB
            raise serializers.ValidationError(
                _("File size exceeds 10MB limit.")
            )
        return value


# ==================== REVIEW SERIALIZERS ====================

class ReviewSerializer(serializers.ModelSerializer):
    """
    Review serializer for read operations.
    """
    reviewer = BasicUserSerializer(read_only=True)
    reviewee = BasicUserSerializer(read_only=True)
    review_type_display = serializers.CharField(source='get_review_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Review
        fields = [
            'uuid', 'reviewer', 'reviewee',
            'review_type', 'review_type_display',
            'context_type', 'context_id',
            # Ratings
            'overall_rating', 'communication_rating', 'professionalism_rating',
            'quality_rating', 'timeliness_rating',
            'would_recommend', 'would_work_again',
            # Content
            'title', 'content', 'pros', 'cons',
            # Status
            'status', 'status_display',
            'is_negative', 'requires_verification',
            # Response (for reviewee)
            'reviewee_response',
            # Timestamps
            'created_at', 'updated_at', 'published_at', 'disputed_at', 'resolved_at'
        ]
        read_only_fields = [
            'uuid', 'reviewer', 'reviewee', 'status', 'is_negative',
            'requires_verification', 'created_at', 'updated_at',
            'published_at', 'disputed_at', 'resolved_at'
        ]


class ReviewCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new reviews."""
    reviewee_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = None  # Set dynamically
        fields = [
            'reviewee_id', 'review_type', 'context_type', 'context_id',
            'overall_rating', 'communication_rating', 'professionalism_rating',
            'quality_rating', 'timeliness_rating',
            'would_recommend', 'would_work_again',
            'title', 'content', 'pros', 'cons'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from ..models import Review
        self.Meta.model = Review

    def validate_reviewee_id(self, value):
        """Validate reviewee exists and is not the reviewer."""
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(_("User not found."))

        if self.context['request'].user.id == value:
            raise serializers.ValidationError(_("Cannot review yourself."))
        return value

    def validate(self, attrs):
        """Validate review doesn't already exist for this context."""
        from ..models import Review
        reviewer = self.context['request'].user
        reviewee_id = attrs.get('reviewee_id')
        context_type = attrs.get('context_type', '')
        context_id = attrs.get('context_id')

        existing = Review.objects.filter(
            reviewer=reviewer,
            reviewee_id=reviewee_id,
            context_type=context_type,
            context_id=context_id
        ).exists()

        if existing:
            raise serializers.ValidationError(
                _("You have already reviewed this user for this context.")
            )
        return attrs

    def create(self, validated_data):
        reviewee_id = validated_data.pop('reviewee_id')
        validated_data['reviewer'] = self.context['request'].user
        validated_data['reviewee_id'] = reviewee_id
        return super().create(validated_data)


class ReviewDisputeSerializer(serializers.Serializer):
    """Serializer for disputing a review."""
    response = serializers.CharField(required=True, min_length=50)
    evidence = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        default=list
    )


class ReviewResponseSerializer(serializers.Serializer):
    """Serializer for reviewee to respond to a review."""
    response = serializers.CharField(required=True, min_length=10, max_length=2000)


# ==================== CANDIDATE CV SERIALIZERS ====================

class CandidateCVSerializer(serializers.ModelSerializer):
    """
    Candidate CV serializer for read operations.
    """
    user = BasicUserSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = None  # Set dynamically
        fields = [
            'uuid', 'user',
            'name', 'slug', 'is_primary', 'status', 'status_display',
            # Target
            'target_job_types', 'target_industries', 'target_keywords',
            # Content
            'summary', 'headline', 'skills', 'highlighted_skills',
            # Experience selection
            'included_experiences', 'experience_order', 'included_education',
            # Portfolio
            'projects', 'certifications',
            # Files
            'cv_file',
            # AI Analysis
            'ai_score', 'ai_feedback', 'ats_compatibility_score', 'last_analyzed_at',
            # Usage stats
            'times_used', 'last_used_at', 'applications_count', 'interview_rate',
            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'uuid', 'user', 'slug', 'ai_score', 'ai_feedback',
            'ats_compatibility_score', 'last_analyzed_at',
            'times_used', 'last_used_at', 'applications_count', 'interview_rate',
            'created_at', 'updated_at'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from ..models import CandidateCV
        self.Meta.model = CandidateCV

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class CandidateCVCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new CVs."""

    class Meta:
        model = None  # Set dynamically
        fields = [
            'name', 'is_primary', 'status',
            'target_job_types', 'target_industries', 'target_keywords',
            'summary', 'headline', 'skills', 'highlighted_skills',
            'included_experiences', 'experience_order', 'included_education',
            'projects', 'certifications', 'cv_file'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from ..models import CandidateCV
        self.Meta.model = CandidateCV

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class BestCVMatchSerializer(serializers.Serializer):
    """Serializer for requesting best CV match for a job."""
    job_description = serializers.CharField(required=True)
    job_keywords = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list
    )


# ==================== STUDENT PROFILE SERIALIZERS ====================

class StudentProfileSerializer(serializers.ModelSerializer):
    """
    Student profile serializer for read operations.
    """
    user = BasicUserSerializer(read_only=True)
    student_type_display = serializers.CharField(source='get_student_type_display', read_only=True)
    program_type_display = serializers.CharField(source='get_program_type_display', read_only=True)
    enrollment_status_display = serializers.CharField(source='get_enrollment_status_display', read_only=True)
    is_eligible_for_work = serializers.ReadOnlyField()

    class Meta:
        model = None  # Set dynamically
        fields = [
            'uuid', 'user',
            'student_type', 'student_type_display',
            'program_type', 'program_type_display',
            # Institution
            'institution_name', 'institution_type', 'institution_email_domain',
            'student_email', 'student_id',
            # Program details
            'program_name', 'faculty', 'major', 'minor',
            'expected_graduation', 'current_year', 'current_term',
            # Enrollment
            'enrollment_status', 'enrollment_status_display',
            'enrollment_verified', 'enrollment_verified_at',
            # Co-op details
            'coop_sequence', 'work_terms_completed', 'work_terms_required',
            'next_work_term_start', 'next_work_term_end',
            # GPA
            'gpa', 'gpa_scale', 'gpa_verified',
            # Skills and interests
            'skills', 'interests', 'preferred_industries',
            'preferred_locations', 'remote_preference',
            # Work authorization
            'work_authorization', 'work_permit_expiry',
            # Coordinator
            'coordinator_name', 'coordinator_email',
            # Computed
            'is_eligible_for_work',
            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'uuid', 'user', 'enrollment_verified', 'enrollment_verified_at',
            'gpa_verified', 'is_eligible_for_work', 'created_at', 'updated_at'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from ..models import StudentProfile
        self.Meta.model = StudentProfile

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class StudentProfileCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new student profiles."""

    class Meta:
        model = None  # Set dynamically
        fields = [
            'student_type', 'program_type',
            'institution_name', 'institution_type', 'institution_email_domain',
            'student_email', 'student_id',
            'program_name', 'faculty', 'major', 'minor',
            'expected_graduation', 'current_year', 'current_term',
            'coop_sequence', 'work_terms_completed', 'work_terms_required',
            'next_work_term_start', 'next_work_term_end',
            'gpa', 'gpa_scale',
            'skills', 'interests', 'preferred_industries',
            'preferred_locations', 'remote_preference',
            'work_authorization', 'work_permit_expiry',
            'coordinator_name', 'coordinator_email'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from ..models import StudentProfile
        self.Meta.model = StudentProfile

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class CoopTermSerializer(serializers.ModelSerializer):
    """
    Co-op term serializer for read operations.
    """
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = None  # Set dynamically
        fields = [
            'uuid', 'student',
            'term_number', 'term_name', 'start_date', 'end_date',
            'status', 'status_display',
            # Employer/Position
            'employer_name', 'employer_tenant', 'job_title',
            'job_description', 'location', 'is_remote',
            # Compensation
            'hourly_rate', 'currency',
            # Evaluation
            'employer_rating', 'student_rating',
            # School approval
            'school_approved', 'school_approved_by', 'school_approved_at',
            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'uuid', 'student', 'employer_rating', 'student_rating',
            'school_approved', 'school_approved_by', 'school_approved_at',
            'created_at', 'updated_at'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from ..models import CoopTerm
        self.Meta.model = CoopTerm


# ==================== VERIFICATION SERIALIZERS ====================

class KYCVerificationSerializer(serializers.Serializer):
    """
    Serializer for KYC document submission.
    Supports passport, driver's license, and national ID.
    """
    document_type = serializers.ChoiceField(choices=[
        ('passport', _('Passport')),
        ('drivers_license', _("Driver's License")),
        ('national_id', _('National ID')),
    ])
    document_file = serializers.FileField()
    document_number = serializers.CharField(max_length=50)

    def validate_document_file(self, value):
        """Validate file size and type."""
        # Max 5MB
        if value.size > 5 * 1024 * 1024:
            raise serializers.ValidationError(_("File size exceeds 5MB limit."))

        # Allowed types
        allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
        if value.content_type not in allowed_types:
            raise serializers.ValidationError(_("Unsupported file type. Use PDF, JPEG, or PNG."))

        return value


class CVVerificationSerializer(serializers.Serializer):
    """
    Serializer for CV upload and verification.
    Supports PDF, DOC, and DOCX formats.
    """
    cv_file = serializers.FileField()

    def validate_cv_file(self, value):
        """Validate CV file."""
        # Max 5MB
        if value.size > 5 * 1024 * 1024:
            raise serializers.ValidationError(_("File size exceeds 5MB limit."))

        # Allowed types
        allowed_types = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
        if value.content_type not in allowed_types:
            raise serializers.ValidationError(_("Unsupported file type. Use PDF, DOC, or DOCX."))

        return value


class VerificationStatusSerializer(serializers.Serializer):
    """
    Serializer for verification status display.
    Shows user CV/KYC verification and tenant EIN verification (if applicable).
    """
    cv_verified = serializers.BooleanField()
    cv_verified_at = serializers.DateTimeField(allow_null=True)
    kyc_verified = serializers.BooleanField()
    kyc_verified_at = serializers.DateTimeField(allow_null=True)

    # Optional tenant verification (if user has tenant)
    ein_verified = serializers.BooleanField(required=False)
    ein_verified_at = serializers.DateTimeField(allow_null=True, required=False)


# ============================================
# TENANT PROFILE SERIALIZERS
# ============================================

class TenantProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for TenantProfile.
    Combines tenant-specific employment data with synced public profile fields.
    """
    sync_status = serializers.ReadOnlyField()
    full_address = serializers.ReadOnlyField()
    display_name_or_email = serializers.ReadOnlyField()
    user_email = serializers.EmailField(source='user.email', read_only=True)
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True, allow_null=True)

    class Meta:
        model = TenantProfile
        fields = [
            'uuid',
            'user_email',
            'tenant_name',
            # Employment Details (tenant-specific)
            'employee_id',
            'department',
            'department_name',
            'job_title',
            'reports_to',
            'hire_date',
            'employment_type',
            # Personal/Private Data (tenant-specific)
            'address_line1',
            'address_line2',
            'postal_code',
            'date_of_birth',
            'emergency_contact_name',
            'emergency_contact_phone',
            # Synced Fields (from PublicProfile)
            'full_name',
            'avatar_url',
            'bio',
            'email',
            'phone',
            'city',
            'state',
            'country',
            'linkedin_url',
            'github_url',
            'portfolio_url',
            'skills_json',
            'languages_json',
            # Sync Metadata
            'last_synced_at',
            'synced_fields',
            # Computed
            'sync_status',
            'full_address',
            'display_name_or_email',
            # Timestamps
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'user_email',
            'tenant_name',
            'department_name',
            # Synced fields (read-only, updated via sync)
            'full_name',
            'avatar_url',
            'bio',
            'email',
            'phone',
            'city',
            'state',
            'country',
            'linkedin_url',
            'github_url',
            'portfolio_url',
            'skills_json',
            'languages_json',
            # Sync metadata
            'last_synced_at',
            'synced_fields',
            'sync_status',
            'full_address',
            'display_name_or_email',
            'created_at',
            'updated_at',
        ]


class TenantProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating tenant-specific fields only.
    Synced fields from PublicProfile are read-only.
    """
    class Meta:
        model = TenantProfile
        fields = [
            # Employment Details
            'employee_id',
            'department',
            'job_title',
            'reports_to',
            'hire_date',
            'employment_type',
            # Personal/Private Data
            'address_line1',
            'address_line2',
            'postal_code',
            'date_of_birth',
            'emergency_contact_name',
            'emergency_contact_phone',
        ]


class ProfileSyncTriggerSerializer(serializers.Serializer):
    """
    Serializer for manual profile sync trigger.
    Allows optional field overrides for one-time sync.
    """
    field_overrides = serializers.DictField(
        child=serializers.BooleanField(),
        required=False,
        allow_null=True,
        help_text=_('Optional field overrides for this sync only. Example: {"sync_phone": true}')
    )

    def validate_field_overrides(self, value):
        """Validate field override keys."""
        if not value:
            return value

        allowed_fields = [
            'sync_display_name', 'sync_avatar', 'sync_bio',
            'sync_public_email', 'sync_phone',
            'sync_city', 'sync_state', 'sync_country',
            'sync_linkedin', 'sync_github', 'sync_portfolio',
            'sync_skills', 'sync_languages'
        ]

        invalid_fields = [k for k in value.keys() if k not in allowed_fields]
        if invalid_fields:
            raise serializers.ValidationError(
                f"Invalid field overrides: {', '.join(invalid_fields)}. "
                f"Allowed fields: {', '.join(allowed_fields)}"
            )

        return value

# ==================== FREELANCER PROFILE SERIALIZERS ====================

class FreelancerProfileSerializer(serializers.ModelSerializer):
    """
    Freelancer profile serializer for read/update operations.

    Includes computed fields and nested user information.
    """
    user = BasicUserSerializer(read_only=True)
    availability_status_display = serializers.CharField(
        source='get_availability_status_display',
        read_only=True
    )
    hourly_rate_currency_display = serializers.CharField(
        source='get_hourly_rate_currency_display',
        read_only=True
    )
    is_available_for_work = serializers.ReadOnlyField()
    has_portfolio = serializers.ReadOnlyField()
    completion_rate = serializers.ReadOnlyField()

    class Meta:
        model = FreelancerProfile
        fields = [
            'uuid', 'user',
            # Professional info
            'professional_title', 'bio', 'years_of_experience',
            # Availability
            'availability_status', 'availability_status_display',
            'availability_hours_per_week', 'is_available_for_work',
            # Pricing
            'hourly_rate', 'hourly_rate_currency', 'hourly_rate_currency_display',
            'minimum_project_budget',
            # Skills and expertise
            'skills', 'categories', 'years_of_experience',
            # Portfolio & Links
            'portfolio_url', 'github_url', 'linkedin_url',
            'behance_url', 'dribbble_url', 'has_portfolio',
            # Location & Remote Work
            'city', 'country', 'timezone',
            'willing_to_relocate', 'remote_only',
            # Verification & Trust
            'is_verified', 'verification_date',
            'identity_verified', 'payment_method_verified',
            # Platform Stats (read-only)
            'completed_projects', 'completed_services',
            'total_earnings', 'average_rating', 'total_reviews',
            'completion_rate',
            # Relationships
            'service_provider',
            # Timestamps
            'created_at', 'updated_at', 'last_active_at'
        ]
        read_only_fields = [
            'uuid', 'user',
            'is_verified', 'verification_date',
            'identity_verified', 'payment_method_verified',
            'completed_projects', 'completed_services',
            'total_earnings', 'average_rating', 'total_reviews',
            'is_available_for_work', 'has_portfolio', 'completion_rate',
            'created_at', 'updated_at', 'last_active_at'
        ]

    def validate_hourly_rate(self, value):
        """Validate hourly rate is positive."""
        if value <= 0:
            raise serializers.ValidationError("Hourly rate must be greater than 0")
        return value

    def validate_minimum_project_budget(self, value):
        """Validate minimum project budget if provided."""
        if value is not None and value <= 0:
            raise serializers.ValidationError("Minimum project budget must be greater than 0")
        return value

    def validate_availability_hours_per_week(self, value):
        """Validate availability hours per week is within valid range."""
        if value < 1 or value > 168:
            raise serializers.ValidationError(
                "Availability hours per week must be between 1 and 168 (hours in a week)"
            )
        return value

    def validate_years_of_experience(self, value):
        """Validate years of experience is reasonable."""
        if value < 0 or value > 50:
            raise serializers.ValidationError(
                "Years of experience must be between 0 and 50"
            )
        return value


class FreelancerProfileCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new freelancer profiles.

    Automatically associates profile with the authenticated user.
    """

    class Meta:
        model = FreelancerProfile
        fields = [
            # Professional info (required)
            'professional_title', 'bio', 'years_of_experience',
            # Availability
            'availability_status', 'availability_hours_per_week',
            # Pricing
            'hourly_rate', 'hourly_rate_currency', 'minimum_project_budget',
            # Skills and expertise
            'skills', 'categories',
            # Portfolio & Links
            'portfolio_url', 'github_url', 'linkedin_url',
            'behance_url', 'dribbble_url',
            # Location & Remote Work
            'city', 'country', 'timezone',
            'willing_to_relocate', 'remote_only',
        ]

    def validate(self, attrs):
        """Check if user already has a freelancer profile."""
        user = self.context['request'].user
        if hasattr(user, 'freelancer_profile'):
            raise serializers.ValidationError(
                "You already have a freelancer profile. Use PUT/PATCH to update it."
            )
        return attrs

    def create(self, validated_data):
        """Create freelancer profile for authenticated user."""
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class FreelancerProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating existing freelancer profiles.

    Allows updating all non-system fields.
    """

    class Meta:
        model = FreelancerProfile
        fields = [
            # Professional info
            'professional_title', 'bio', 'years_of_experience',
            # Availability
            'availability_status', 'availability_hours_per_week',
            # Pricing
            'hourly_rate', 'hourly_rate_currency', 'minimum_project_budget',
            # Skills and expertise
            'skills', 'categories',
            # Portfolio & Links
            'portfolio_url', 'github_url', 'linkedin_url',
            'behance_url', 'dribbble_url',
            # Location & Remote Work
            'city', 'country', 'timezone',
            'willing_to_relocate', 'remote_only',
        ]

    def validate_hourly_rate(self, value):
        """Validate hourly rate is positive."""
        if value <= 0:
            raise serializers.ValidationError("Hourly rate must be greater than 0")
        return value

    def validate_minimum_project_budget(self, value):
        """Validate minimum project budget if provided."""
        if value is not None and value <= 0:
            raise serializers.ValidationError("Minimum project budget must be greater than 0")
        return value


class FreelancerProfileListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for listing freelancer profiles.

    Used in browse/search endpoints for performance.
    """
    user_name = serializers.SerializerMethodField()
    availability_status_display = serializers.CharField(
        source='get_availability_status_display',
        read_only=True
    )

    class Meta:
        model = FreelancerProfile
        fields = [
            'uuid',
            'user_name',
            'professional_title',
            'city',
            'country',
            'hourly_rate',
            'hourly_rate_currency',
            'availability_status',
            'availability_status_display',
            'is_verified',
            'average_rating',
            'total_reviews',
            'completed_projects',
            'completed_services',
            'skills',
            'remote_only',
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_user_name(self, obj):
        """Return user's full name or email."""
        full_name = obj.user.get_full_name()
        return full_name if full_name else obj.user.email
