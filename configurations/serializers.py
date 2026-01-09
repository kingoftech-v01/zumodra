"""
Configurations App Serializers.

Provides serializers for:
- Skill taxonomy
- Company/Organization structure (Company, Site, Department, Role)
- Job board models (Job, JobApplication)
- Website content (FAQ, Testimonial)
"""

from rest_framework import serializers

from core.serializers import TenantAwareSerializer, AuditedSerializerMixin

from .models import (
    Skill,
    Company,
    Site,
    CompanyProfile,
    Department,
    Role,
    Membership,
    CandidateProfile,
    JobPosition,
    Job,
    JobApplication,
    EmployeeRecord,
    ContractDocument,
    Interview,
    InterviewNote,
    OnboardingChecklist,
    LeaveRequest,
    Timesheet,
    EmployeeDocument,
    InternalNotification,
    WorkExperience,
    Education,
    Certification,
    CandidateDocument,
    ApplicationNote,
    ApplicationMessage,
    FAQEntry,
    Partnership,
    Testimonial,
    TrustedCompany,
)


# =============================================================================
# SKILL SERIALIZERS
# =============================================================================

class SkillListSerializer(TenantAwareSerializer):
    """List serializer for skills."""

    class Meta:
        model = Skill
        fields = ['id', 'name', 'slug', 'category', 'is_verified', 'created_at']
        read_only_fields = ['id', 'slug', 'created_at']


class SkillDetailSerializer(TenantAwareSerializer):
    """Detail serializer for skills."""

    class Meta:
        model = Skill
        fields = ['id', 'name', 'slug', 'description', 'category', 'is_verified', 'created_at', 'updated_at']
        read_only_fields = ['id', 'slug', 'created_at', 'updated_at']


class SkillCreateSerializer(TenantAwareSerializer):
    """Create serializer for skills."""

    class Meta:
        model = Skill
        fields = ['name', 'description', 'category']


# =============================================================================
# COMPANY SERIALIZERS
# =============================================================================

class CompanyListSerializer(TenantAwareSerializer):
    """List serializer for companies."""

    class Meta:
        model = Company
        fields = ['id', 'name', 'slug', 'industry', 'logo', 'is_verified', 'employee_count']
        read_only_fields = ['id', 'slug']


class CompanyDetailSerializer(TenantAwareSerializer):
    """Detail serializer for companies."""
    sites_count = serializers.SerializerMethodField()

    class Meta:
        model = Company
        fields = [
            'id', 'name', 'slug', 'description', 'domain', 'industry',
            'logo', 'website', 'employee_count', 'founded_year',
            'is_verified', 'sites_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'slug', 'created_at', 'updated_at']

    def get_sites_count(self, obj):
        return obj.sites.count()


class CompanyCreateSerializer(TenantAwareSerializer):
    """Create serializer for companies."""

    class Meta:
        model = Company
        fields = ['name', 'description', 'domain', 'industry', 'logo', 'website', 'employee_count', 'founded_year']


# =============================================================================
# SITE SERIALIZERS
# =============================================================================

class SiteListSerializer(TenantAwareSerializer):
    """List serializer for sites."""
    company_name = serializers.CharField(source='company.name', read_only=True)

    class Meta:
        model = Site
        fields = ['id', 'name', 'company', 'company_name', 'city', 'country', 'is_main_office', 'is_active']
        read_only_fields = ['id']


class SiteDetailSerializer(TenantAwareSerializer):
    """Detail serializer for sites."""
    company_name = serializers.CharField(source='company.name', read_only=True)

    class Meta:
        model = Site
        fields = [
            'id', 'company', 'company_name', 'name', 'address', 'city',
            'state', 'postal_code', 'country', 'phone', 'email',
            'established_date', 'number_of_employees', 'is_main_office',
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class SiteCreateSerializer(TenantAwareSerializer):
    """Create serializer for sites."""

    class Meta:
        model = Site
        fields = [
            'company', 'name', 'address', 'city', 'state', 'postal_code',
            'country', 'phone', 'email', 'established_date', 'number_of_employees',
            'is_main_office', 'is_active'
        ]


# =============================================================================
# DEPARTMENT SERIALIZERS
# =============================================================================

class DepartmentListSerializer(TenantAwareSerializer):
    """List serializer for departments."""
    company_name = serializers.CharField(source='company.company.name', read_only=True)
    manager_name = serializers.SerializerMethodField()
    members_count = serializers.SerializerMethodField()

    class Meta:
        model = Department
        fields = ['id', 'name', 'company', 'company_name', 'manager', 'manager_name', 'parent', 'members_count']
        read_only_fields = ['id']

    def get_manager_name(self, obj):
        return obj.manager.get_full_name() if obj.manager else None

    def get_members_count(self, obj):
        return obj.memberships.filter(is_active=True).count()


class DepartmentDetailSerializer(TenantAwareSerializer):
    """Detail serializer for departments."""
    company_name = serializers.CharField(source='company.company.name', read_only=True)
    manager_name = serializers.SerializerMethodField()
    parent_name = serializers.CharField(source='parent.name', read_only=True)
    sub_departments = serializers.SerializerMethodField()

    class Meta:
        model = Department
        fields = [
            'id', 'name', 'description', 'company', 'company_name',
            'manager', 'manager_name', 'parent', 'parent_name',
            'sub_departments', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_manager_name(self, obj):
        return obj.manager.get_full_name() if obj.manager else None

    def get_sub_departments(self, obj):
        return [{'id': d.id, 'name': d.name} for d in obj.sub_departments.all()]


class DepartmentCreateSerializer(TenantAwareSerializer):
    """Create serializer for departments."""

    class Meta:
        model = Department
        fields = ['name', 'description', 'company', 'manager', 'parent']


# =============================================================================
# ROLE SERIALIZERS
# =============================================================================

class RoleListSerializer(TenantAwareSerializer):
    """List serializer for roles."""
    company_name = serializers.CharField(source='company.company.name', read_only=True)
    members_count = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'name', 'company', 'company_name', 'is_default', 'members_count']
        read_only_fields = ['id']

    def get_members_count(self, obj):
        return obj.memberships.filter(is_active=True).count()


class RoleDetailSerializer(TenantAwareSerializer):
    """Detail serializer for roles."""
    company_name = serializers.CharField(source='company.company.name', read_only=True)
    permissions_list = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = [
            'id', 'name', 'description', 'company', 'company_name',
            'group', 'is_default', 'permissions_list', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_permissions_list(self, obj):
        return list(obj.permissions.values_list('codename', flat=True))


class RoleCreateSerializer(TenantAwareSerializer):
    """Create serializer for roles."""

    class Meta:
        model = Role
        fields = ['name', 'description', 'company', 'is_default']


# =============================================================================
# MEMBERSHIP SERIALIZERS
# =============================================================================

class MembershipListSerializer(TenantAwareSerializer):
    """List serializer for memberships."""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    company_name = serializers.CharField(source='company.company.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = Membership
        fields = [
            'id', 'user', 'user_email', 'user_name', 'company', 'company_name',
            'department', 'department_name', 'role', 'role_name', 'job_title', 'is_active'
        ]
        read_only_fields = ['id']

    def get_user_name(self, obj):
        return obj.user.get_full_name()


class MembershipDetailSerializer(TenantAwareSerializer):
    """Detail serializer for memberships."""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    company_name = serializers.CharField(source='company.company.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Membership
        fields = [
            'id', 'user', 'user_email', 'user_name', 'company', 'company_name',
            'department', 'department_name', 'role', 'role_name', 'job_title',
            'is_active', 'joined_at', 'permissions', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'joined_at', 'created_at', 'updated_at']

    def get_user_name(self, obj):
        return obj.user.get_full_name()

    def get_permissions(self, obj):
        return list(obj.get_all_permissions())


# =============================================================================
# JOB SERIALIZERS
# =============================================================================

class JobPositionSerializer(TenantAwareSerializer):
    """Serializer for job positions."""
    company_name = serializers.CharField(source='company.company.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    site_name = serializers.CharField(source='site.name', read_only=True)

    class Meta:
        model = JobPosition
        fields = [
            'id', 'title', 'description', 'company', 'company_name',
            'site', 'site_name', 'department', 'department_name', 'is_open'
        ]
        read_only_fields = ['id']


class JobListSerializer(TenantAwareSerializer):
    """List serializer for jobs."""
    company_name = serializers.CharField(source='company.name', read_only=True)
    position_title = serializers.CharField(source='position.title', read_only=True)
    applications_count = serializers.SerializerMethodField()

    class Meta:
        model = Job
        fields = [
            'id', 'title', 'company', 'company_name', 'position', 'position_title',
            'salary_from', 'salary_to', 'currency', 'is_active', 'posted_at',
            'closes_at', 'applications_count'
        ]
        read_only_fields = ['id', 'posted_at']

    def get_applications_count(self, obj):
        return obj.applications.count()


class JobDetailSerializer(TenantAwareSerializer):
    """Detail serializer for jobs."""
    company_name = serializers.CharField(source='company.name', read_only=True)
    company_logo = serializers.ImageField(source='company.logo', read_only=True)
    position_detail = JobPositionSerializer(source='position', read_only=True)

    class Meta:
        model = Job
        fields = [
            'id', 'title', 'description', 'requirements', 'company', 'company_name',
            'company_logo', 'position', 'position_detail', 'salary_from', 'salary_to',
            'currency', 'is_active', 'posted_at', 'closes_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'posted_at', 'created_at', 'updated_at']


class JobCreateSerializer(TenantAwareSerializer):
    """Create serializer for jobs."""

    class Meta:
        model = Job
        fields = [
            'title', 'description', 'requirements', 'company', 'position',
            'salary_from', 'salary_to', 'currency', 'is_active', 'closes_at'
        ]


# =============================================================================
# JOB APPLICATION SERIALIZERS
# =============================================================================

class JobApplicationListSerializer(TenantAwareSerializer):
    """List serializer for job applications."""
    candidate_email = serializers.CharField(source='candidate.user.email', read_only=True)
    candidate_name = serializers.SerializerMethodField()
    job_title = serializers.CharField(source='job.title', read_only=True)

    class Meta:
        model = JobApplication
        fields = [
            'id', 'candidate', 'candidate_email', 'candidate_name',
            'job', 'job_title', 'status', 'applied_at'
        ]
        read_only_fields = ['id', 'applied_at']

    def get_candidate_name(self, obj):
        return obj.candidate.user.get_full_name()


class JobApplicationDetailSerializer(TenantAwareSerializer):
    """Detail serializer for job applications."""
    candidate_email = serializers.CharField(source='candidate.user.email', read_only=True)
    candidate_name = serializers.SerializerMethodField()
    job_detail = JobListSerializer(source='job', read_only=True)
    reviewed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = JobApplication
        fields = [
            'id', 'candidate', 'candidate_email', 'candidate_name',
            'job', 'job_detail', 'cover_letter', 'status', 'applied_at',
            'reviewed_at', 'reviewed_by', 'reviewed_by_name',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'applied_at', 'created_at', 'updated_at']

    def get_candidate_name(self, obj):
        return obj.candidate.user.get_full_name()

    def get_reviewed_by_name(self, obj):
        return obj.reviewed_by.get_full_name() if obj.reviewed_by else None


class JobApplicationUpdateSerializer(TenantAwareSerializer):
    """Update serializer for job applications (status changes)."""

    class Meta:
        model = JobApplication
        fields = ['status']


# =============================================================================
# FAQ SERIALIZERS
# =============================================================================

class FAQListSerializer(TenantAwareSerializer):
    """List serializer for FAQs."""

    class Meta:
        model = FAQEntry
        fields = ['id', 'question', 'category', 'sort_order', 'is_published']
        read_only_fields = ['id']


class FAQDetailSerializer(TenantAwareSerializer):
    """Detail serializer for FAQs."""

    class Meta:
        model = FAQEntry
        fields = ['id', 'question', 'answer', 'category', 'sort_order', 'is_published', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class FAQCreateSerializer(TenantAwareSerializer):
    """Create serializer for FAQs."""

    class Meta:
        model = FAQEntry
        fields = ['question', 'answer', 'category', 'sort_order', 'is_published']


# =============================================================================
# TESTIMONIAL SERIALIZERS
# =============================================================================

class TestimonialListSerializer(TenantAwareSerializer):
    """List serializer for testimonials."""

    class Meta:
        model = Testimonial
        fields = ['id', 'author_name', 'author_title', 'author_company', 'rating', 'is_featured', 'is_published']
        read_only_fields = ['id']


class TestimonialDetailSerializer(TenantAwareSerializer):
    """Detail serializer for testimonials."""

    class Meta:
        model = Testimonial
        fields = [
            'id', 'author_name', 'author_title', 'author_company', 'content',
            'author_photo', 'rating', 'is_featured', 'is_published',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class TestimonialCreateSerializer(TenantAwareSerializer):
    """Create serializer for testimonials."""

    class Meta:
        model = Testimonial
        fields = ['author_name', 'author_title', 'author_company', 'content', 'author_photo', 'rating', 'is_featured', 'is_published']


# =============================================================================
# PARTNERSHIP SERIALIZERS
# =============================================================================

class PartnershipSerializer(TenantAwareSerializer):
    """Serializer for partnerships."""

    class Meta:
        model = Partnership
        fields = ['id', 'name', 'logo', 'website', 'description', 'is_featured', 'sort_order']
        read_only_fields = ['id']


# =============================================================================
# TRUSTED COMPANY SERIALIZERS
# =============================================================================

class TrustedCompanySerializer(TenantAwareSerializer):
    """Serializer for trusted companies."""

    class Meta:
        model = TrustedCompany
        fields = ['id', 'name', 'logo', 'website', 'sort_order']
        read_only_fields = ['id']


# =============================================================================
# CANDIDATE PROFILE SERIALIZERS
# =============================================================================

class WorkExperienceSerializer(TenantAwareSerializer):
    """Serializer for work experience."""

    class Meta:
        model = WorkExperience
        fields = [
            'id', 'job_title', 'company_name', 'location',
            'start_date', 'end_date', 'is_current', 'description'
        ]
        read_only_fields = ['id']


class EducationSerializer(TenantAwareSerializer):
    """Serializer for education."""

    class Meta:
        model = Education
        fields = [
            'id', 'school_name', 'degree', 'field_of_study',
            'start_date', 'end_date', 'description', 'gpa'
        ]
        read_only_fields = ['id']


class CertificationSerializer(TenantAwareSerializer):
    """Serializer for certifications."""
    is_valid = serializers.BooleanField(read_only=True)

    class Meta:
        model = Certification
        fields = [
            'id', 'name', 'issuing_authority', 'credential_id',
            'credential_url', 'issue_date', 'expiry_date', 'is_valid'
        ]
        read_only_fields = ['id', 'is_valid']


class CandidateProfileSerializer(TenantAwareSerializer):
    """Serializer for candidate profiles."""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    skills_list = SkillListSerializer(source='skills', many=True, read_only=True)
    work_experiences = WorkExperienceSerializer(many=True, read_only=True)
    educations = EducationSerializer(many=True, read_only=True)
    certifications = CertificationSerializer(many=True, read_only=True)

    class Meta:
        model = CandidateProfile
        fields = [
            'id', 'user', 'user_email', 'user_name', 'resume', 'bio',
            'phone', 'linkedin_url', 'github_url', 'portfolio_url',
            'skills', 'skills_list', 'work_experiences', 'educations', 'certifications',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_user_name(self, obj):
        return obj.user.get_full_name()


# =============================================================================
# LEAVE REQUEST SERIALIZERS
# =============================================================================

class LeaveRequestListSerializer(TenantAwareSerializer):
    """List serializer for leave requests."""
    employee_name = serializers.SerializerMethodField()
    leave_type_display = serializers.CharField(source='get_leave_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = LeaveRequest
        fields = [
            'id', 'employee_record', 'employee_name', 'leave_type', 'leave_type_display',
            'start_date', 'end_date', 'duration_days', 'status', 'status_display', 'created_at'
        ]
        read_only_fields = ['id', 'duration_days', 'created_at']

    def get_employee_name(self, obj):
        return obj.employee_record.membership.user.get_full_name()


class LeaveRequestDetailSerializer(TenantAwareSerializer):
    """Detail serializer for leave requests."""
    employee_name = serializers.SerializerMethodField()
    reviewed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = LeaveRequest
        fields = [
            'id', 'employee_record', 'employee_name', 'leave_type', 'start_date',
            'end_date', 'duration_days', 'reason', 'status', 'reviewed_by',
            'reviewed_by_name', 'reviewed_at', 'review_notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'duration_days', 'reviewed_at', 'created_at', 'updated_at']

    def get_employee_name(self, obj):
        return obj.employee_record.membership.user.get_full_name()

    def get_reviewed_by_name(self, obj):
        return obj.reviewed_by.get_full_name() if obj.reviewed_by else None


# =============================================================================
# INTERNAL NOTIFICATION SERIALIZERS
# =============================================================================

class InternalNotificationSerializer(TenantAwareSerializer):
    """Serializer for internal notifications."""
    created_by_name = serializers.SerializerMethodField()

    class Meta:
        model = InternalNotification
        fields = [
            'id', 'company', 'created_by', 'created_by_name', 'title',
            'message', 'target_roles', 'is_urgent', 'is_published',
            'expires_at', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def get_created_by_name(self, obj):
        return obj.created_by.get_full_name() if obj.created_by else None
