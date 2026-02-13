"""
Zumodra Test Configuration - pytest fixtures and factories

This module provides:
- pytest-django configuration
- factory_boy factories for all major models
- Shared fixtures for testing

IMPORTANT (2026-02-12):
=======================
Multi-tenancy has been removed from the platform.
Tenant-related factories (TenantFactory, PlanFactory, DomainFactory, etc.)
are DEPRECATED and marked for removal. They are retained temporarily for
backwards compatibility with existing tests.

All new tests should NOT use tenant factories or tenant-scoped fixtures.
Tests that depend on multi-tenancy are marked with @pytest.mark.deprecated.

NEXT STEPS:
- Update all tests to remove tenant dependencies
- Achieve 99%+ code coverage
- Remove deprecated tenant factories
"""

import pytest
import uuid
from datetime import datetime, timedelta, date
from decimal import Decimal
from django.utils import timezone
from django.db import connection

import factory
from factory import fuzzy
from factory.django import DjangoModelFactory

# Ensure connection.schema_name compatibility for code that still references it
# (django-tenants removed, but many files check connection.schema_name)
if not hasattr(connection, 'schema_name'):
    connection.schema_name = 'public'
if not hasattr(connection, 'set_schema'):
    connection.set_schema = lambda name: None
if not hasattr(connection, 'set_schema_to_public'):
    connection.set_schema_to_public = lambda: None


# ============================================================================
# USER FACTORIES
# ============================================================================

class UserFactory(DjangoModelFactory):
    """Factory for CustomUser model."""

    class Meta:
        model = 'core_identity.CustomUser'
        django_get_or_create = ('email',)

    username = factory.LazyAttribute(lambda o: f"user_{uuid.uuid4().hex[:8]}")
    email = factory.LazyAttribute(lambda o: f"{o.username}@example.com")
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    password = factory.PostGenerationMethodCall('set_password', 'testpass123')
    is_active = True
    mfa_enabled = False
    anonymous_mode = False

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Override create to handle password and strip non-User fields."""
        password = kwargs.pop('password', None)
        # Strip fields that belong to TenantUser, not CustomUser
        tenant = kwargs.pop('tenant', None)
        role = kwargs.pop('role', None)
        kwargs.pop('department', None)
        kwargs.pop('position', None)
        user = super()._create(model_class, *args, **kwargs)
        if password:
            user.set_password(password)
            user.save()
        # If tenant/role provided, create TenantUser association
        if tenant:
            from tenant_profiles.models import TenantUser
            TenantUser.objects.get_or_create(
                user=user, tenant=tenant,
                defaults={'role': role or 'employee', 'is_active': True}
            )
        return user


class SuperUserFactory(UserFactory):
    """Factory for superuser accounts."""

    is_staff = True
    is_superuser = True


# ============================================================================
# DEPRECATED: TENANT FACTORIES (Multi-tenancy removed 2026-02-12)
# These factories are retained for backwards compatibility with existing tests.
# Do NOT use in new tests. Will be removed in a future release.
# ============================================================================

class PlanFactory(DjangoModelFactory):
    """DEPRECATED: Factory for subscription plans."""

    class Meta:
        model = 'tenants.Plan'
        django_get_or_create = ('slug',)

    name = factory.Sequence(lambda n: f"Plan {n}")
    slug = factory.Sequence(lambda n: f"plan-{n}")
    plan_type = 'professional'
    description = factory.Faker('text', max_nb_chars=200)

    price_monthly = Decimal('29.99')
    price_yearly = Decimal('299.99')
    currency = 'USD'

    max_users = 10
    max_job_postings = 25
    max_candidates_per_month = 500
    max_circusales = 3
    storage_limit_gb = 10

    feature_ats = True
    feature_hr_core = True
    feature_analytics = True
    feature_api_access = True
    feature_custom_pipelines = True
    feature_ai_matching = False
    feature_video_interviews = False
    feature_esignature = False
    feature_sso = False
    feature_audit_logs = True
    feature_custom_branding = False
    feature_priority_support = False
    feature_data_export = True
    feature_bulk_actions = True
    feature_advanced_filters = True
    feature_diversity_analytics = False
    feature_compliance_tools = False

    is_active = True
    is_popular = False
    sort_order = 0


class FreePlanFactory(PlanFactory):
    """DEPRECATED: Factory for free tier plan."""

    name = 'Free'
    slug = 'free'
    plan_type = 'free'
    price_monthly = Decimal('0.00')
    price_yearly = Decimal('0.00')
    max_users = 2
    max_job_postings = 3
    max_candidates_per_month = 25
    max_circusales = 1
    storage_limit_gb = 1
    feature_hr_core = False
    feature_analytics = False
    feature_api_access = False
    feature_custom_pipelines = False


class EnterprisePlanFactory(PlanFactory):
    """DEPRECATED: Factory for enterprise tier plan."""

    name = 'Enterprise'
    slug = 'enterprise'
    plan_type = 'enterprise'
    price_monthly = Decimal('299.99')
    price_yearly = Decimal('2999.99')
    max_users = 500
    max_job_postings = 1000
    max_candidates_per_month = 10000
    max_circusales = 50
    storage_limit_gb = 500
    feature_ai_matching = True
    feature_video_interviews = True
    feature_esignature = True
    feature_sso = True
    feature_custom_branding = True
    feature_priority_support = True
    feature_diversity_analytics = True
    feature_compliance_tools = True


class TenantFactory(DjangoModelFactory):
    """DEPRECATED: Factory for multi-tenant organizations."""

    class Meta:
        model = 'tenants.Tenant'
        django_get_or_create = ('slug',)
        skip_postgeneration_save = True

    name = factory.Sequence(lambda n: f"Company {n}")
    slug = factory.Sequence(lambda n: f"company-{n}")
    schema_name = factory.LazyAttribute(lambda o: o.slug.replace('-', '_'))

    status = 'active'
    plan = factory.SubFactory(PlanFactory)

    trial_ends_at = factory.LazyFunction(lambda: timezone.now() + timedelta(days=14))
    paid_until = factory.LazyFunction(lambda: timezone.now() + timedelta(days=30))
    on_trial = False

    owner_email = factory.LazyAttribute(lambda o: f"owner@{o.slug}.com")
    industry = 'Technology'
    company_size = '11-50'
    website = factory.LazyAttribute(lambda o: f"https://{o.slug}.com")

    address_line1 = factory.Faker('street_address')
    city = factory.Faker('city')
    state = factory.Faker('state')
    postal_code = factory.Faker('postcode')
    country = 'CA'

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Create tenant instance, handling legacy 'domain' kwarg."""
        domain = kwargs.pop('domain', None)
        kwargs.pop('auto_create_schema', None)
        kwargs.pop('auto_drop_schema', None)
        obj = model_class(*args, **kwargs)
        obj.save()
        if domain:
            from tenants.models import Domain
            Domain.objects.get_or_create(
                tenant=obj, domain=domain, defaults={'is_primary': True}
            )
        return obj


class TrialTenantFactory(TenantFactory):
    """DEPRECATED: Factory for tenants on trial."""
    status = 'trial'
    on_trial = True
    trial_ends_at = factory.LazyFunction(lambda: timezone.now() + timedelta(days=14))


class TenantSettingsFactory(DjangoModelFactory):
    """DEPRECATED: Factory for tenant settings."""

    class Meta:
        model = 'tenants.TenantSettings'

    tenant = factory.SubFactory(TenantFactory)

    primary_color = '#3B82F6'
    secondary_color = '#1E40AF'
    accent_color = '#10B981'

    default_language = 'en'
    default_timezone = 'America/Toronto'
    date_format = 'YYYY-MM-DD'
    time_format = '24h'
    currency = 'CAD'

    require_cover_letter = False
    auto_reject_after_days = 30
    send_rejection_email = True

    fiscal_year_start_month = 1
    default_pto_days = 15
    approval_workflow_enabled = True

    require_2fa = False
    session_timeout_minutes = 480
    password_expiry_days = 0

    notify_new_application = True
    notify_interview_scheduled = True
    notify_offer_accepted = True
    daily_digest_enabled = False

    career_page_enabled = True
    career_page_title = 'Careers'


class DomainFactory(DjangoModelFactory):
    """DEPRECATED: Factory for tenant domains."""

    class Meta:
        model = 'tenants.Domain'

    tenant = factory.SubFactory(TenantFactory)
    domain = factory.LazyAttribute(lambda o: f"{o.tenant.slug}.localhost")
    is_primary = True
    is_careers_domain = False
    ssl_enabled = True


class TenantInvitationFactory(DjangoModelFactory):
    """DEPRECATED: Factory for tenant invitations."""

    class Meta:
        model = 'tenants.TenantInvitation'

    tenant = factory.SubFactory(TenantFactory)
    email = factory.Faker('email')
    invited_by = factory.SubFactory(UserFactory)
    assigned_role = 'member'
    status = 'pending'
    token = factory.LazyFunction(lambda: uuid.uuid4().hex)
    expires_at = factory.LazyFunction(lambda: timezone.now() + timedelta(days=7))


class TenantUsageFactory(DjangoModelFactory):
    """DEPRECATED: Factory for tenant usage tracking."""

    class Meta:
        model = 'tenants.TenantUsage'

    tenant = factory.SubFactory(TenantFactory)
    user_count = 5
    active_job_count = 3
    total_job_count = 10
    candidate_count_this_month = 50
    total_candidate_count = 200
    circusale_count = 1
    employee_count = 8
    storage_used_bytes = 1024 * 1024 * 100
    api_calls_this_month = 1000


class AuditLogFactory(DjangoModelFactory):
    """DEPRECATED: Factory for tenant audit logs."""

    class Meta:
        model = 'tenants.AuditLog'

    tenant = factory.SubFactory(TenantFactory)
    user = factory.SubFactory(UserFactory)
    action = 'create'
    resource_type = 'JobPosting'
    resource_id = factory.Sequence(lambda n: str(n))
    description = factory.Faker('sentence')
    ip_address = '127.0.0.1'


# ============================================================================
# ACCOUNTS FACTORIES
# ============================================================================

class TenantUserFactory(DjangoModelFactory):
    """Factory for tenant user memberships."""

    class Meta:
        model = 'tenant_profiles.TenantUser'

    user = factory.SubFactory(UserFactory)
    tenant = factory.SubFactory(TenantFactory)
    role = 'employee'
    job_title = factory.Faker('job')
    is_active = True
    is_primary_tenant = True


class AdminTenantUserFactory(TenantUserFactory):
    """Factory for admin tenant users."""
    role = 'admin'


class RecruiterTenantUserFactory(TenantUserFactory):
    """Factory for recruiter tenant users."""
    role = 'recruiter'


class HRManagerTenantUserFactory(TenantUserFactory):
    """Factory for HR manager tenant users."""
    role = 'hr_manager'


class UserProfileFactory(DjangoModelFactory):
    """Factory for user profiles."""

    class Meta:
        model = 'tenant_profiles.UserProfile'

    user = factory.SubFactory(UserFactory)
    profile_type = 'candidate'

    phone = factory.Faker('phone_number')
    phone_verified = False
    date_of_birth = factory.Faker('date_of_birth', minimum_age=18, maximum_age=65)
    nationality = 'Canadian'

    address_line1 = factory.Faker('street_address')
    city = factory.Faker('city')
    state = 'ON'
    postal_code = factory.Faker('postcode')
    country = 'CA'

    bio = factory.Faker('text', max_nb_chars=500)
    linkedin_url = factory.LazyAttribute(lambda o: f"https://linkedin.com/in/{o.user.username}")

    preferred_language = 'en'
    timezone = 'America/Toronto'


class KYCVerificationFactory(DjangoModelFactory):
    """Factory for KYC verifications."""

    class Meta:
        model = 'tenant_profiles.KYCVerification'

    user = factory.SubFactory(UserFactory)
    verification_type = 'identity'
    status = 'pending'
    level = 'basic'
    provider = 'onfido'
    document_type = 'passport'
    document_country = 'CA'


class VerifiedKYCFactory(KYCVerificationFactory):
    """Factory for verified KYC records."""
    status = 'verified'
    confidence_score = Decimal('95.50')
    verified_at = factory.LazyFunction(timezone.now)
    expires_at = factory.LazyFunction(lambda: timezone.now() + timedelta(days=365))


class ProgressiveConsentFactory(DjangoModelFactory):
    """Factory for progressive consent records."""

    class Meta:
        model = 'tenant_profiles.ProgressiveConsent'

    grantor = factory.SubFactory(UserFactory)
    grantee_tenant = factory.SubFactory(TenantFactory)
    data_category = 'basic'
    status = 'not_requested'
    purpose = factory.Faker('sentence')


class LoginHistoryFactory(DjangoModelFactory):
    """Factory for login history records."""

    class Meta:
        model = 'tenant_profiles.LoginHistory'

    user = factory.SubFactory(UserFactory)
    result = 'success'
    ip_address = '127.0.0.1'
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'


# ============================================================================
# ATS FACTORIES
# ============================================================================

class JobCategoryFactory(DjangoModelFactory):
    """Factory for job categories."""

    class Meta:
        model = 'jobs.JobCategory'
        django_get_or_create = ('tenant', 'slug',)

    tenant = factory.SubFactory(TenantFactory)
    name = factory.Sequence(lambda n: f"Category {n}")
    slug = factory.Sequence(lambda n: f"category-{n}")
    description = factory.Faker('text', max_nb_chars=200)
    color = '#3B82F6'
    sort_order = factory.Sequence(lambda n: n)
    is_active = True


class PipelineFactory(DjangoModelFactory):
    """Factory for recruitment pipelines."""

    class Meta:
        model = 'jobs.Pipeline'

    tenant = factory.SubFactory(TenantFactory)
    name = factory.Sequence(lambda n: f"Pipeline {n}")
    description = factory.Faker('text', max_nb_chars=200)
    is_default = False
    is_active = True
    created_by = factory.SubFactory(UserFactory)


class DefaultPipelineFactory(PipelineFactory):
    """Factory for default pipeline."""
    name = 'Default Pipeline'
    is_default = True


class PipelineStageFactory(DjangoModelFactory):
    """Factory for pipeline stages."""

    class Meta:
        model = 'jobs.PipelineStage'

    pipeline = factory.SubFactory(PipelineFactory)
    name = factory.Sequence(lambda n: f"Stage {n}")
    stage_type = 'new'
    description = factory.Faker('sentence')
    color = '#6B7280'
    order = factory.Sequence(lambda n: n)
    is_active = True
    auto_reject_after_days = 0
    send_email_on_enter = False


class JobPostingFactory(DjangoModelFactory):
    """Factory for job postings."""

    class Meta:
        model = 'jobs.JobPosting'

    tenant = factory.SubFactory(TenantFactory)
    title = factory.Faker('job')
    slug = factory.LazyAttribute(lambda o: f"{o.title.lower().replace(' ', '-')}-{uuid.uuid4().hex[:6]}")
    reference_code = factory.Sequence(lambda n: f"JOB-{n:05d}")
    category = factory.SubFactory(JobCategoryFactory, tenant=factory.SelfAttribute('..tenant'))

    status = 'open'
    pipeline = factory.SubFactory(PipelineFactory, tenant=factory.SelfAttribute('..tenant'))

    description = factory.Faker('text', max_nb_chars=1000)
    responsibilities = factory.Faker('text', max_nb_chars=500)
    requirements = factory.Faker('text', max_nb_chars=500)
    benefits = factory.Faker('text', max_nb_chars=300)

    job_type = 'full_time'
    experience_level = 'mid'

    remote_policy = 'hybrid'
    location_city = factory.Faker('city')
    location_state = 'ON'
    location_country = 'Canada'

    salary_min = Decimal('60000.00')
    salary_max = Decimal('90000.00')
    salary_currency = 'CAD'
    salary_period = 'yearly'
    show_salary = True

    positions_count = 1
    hiring_manager = factory.SubFactory(UserFactory)
    recruiter = factory.SubFactory(UserFactory)

    require_cover_letter = False
    require_resume = True

    is_internal_only = False
    is_featured = False
    published_on_career_page = True

    created_by = factory.SubFactory(UserFactory)
    published_at = factory.LazyFunction(timezone.now)


class DraftJobPostingFactory(JobPostingFactory):
    """Factory for draft job postings."""
    status = 'draft'
    published_at = None


class CandidateFactory(DjangoModelFactory):
    """Factory for ATS candidates."""

    class Meta:
        model = 'jobs.Candidate'

    tenant = factory.SubFactory(TenantFactory)
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    email = factory.LazyAttribute(lambda o: f"{o.first_name.lower()}.{o.last_name.lower()}@example.com")
    phone = factory.Faker('phone_number')

    headline = factory.Faker('job')
    summary = factory.Faker('text', max_nb_chars=500)
    current_company = factory.Faker('company')
    current_title = factory.Faker('job')
    years_experience = factory.fuzzy.FuzzyInteger(1, 20)

    city = factory.Faker('city')
    state = 'ON'
    country = 'Canada'
    willing_to_relocate = False

    resume_text = factory.Faker('text', max_nb_chars=2000)
    linkedin_url = factory.LazyAttribute(lambda o: f"https://linkedin.com/in/{o.first_name.lower()}{o.last_name.lower()}")

    source = 'career_page'
    consent_to_store = True
    consent_date = factory.LazyFunction(timezone.now)


class ApplicationFactory(DjangoModelFactory):
    """Factory for job applications."""

    class Meta:
        model = 'jobs.Application'

    tenant = factory.SubFactory(TenantFactory)
    candidate = factory.SubFactory(CandidateFactory, tenant=factory.SelfAttribute('..tenant'))
    job = factory.SubFactory(JobPostingFactory, tenant=factory.SelfAttribute('..tenant'))

    status = 'new'
    current_stage = factory.SubFactory(PipelineStageFactory, pipeline=factory.SelfAttribute('..job.pipeline'))

    cover_letter = factory.Faker('text', max_nb_chars=500)
    send_rejection_email = True


class ApplicationActivityFactory(DjangoModelFactory):
    """Factory for application activities."""

    class Meta:
        model = 'jobs.ApplicationActivity'

    application = factory.SubFactory(ApplicationFactory)
    activity_type = 'created'
    performed_by = factory.SubFactory(UserFactory)
    notes = factory.Faker('sentence')


class ApplicationNoteFactory(DjangoModelFactory):
    """Factory for application notes."""

    class Meta:
        model = 'jobs.ApplicationNote'

    application = factory.SubFactory(ApplicationFactory)
    author = factory.SubFactory(UserFactory)
    content = factory.Faker('text', max_nb_chars=500)
    is_private = False


class InterviewFactory(DjangoModelFactory):
    """Factory for interviews."""

    class Meta:
        model = 'jobs.Interview'

    application = factory.SubFactory(ApplicationFactory)
    interview_type = 'video'
    status = 'scheduled'
    title = factory.LazyAttribute(lambda o: f"Interview with {o.application.candidate.full_name}")
    description = factory.Faker('sentence')

    scheduled_start = factory.LazyFunction(lambda: timezone.now() + timedelta(days=2))
    scheduled_end = factory.LazyFunction(lambda: timezone.now() + timedelta(days=2, hours=1))
    timezone = 'America/Toronto'

    location = 'Virtual'
    meeting_url = 'https://meet.google.com/abc-defg-hij'

    organizer = factory.SubFactory(UserFactory)
    candidate_notified = True
    interviewers_notified = True


class InterviewFeedbackFactory(DjangoModelFactory):
    """Factory for interview feedback."""

    class Meta:
        model = 'jobs.InterviewFeedback'

    interview = factory.SubFactory(InterviewFactory)
    interviewer = factory.SubFactory(UserFactory)

    overall_rating = 4
    technical_skills = 4
    communication = 5
    cultural_fit = 4
    problem_solving = 4

    recommendation = 'yes'
    strengths = factory.Faker('text', max_nb_chars=300)
    weaknesses = factory.Faker('text', max_nb_chars=200)
    notes = factory.Faker('text', max_nb_chars=500)


class OfferFactory(DjangoModelFactory):
    """Factory for job offers."""

    class Meta:
        model = 'jobs.Offer'

    application = factory.SubFactory(ApplicationFactory)

    status = 'draft'

    job_title = factory.LazyAttribute(lambda o: o.application.job.title)
    department = 'Engineering'
    start_date = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=30)).date())
    employment_type = 'full_time'

    base_salary = Decimal('75000.00')
    salary_currency = 'CAD'
    salary_period = 'yearly'
    signing_bonus = Decimal('5000.00')

    benefits_summary = factory.Faker('text', max_nb_chars=300)
    pto_days = 20
    remote_policy = 'Hybrid - 2 days remote'

    offer_letter_content = factory.Faker('text', max_nb_chars=2000)
    expiration_date = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=14)).date())

    requires_signature = True
    created_by = factory.SubFactory(UserFactory)


class SentOfferFactory(OfferFactory):
    """Factory for sent offers."""
    status = 'sent'
    sent_at = factory.LazyFunction(timezone.now)


class SavedSearchFactory(DjangoModelFactory):
    """Factory for saved searches."""

    class Meta:
        model = 'jobs.SavedSearch'

    user = factory.SubFactory(UserFactory)
    name = factory.Sequence(lambda n: f"Search {n}")
    filters = {'skills': ['Python', 'Django'], 'experience': '3-5'}
    is_alert_enabled = False
    alert_frequency = 'daily'


# ============================================================================
# HR CORE FACTORIES
# ============================================================================

class EmployeeFactory(DjangoModelFactory):
    """Factory for HR employees."""

    class Meta:
        model = 'hr_core.Employee'

    tenant = factory.SubFactory(TenantFactory)
    user = factory.SubFactory(UserFactory)
    employee_id = factory.Sequence(lambda n: f"EMP{n:05d}")
    status = 'active'
    employment_type = 'full_time'

    job_title = factory.Faker('job')
    team = 'Engineering'
    work_location = 'Toronto HQ'

    hire_date = factory.LazyFunction(lambda: (timezone.now() - timedelta(days=365)).date())
    start_date = factory.LazyFunction(lambda: (timezone.now() - timedelta(days=365)).date())
    probation_end_date = factory.LazyFunction(lambda: (timezone.now() - timedelta(days=275)).date())

    base_salary = Decimal('75000.00')
    salary_currency = 'CAD'
    pay_frequency = 'bi_weekly'

    pto_balance = Decimal('15.00')
    sick_leave_balance = Decimal('10.00')

    emergency_contact_name = factory.Faker('name')
    emergency_contact_phone = factory.Faker('phone_number')
    emergency_contact_relationship = 'Spouse'


class ProbationaryEmployeeFactory(EmployeeFactory):
    """Factory for employees on probation."""
    status = 'probation'
    hire_date = factory.LazyFunction(lambda: (timezone.now() - timedelta(days=30)).date())
    start_date = factory.LazyFunction(lambda: (timezone.now() - timedelta(days=30)).date())
    probation_end_date = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=60)).date())


class TimeOffTypeFactory(DjangoModelFactory):
    """Factory for time off types."""

    class Meta:
        model = 'hr_core.TimeOffType'
        django_get_or_create = ('tenant', 'code',)

    tenant = factory.SubFactory(TenantFactory)
    name = factory.Sequence(lambda n: f"Time Off Type {n}")
    code = factory.Sequence(lambda n: f"TOT{n}")
    description = factory.Faker('sentence')
    color = '#3B82F6'

    is_accrued = True
    accrual_rate = Decimal('1.25')
    max_balance = Decimal('30.00')
    max_carryover = Decimal('5.00')

    requires_approval = True
    requires_documentation = False
    min_notice_days = 1
    is_paid = True
    is_active = True


class VacationTypeFactory(TimeOffTypeFactory):
    """Factory for vacation time off type."""
    name = 'Vacation'
    code = 'vacation'
    is_accrued = True
    accrual_rate = Decimal('1.25')


class SickLeaveTypeFactory(TimeOffTypeFactory):
    """Factory for sick leave time off type."""
    name = 'Sick Leave'
    code = 'sick'
    is_accrued = True
    accrual_rate = Decimal('0.83')
    requires_documentation = True
    min_notice_days = 0


class TimeOffRequestFactory(DjangoModelFactory):
    """Factory for time off requests."""

    class Meta:
        model = 'hr_core.TimeOffRequest'

    employee = factory.SubFactory(EmployeeFactory)
    tenant = factory.LazyAttribute(lambda o: o.employee.tenant)
    time_off_type = factory.SubFactory(VacationTypeFactory, tenant=factory.SelfAttribute('..tenant'))

    start_date = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=14)).date())
    end_date = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=18)).date())
    is_half_day = False

    total_days = Decimal('5.00')
    reason = factory.Faker('sentence')
    status = 'pending'


class ApprovedTimeOffRequestFactory(TimeOffRequestFactory):
    """Factory for approved time off requests."""
    status = 'approved'
    approver = factory.SubFactory(UserFactory)
    approved_at = factory.LazyFunction(timezone.now)


class OnboardingChecklistFactory(DjangoModelFactory):
    """Factory for onboarding checklists."""

    class Meta:
        model = 'hr_core.OnboardingChecklist'

    name = factory.Sequence(lambda n: f"Onboarding Checklist {n}")
    description = factory.Faker('text', max_nb_chars=200)
    employment_type = ''
    is_active = True


class OnboardingTaskFactory(DjangoModelFactory):
    """Factory for onboarding tasks."""

    class Meta:
        model = 'hr_core.OnboardingTask'

    checklist = factory.SubFactory(OnboardingChecklistFactory)
    title = factory.Sequence(lambda n: f"Task {n}")
    description = factory.Faker('sentence')
    category = 'documentation'
    order = factory.Sequence(lambda n: n)
    assigned_to_role = 'HR'
    due_days = 7
    is_required = True
    requires_signature = False


class EmployeeOnboardingFactory(DjangoModelFactory):
    """Factory for employee onboarding progress."""

    class Meta:
        model = 'hr_core.EmployeeOnboarding'

    employee = factory.SubFactory(EmployeeFactory)
    checklist = factory.SubFactory(OnboardingChecklistFactory)
    start_date = factory.LazyFunction(lambda: timezone.now().date())
    target_completion_date = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=30)).date())


class OnboardingTaskProgressFactory(DjangoModelFactory):
    """Factory for onboarding task progress."""

    class Meta:
        model = 'hr_core.OnboardingTaskProgress'

    onboarding = factory.SubFactory(EmployeeOnboardingFactory)
    task = factory.SubFactory(OnboardingTaskFactory, checklist=factory.SelfAttribute('..onboarding.checklist'))
    is_completed = False
    due_date = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=7)).date())


class DocumentTemplateFactory(DjangoModelFactory):
    """Factory for document templates."""

    class Meta:
        model = 'hr_core.DocumentTemplate'

    name = factory.Sequence(lambda n: f"Document Template {n}")
    category = 'contract'
    description = factory.Faker('sentence')
    content = '<html><body>{{ employee_name }} - {{ date }}</body></html>'
    placeholders = ['employee_name', 'date', 'job_title']
    requires_signature = True
    is_active = True
    version = '1.0'


class EmployeeDocumentFactory(DjangoModelFactory):
    """Factory for employee documents."""

    class Meta:
        model = 'hr_core.EmployeeDocument'

    employee = factory.SubFactory(EmployeeFactory)
    template = factory.SubFactory(DocumentTemplateFactory)

    title = factory.Sequence(lambda n: f"Document {n}")
    category = 'contract'
    description = factory.Faker('sentence')
    file = factory.django.FileField(filename='document.pdf')
    file_type = 'application/pdf'

    status = 'draft'
    requires_signature = True
    uploaded_by = factory.SubFactory(UserFactory)


class OffboardingFactory(DjangoModelFactory):
    """Factory for employee offboarding."""

    class Meta:
        model = 'hr_core.Offboarding'

    employee = factory.SubFactory(EmployeeFactory)

    separation_type = 'resignation'
    reason = factory.Faker('text', max_nb_chars=200)
    notice_date = factory.LazyFunction(lambda: timezone.now().date())
    last_working_day = factory.LazyFunction(lambda: (timezone.now() + timedelta(days=14)).date())

    knowledge_transfer_complete = False
    equipment_returned = False
    access_revoked = False
    final_paycheck_processed = False
    benefits_terminated = False
    exit_interview_completed = False

    eligible_for_rehire = True
    processed_by = factory.SubFactory(UserFactory)


class PerformanceReviewFactory(DjangoModelFactory):
    """Factory for performance reviews."""

    class Meta:
        model = 'hr_core.PerformanceReview'

    employee = factory.SubFactory(EmployeeFactory)
    reviewer = factory.SubFactory(UserFactory)

    review_type = 'annual'
    review_period_start = factory.LazyFunction(lambda: (timezone.now() - timedelta(days=365)).date())
    review_period_end = factory.LazyFunction(lambda: timezone.now().date())
    status = 'draft'

    overall_rating = 4
    goals_met_percentage = 85

    self_assessment = factory.Faker('text', max_nb_chars=500)
    manager_feedback = factory.Faker('text', max_nb_chars=500)
    accomplishments = factory.Faker('text', max_nb_chars=300)
    areas_for_improvement = factory.Faker('text', max_nb_chars=300)
    goals_for_next_period = factory.Faker('text', max_nb_chars=300)

    promotion_recommended = False
    salary_increase_recommended = True
    salary_increase_percentage = Decimal('5.00')
    pip_recommended = False


# ============================================================================
# CAREERS FACTORIES
# ============================================================================

class CareerPageFactory(DjangoModelFactory):
    """Factory for career pages."""

    class Meta:
        model = 'careers.CareerPage'

    title = 'Careers'
    tagline = factory.Faker('catch_phrase')
    description = factory.Faker('text', max_nb_chars=500)

    primary_color = '#3B82F6'
    secondary_color = '#1E40AF'
    accent_color = '#10B981'
    text_color = '#1F2937'
    background_color = '#FFFFFF'

    show_company_info = True
    company_description = factory.Faker('text', max_nb_chars=500)
    show_benefits = True
    benefits_content = factory.Faker('text', max_nb_chars=300)
    show_culture = True
    culture_content = factory.Faker('text', max_nb_chars=300)
    show_values = True

    is_active = True
    require_account = False
    show_salary_range = True
    allow_general_applications = True


class CareerPageSectionFactory(DjangoModelFactory):
    """Factory for career page sections."""

    class Meta:
        model = 'careers.CareerPageSection'

    career_page = factory.SubFactory(CareerPageFactory)
    title = factory.Sequence(lambda n: f"Section {n}")
    section_type = 'text'
    content = {'text': 'Section content here'}
    order = factory.Sequence(lambda n: n)
    is_visible = True


class JobListingFactory(DjangoModelFactory):
    """Factory for public job listings."""

    class Meta:
        model = 'careers.JobListing'

    job = factory.SubFactory(JobPostingFactory)

    custom_slug = ''
    show_company_name = True
    show_department = True
    show_team_size = False
    show_application_count = False
    application_count_threshold = 10

    is_featured = False
    feature_priority = 0

    view_count = 0
    apply_click_count = 0

    published_at = factory.LazyFunction(timezone.now)


class FeaturedJobListingFactory(JobListingFactory):
    """Factory for featured job listings."""
    is_featured = True
    feature_priority = 10


class PublicApplicationFactory(DjangoModelFactory):
    """Factory for public applications."""

    class Meta:
        model = 'careers.PublicApplication'

    job_listing = factory.SubFactory(JobListingFactory)

    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    email = factory.LazyAttribute(lambda o: f"{o.first_name.lower()}.{o.last_name.lower()}@example.com")
    phone = factory.Faker('phone_number')

    resume = factory.django.FileField(filename='resume.pdf')
    cover_letter = factory.Faker('text', max_nb_chars=500)
    linkedin_url = factory.LazyAttribute(lambda o: f"https://linkedin.com/in/{o.first_name.lower()}{o.last_name.lower()}")

    privacy_consent = True
    marketing_consent = False
    consent_timestamp = factory.LazyFunction(timezone.now)
    consent_ip = '127.0.0.1'

    status = 'pending'

    source = 'direct'
    utm_source = ''
    utm_medium = ''
    utm_campaign = ''
    ip_address = '127.0.0.1'


class ProcessedPublicApplicationFactory(PublicApplicationFactory):
    """Factory for processed public applications."""
    status = 'processed'
    processed_at = factory.LazyFunction(timezone.now)
    ats_candidate = factory.SubFactory(CandidateFactory)
    ats_application = factory.SubFactory(ApplicationFactory)


class TalentPoolFactory(DjangoModelFactory):
    """Factory for talent pools."""

    class Meta:
        model = 'careers.TalentPool'

    name = factory.Sequence(lambda n: f"Talent Pool {n}")
    description = factory.Faker('text', max_nb_chars=200)
    is_public = False
    created_by = factory.SubFactory(UserFactory)


class TalentPoolMemberFactory(DjangoModelFactory):
    """Factory for talent pool members."""

    class Meta:
        model = 'careers.TalentPoolMember'

    pool = factory.SubFactory(TalentPoolFactory)
    candidate = factory.SubFactory(CandidateFactory)
    added_by = factory.SubFactory(UserFactory)
    notes = factory.Faker('sentence')


# ============================================================================
# MESSAGE FACTORIES
# ============================================================================

class ConversationFactory(DjangoModelFactory):
    """Factory for Conversation model."""

    class Meta:
        model = 'messages_sys.Conversation'

    name = factory.Faker('catch_phrase')

    @factory.post_generation
    def participants(self, create, extracted, **kwargs):
        """Handle many-to-many participants relationship."""
        if not create:
            return
        if extracted:
            for user in extracted:
                self.participants.add(user)
        else:
            user = UserFactory()
            self.participants.add(user)


# ============================================================================
# ROLE-BASED USER FACTORIES
# ============================================================================

class OwnerTenantUserFactory(TenantUserFactory):
    """Factory for owner/PDG tenant users."""
    role = 'owner'


class ViewerTenantUserFactory(TenantUserFactory):
    """Factory for viewer (read-only) tenant users."""
    role = 'viewer'


class HiringManagerTenantUserFactory(TenantUserFactory):
    """Factory for hiring manager tenant users."""
    role = 'hiring_manager'


# ============================================================================
# FREELANCER PROFILE FACTORY
# ============================================================================

class FreelancerProfileFactory(DjangoModelFactory):
    """Factory for freelancer profiles."""

    class Meta:
        model = 'tenant_profiles.FreelancerProfile'

    user = factory.SubFactory(UserFactory)
    professional_title = factory.Faker('job')
    bio = factory.Faker('text', max_nb_chars=500)
    years_of_experience = factory.Faker('random_int', min=0, max=20)

    availability_status = 'available'
    availability_hours_per_week = 40

    hourly_rate = factory.Faker('pydecimal', left_digits=3, right_digits=2, positive=True, min_value=15, max_value=500)
    hourly_rate_currency = 'CAD'
    minimum_project_budget = factory.Faker('pydecimal', left_digits=4, right_digits=2, positive=True, min_value=500, max_value=10000)

    skills = factory.LazyFunction(
        lambda: [
            'Python', 'Django', 'React', 'JavaScript', 'PostgreSQL'
        ][:factory.Faker('random_int', min=1, max=5).evaluate(None, None, {})]
    )

    portfolio_url = factory.LazyAttribute(lambda o: f"https://portfolio.{o.user.username}.com")
    github_url = factory.LazyAttribute(lambda o: f"https://github.com/{o.user.username}")
    linkedin_url = factory.LazyAttribute(lambda o: f"https://linkedin.com/in/{o.user.username}")

    city = factory.Faker('city')
    country = 'Canada'
    timezone = 'America/Toronto'
    remote_only = True
    willing_to_relocate = False

    is_verified = False
    identity_verified = False
    payment_method_verified = False

    completed_projects = 0
    completed_services = 0
    total_earnings = Decimal('0.00')
    average_rating = None
    total_reviews = 0


class VerifiedFreelancerProfileFactory(FreelancerProfileFactory):
    """Factory for verified freelancer profiles."""
    is_verified = True
    identity_verified = True
    payment_method_verified = True
    verification_date = factory.LazyFunction(timezone.now)
    years_of_experience = factory.Faker('random_int', min=3, max=15)
    completed_projects = factory.Faker('random_int', min=5, max=50)
    completed_services = factory.Faker('random_int', min=2, max=30)
    total_earnings = factory.Faker('pydecimal', left_digits=5, right_digits=2, positive=True, min_value=5000, max_value=250000)
    average_rating = factory.Faker('pydecimal', left_digits=1, right_digits=2, positive=True, min_value=3.5, max_value=5.0)
    total_reviews = factory.Faker('random_int', min=5, max=100)


# ============================================================================
# PYTEST FIXTURES
# ============================================================================

@pytest.fixture
def user_factory(db):
    """Provide UserFactory for tests."""
    return UserFactory


@pytest.fixture
def superuser_factory(db):
    """Provide SuperUserFactory for tests."""
    return SuperUserFactory


@pytest.fixture
def plan_factory(db):
    """DEPRECATED: Provide PlanFactory for tests."""
    return PlanFactory


@pytest.fixture
def tenant_factory(db):
    """DEPRECATED: Provide TenantFactory for tests."""
    return TenantFactory


@pytest.fixture
def tenant_user_factory(db):
    """Provide TenantUserFactory for tests."""
    return TenantUserFactory


@pytest.fixture
def user_profile_factory(db):
    """Provide UserProfileFactory for tests."""
    return UserProfileFactory


@pytest.fixture
def job_category_factory(db):
    """Provide JobCategoryFactory for tests."""
    return JobCategoryFactory


@pytest.fixture
def pipeline_factory(db):
    """Provide PipelineFactory for tests."""
    return PipelineFactory


@pytest.fixture
def pipeline_stage_factory(db):
    """Provide PipelineStageFactory for tests."""
    return PipelineStageFactory


@pytest.fixture
def job_posting_factory(db):
    """Provide JobPostingFactory for tests."""
    return JobPostingFactory


@pytest.fixture
def job_factory(db):
    """Alias for job_posting_factory. Provide JobPostingFactory for tests."""
    return JobPostingFactory


@pytest.fixture
def free_plan_factory(db):
    """DEPRECATED: Provide FreePlanFactory for tests."""
    return FreePlanFactory


@pytest.fixture
def candidate_factory(db):
    """Provide CandidateFactory for tests."""
    return CandidateFactory


@pytest.fixture
def application_factory(db):
    """Provide ApplicationFactory for tests."""
    return ApplicationFactory


@pytest.fixture
def interview_factory(db):
    """Provide InterviewFactory for tests."""
    return InterviewFactory


@pytest.fixture
def offer_factory(db):
    """Provide OfferFactory for tests."""
    return OfferFactory


@pytest.fixture
def employee_factory(db):
    """Provide EmployeeFactory for tests."""
    return EmployeeFactory


@pytest.fixture
def time_off_type_factory(db):
    """Provide TimeOffTypeFactory for tests."""
    return TimeOffTypeFactory


@pytest.fixture
def time_off_request_factory(db):
    """Provide TimeOffRequestFactory for tests."""
    return TimeOffRequestFactory


@pytest.fixture
def career_page_factory(db):
    """Provide CareerPageFactory for tests."""
    return CareerPageFactory


@pytest.fixture
def job_listing_factory(db):
    """Provide JobListingFactory for tests."""
    return JobListingFactory


@pytest.fixture
def public_application_factory(db):
    """Provide PublicApplicationFactory for tests."""
    return PublicApplicationFactory


@pytest.fixture
def talent_pool_factory(db):
    """Provide TalentPoolFactory for tests."""
    return TalentPoolFactory


@pytest.fixture
def conversation_factory(db):
    """Provide ConversationFactory for tests."""
    return ConversationFactory


# ============================================================================
# COMMON TEST FIXTURES
# ============================================================================

@pytest.fixture
def user(db):
    """Create a standard test user."""
    return UserFactory()


@pytest.fixture
def admin_user(db):
    """Create an admin user."""
    return SuperUserFactory()


@pytest.fixture
def plan(db):
    """DEPRECATED: Create a standard plan."""
    return PlanFactory()


@pytest.fixture
def free_plan(db):
    """DEPRECATED: Create a free plan."""
    return FreePlanFactory()


@pytest.fixture
def tenant(db, plan):
    """DEPRECATED: Create a tenant with a plan."""
    return TenantFactory(plan=plan)


@pytest.fixture
def authenticated_client(db, client, user):
    """Provide an authenticated test client."""
    client.force_login(user)
    return client


@pytest.fixture
def admin_client(db, client, admin_user):
    """Provide an authenticated admin test client."""
    client.force_login(admin_user)
    return client


@pytest.fixture
def api_client(db):
    """Provide a DRF API test client."""
    from rest_framework.test import APIClient
    return APIClient()


@pytest.fixture
def authenticated_api_client(db, api_client, user):
    """Provide an authenticated DRF API test client."""
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def tenant_user(db, user, tenant):
    """DEPRECATED: Create a tenant user membership."""
    return TenantUserFactory(user=user, tenant=tenant)


@pytest.fixture
def pipeline_with_stages(db):
    """Create a pipeline with standard stages."""
    pipeline = DefaultPipelineFactory()
    stages = [
        PipelineStageFactory(pipeline=pipeline, name='New', stage_type='new', order=0),
        PipelineStageFactory(pipeline=pipeline, name='Screening', stage_type='screening', order=1),
        PipelineStageFactory(pipeline=pipeline, name='Interview', stage_type='interview', order=2),
        PipelineStageFactory(pipeline=pipeline, name='Offer', stage_type='offer', order=3),
        PipelineStageFactory(pipeline=pipeline, name='Hired', stage_type='hired', order=4),
        PipelineStageFactory(pipeline=pipeline, name='Rejected', stage_type='rejected', order=5),
    ]
    return pipeline, stages


@pytest.fixture
def job_with_applications(db, pipeline_with_stages):
    """Create a job posting with multiple applications."""
    pipeline, stages = pipeline_with_stages
    job = JobPostingFactory(pipeline=pipeline)
    applications = [
        ApplicationFactory(job=job, current_stage=stages[0]),
        ApplicationFactory(job=job, current_stage=stages[1]),
        ApplicationFactory(job=job, current_stage=stages[2]),
    ]
    return job, applications


@pytest.fixture
def employee_with_onboarding(db):
    """Create an employee with onboarding in progress."""
    employee = EmployeeFactory(status='pending')
    checklist = OnboardingChecklistFactory()
    onboarding = EmployeeOnboardingFactory(employee=employee, checklist=checklist)

    tasks = [
        OnboardingTaskFactory(checklist=checklist, title='Sign employment contract', order=0),
        OnboardingTaskFactory(checklist=checklist, title='Complete tax forms', order=1),
        OnboardingTaskFactory(checklist=checklist, title='IT equipment setup', order=2),
        OnboardingTaskFactory(checklist=checklist, title='Meet the team', order=3),
    ]

    for task in tasks:
        OnboardingTaskProgressFactory(onboarding=onboarding, task=task)

    return employee, onboarding


@pytest.fixture
def full_career_page(db):
    """Create a fully configured career page with jobs."""
    career_page = CareerPageFactory()
    CareerPageSectionFactory(career_page=career_page, title='About Us', section_type='text', order=0)
    CareerPageSectionFactory(career_page=career_page, title='Our Values', section_type='text', order=1)

    jobs = [
        JobListingFactory(is_featured=True),
        JobListingFactory(is_featured=False),
        JobListingFactory(is_featured=False),
    ]

    return career_page, jobs


# ============================================================================
# SECURITY TEST FIXTURES
# ============================================================================

@pytest.fixture
def security_test_payloads():
    """Common security test payloads for penetration testing."""
    return {
        'sql_injection': [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' AND '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --",
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ],
    }


@pytest.fixture
def celery_config():
    """Celery configuration for testing."""
    return {
        'broker_url': 'memory://',
        'result_backend': 'cache+memory://',
        'task_always_eager': True,
        'task_eager_propagates': True,
        'task_store_eager_result': True,
        'broker_connection_retry_on_startup': True,
    }


@pytest.fixture
def mock_stripe():
    """Mock Stripe API for testing payment integrations."""
    from unittest.mock import patch, MagicMock

    with patch('stripe.Account') as mock_account, \
         patch('stripe.PaymentIntent') as mock_payment, \
         patch('stripe.AccountLink') as mock_account_link, \
         patch('stripe.Payout') as mock_payout:

        mock_account.create.return_value = MagicMock(
            id='acct_test123',
            charges_enabled=True,
            payouts_enabled=True,
            details_submitted=True
        )

        mock_payment.create.return_value = MagicMock(
            id='pi_test123',
            status='succeeded',
            amount=10000,
            currency='usd'
        )

        mock_account_link.create.return_value = MagicMock(
            url='https://connect.stripe.com/setup/test123'
        )

        mock_payout.create.return_value = MagicMock(
            id='po_test123',
            status='paid',
            amount=10000,
            currency='usd'
        )

        yield {
            'account': mock_account,
            'payment': mock_payment,
            'account_link': mock_account_link,
            'payout': mock_payout
        }


# ============================================================================
# MOCK REQUEST
# ============================================================================

class MockTenantRequest:
    """Mock request object with tenant context for testing views and permissions."""

    def __init__(self, user=None, tenant=None, method='GET', path='/', **kwargs):
        self.user = user
        self.tenant = tenant
        self.method = method
        self.path = path
        self.META = kwargs.get('META', {'REMOTE_ADDR': '127.0.0.1'})
        self.session = kwargs.get('session', {})
        self.data = kwargs.get('data', {})
        self.query_params = kwargs.get('query_params', {})
        self.FILES = kwargs.get('FILES', {})

        # Set tenant-related attributes
        if tenant:
            self.tenant_settings = getattr(tenant, 'settings', None)
            self.tenant_features = kwargs.get('tenant_features', {})
        else:
            self.tenant_settings = None
            self.tenant_features = {}

        # Apply any additional kwargs as attributes
        for key, value in kwargs.items():
            if key not in ('META', 'session', 'data', 'query_params', 'FILES', 'tenant_features'):
                setattr(self, key, value)


# Alias for backward compatibility
TenantRequestFactory = MockTenantRequest


# ============================================================================
# ADDITIONAL FIXTURES FOR TEST COMPATIBILITY
# ============================================================================

@pytest.fixture
def token(db, user):
    """Provide a JWT or session token for authenticated API tests."""
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token)


@pytest.fixture
def headers(db, token):
    """Provide authorization headers for API tests."""
    return {'HTTP_AUTHORIZATION': f'Bearer {token}'}


@pytest.fixture
def job_listing_id(db):
    """Provide a job listing ID for tests."""
    listing = JobListingFactory()
    return listing.id


@pytest.fixture
def category(db):
    """Provide a job category for tests."""
    return JobCategoryFactory()


@pytest.fixture
def freelancer_profile_factory(db):
    """Provide FreelancerProfileFactory for tests."""
    return FreelancerProfileFactory


@pytest.fixture
def tenant_settings_factory(db):
    """DEPRECATED: Provide TenantSettingsFactory for tests."""
    return TenantSettingsFactory


@pytest.fixture
def tenant_invitation_factory(db):
    """DEPRECATED: Provide TenantInvitationFactory for tests."""
    return TenantInvitationFactory


@pytest.fixture
def domain_factory(db):
    """DEPRECATED: Provide DomainFactory for tests."""
    return DomainFactory


@pytest.fixture
def enterprise_plan_factory(db):
    """DEPRECATED: Provide EnterprisePlanFactory for tests."""
    return EnterprisePlanFactory


@pytest.fixture
def tenant_usage_factory(db):
    """DEPRECATED: Provide TenantUsageFactory for tests."""
    return TenantUsageFactory


@pytest.fixture
def audit_log_factory(db):
    """DEPRECATED: Provide AuditLogFactory for tests."""
    return AuditLogFactory


@pytest.fixture
def onboarding_checklist_factory(db):
    """Provide OnboardingChecklistFactory for tests."""
    return OnboardingChecklistFactory


@pytest.fixture
def performance_review_factory(db):
    """Provide PerformanceReviewFactory for tests."""
    return PerformanceReviewFactory


@pytest.fixture
def document_template_factory(db):
    """Provide DocumentTemplateFactory for tests."""
    return DocumentTemplateFactory


# ============================================================================
# INSTANCE FIXTURES (for tests that use plain fixture names)
# ============================================================================

@pytest.fixture
def job(db, tenant):
    """Create a job posting."""
    return JobPostingFactory(tenant=tenant)


@pytest.fixture
def candidate(db, tenant):
    """Create a candidate."""
    return CandidateFactory(tenant=tenant)


@pytest.fixture
def application(db, tenant, job, candidate):
    """Create an application."""
    return ApplicationFactory(tenant=tenant, job=job, candidate=candidate)


@pytest.fixture
def interview(db, application):
    """Create an interview."""
    return InterviewFactory(application=application)


@pytest.fixture
def employee(db, tenant):
    """Create an employee."""
    return EmployeeFactory(tenant=tenant)


@pytest.fixture
def pipeline(db, tenant):
    """Create a pipeline."""
    return PipelineFactory(tenant=tenant)


@pytest.fixture
def offer(db, application):
    """Create an offer."""
    return OfferFactory(application=application)


@pytest.fixture
def job_listing(db, job):
    """Create a job listing."""
    return JobListingFactory(job=job)


@pytest.fixture
def career_page(db):
    """Create a career page."""
    return CareerPageFactory()


@pytest.fixture
def conversation(db, user):
    """Create a conversation."""
    return ConversationFactory(participants=[user])


@pytest.fixture
def tenant_settings(db, tenant):
    """Create tenant settings."""
    return TenantSettingsFactory(tenant=tenant)
