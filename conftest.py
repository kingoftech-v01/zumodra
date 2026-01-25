"""
Zumodra Test Configuration - pytest fixtures and factories

This module provides:
- pytest-django configuration
- factory_boy factories for all major models
- Shared fixtures for tenant isolation testing

TESTING NOTES (2026-01-16):
==========================
Test Suite Status: 157 passed, 6 skipped
- ATS Tests: 125 passed
- Security Tests: 23 passed, 1 skipped
- Scalability Tests: 9 passed, 5 skipped

IMPORTANT FIXES APPLIED:
1. TenantFactory: Disabled auto_create_schema to prevent django-tenants schema
   creation errors during tests. The _create() method sets auto_create_schema=False
   before save to avoid "Unknown command: 'migrate_schemas'" errors.

2. Database Settings: Tests use DB_HOST and DB_PORT environment variables as
   fallback to work correctly inside Docker containers.

3. Schema Name Handling: All tenant-related code uses getattr(connection, 'schema_name', 'public')
   instead of direct attribute access to handle tests without django-tenants.

4. Bulk Create: When using JobPosting.objects.bulk_create(), must manually generate
   reference_code and slug since pre_save signals are bypassed.

SKIPPED TESTS:
- test_content_security_policy: CSP middleware disabled in test settings
- test_concurrent_reads_50_requests: Requires django-tenants for API tenant routing
- test_pagination_first_page: Requires django-tenants for API tenant routing
- test_repeated_requests_faster: Requires django-tenants for API tenant routing
- test_large_response_memory: Requires django-tenants for API tenant routing
- test_sustained_load: Requires django-tenants for API tenant routing

RUNNING TESTS:
# Run all tests
pytest tests/ -v

# Run by module
pytest tests/test_ats.py -v
pytest tests/test_security_comprehensive.py -v
pytest tests/test_scalability.py -v

# Run by marker
pytest -m security -v
pytest -m scalability -v
pytest -m workflow -v
"""

import pytest
import uuid
from datetime import datetime, timedelta, date
from decimal import Decimal
from django.utils import timezone

import factory
from factory import fuzzy
from factory.django import DjangoModelFactory


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
        """Override create to handle password properly."""
        password = kwargs.pop('password', None)
        user = super()._create(model_class, *args, **kwargs)
        if password:
            user.set_password(password)
            user.save()
        return user


class SuperUserFactory(UserFactory):
    """Factory for superuser accounts."""

    is_staff = True
    is_superuser = True


# ============================================================================
# TENANT FACTORIES
# ============================================================================

class PlanFactory(DjangoModelFactory):
    """Factory for subscription plans."""

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
    """Factory for free tier plan."""

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
    """Factory for enterprise tier plan."""

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
    """Factory for multi-tenant organizations."""

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
        """Override create to disable schema creation for tests."""
        obj = model_class(*args, **kwargs)
        # Disable auto schema creation before save
        obj.auto_create_schema = False
        obj.save()
        return obj


class TrialTenantFactory(TenantFactory):
    """Factory for tenants on trial."""

    status = 'trial'
    on_trial = True
    trial_ends_at = factory.LazyFunction(lambda: timezone.now() + timedelta(days=14))


class TenantSettingsFactory(DjangoModelFactory):
    """Factory for tenant settings."""

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


def _get_test_base_domain():
    """Get base domain for test fixtures from centralized config."""
    import os
    from django.conf import settings
    domain = os.environ.get('TENANT_BASE_DOMAIN') or getattr(settings, 'TENANT_BASE_DOMAIN', 'localhost')
    return domain


class DomainFactory(DjangoModelFactory):
    """Factory for tenant domains."""

    class Meta:
        model = 'tenants.Domain'

    tenant = factory.SubFactory(TenantFactory)
    domain = factory.LazyAttribute(lambda o: f"{o.tenant.slug}.{_get_test_base_domain()}")
    is_primary = True
    is_careers_domain = False
    ssl_enabled = True


class TenantInvitationFactory(DjangoModelFactory):
    """Factory for tenant invitations."""

    class Meta:
        model = 'tenants.TenantInvitation'

    tenant = factory.SubFactory(TenantFactory)
    email = factory.Faker('email')
    invited_by = factory.SubFactory(UserFactory)
    role = 'member'
    status = 'pending'
    token = factory.LazyFunction(lambda: uuid.uuid4().hex)
    expires_at = factory.LazyFunction(lambda: timezone.now() + timedelta(days=7))


class TenantUsageFactory(DjangoModelFactory):
    """Factory for tenant usage tracking."""

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
    storage_used_bytes = 1024 * 1024 * 100  # 100 MB
    api_calls_this_month = 1000


class AuditLogFactory(DjangoModelFactory):
    """Factory for tenant audit logs."""

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
    employment_type = ''  # All types
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
# MULTI-TENANT TEST UTILITIES
# ============================================================================

from contextlib import contextmanager
from django.db import connection
from django.test import RequestFactory as DjangoRequestFactory
from unittest.mock import MagicMock, patch


class TenantRequestFactory(DjangoRequestFactory):
    """
    Request factory that includes tenant context.
    Used for testing tenant-scoped views and permissions.
    """

    def __init__(self, tenant=None, user=None, **defaults):
        super().__init__(**defaults)
        self.tenant = tenant
        self.user = user

    def _add_tenant_context(self, request):
        """Add tenant and user context to request."""
        if self.tenant:
            request.tenant = self.tenant
            request.tenant_settings = getattr(self.tenant, 'settings', None)
            request.tenant_plan = self.tenant.plan
        if self.user:
            request.user = self.user
        return request

    def get(self, path, data=None, secure=False, **extra):
        request = super().get(path, data, secure, **extra)
        return self._add_tenant_context(request)

    def post(self, path, data=None, content_type='application/json', secure=False, **extra):
        request = super().post(path, data, content_type, secure, **extra)
        return self._add_tenant_context(request)

    def put(self, path, data=None, content_type='application/json', secure=False, **extra):
        request = super().put(path, data, content_type, secure, **extra)
        return self._add_tenant_context(request)

    def patch(self, path, data=None, content_type='application/json', secure=False, **extra):
        request = super().patch(path, data, content_type, secure, **extra)
        return self._add_tenant_context(request)

    def delete(self, path, data=None, content_type='application/json', secure=False, **extra):
        request = super().delete(path, data, content_type, secure, **extra)
        return self._add_tenant_context(request)


@contextmanager
def tenant_context(tenant):
    """
    Context manager for executing code within a specific tenant's schema.

    Usage:
        with tenant_context(tenant):
            # All database operations happen in tenant's schema
            Job.objects.create(...)
    """
    from django_tenants.utils import schema_context, get_public_schema_name

    if tenant is None:
        # Use public schema if no tenant provided
        with schema_context(get_public_schema_name()):
            yield
    else:
        with schema_context(tenant.schema_name):
            yield


@contextmanager
def multiple_tenants_context(tenants):
    """
    Context manager for testing concurrent tenant operations.
    Yields a dict mapping tenant slugs to their schema contexts.

    Usage:
        with multiple_tenants_context([tenant1, tenant2]) as contexts:
            # Access tenants by slug
            contexts['tenant-1']  # tenant1 context
    """
    contexts = {}
    for tenant in tenants:
        contexts[tenant.slug] = tenant

    try:
        yield contexts
    finally:
        pass  # Cleanup handled by individual schema_context managers


class MockTenantRequest:
    """
    Mock request object with tenant context for testing permission classes.
    """

    def __init__(self, user=None, tenant=None, method='GET', data=None):
        self.user = user or MagicMock()
        self.tenant = tenant
        self.method = method
        self.data = data or {}
        self.META = {
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_USER_AGENT': 'TestClient/1.0'
        }

        # Add tenant-related attributes
        if tenant:
            self.tenant_settings = getattr(tenant, 'settings', None)
            self.tenant_plan = tenant.plan if hasattr(tenant, 'plan') else None


def create_tenant_with_schema(name, slug, plan=None, create_schema=False):
    """
    Helper to create a tenant with optional schema creation.
    Use create_schema=False for unit tests, True for integration tests.
    """
    from tenants.models import Tenant, Domain

    tenant = Tenant.objects.create(
        name=name,
        slug=slug,
        schema_name=slug.replace('-', '_'),
        plan=plan,
        status='active',
        owner_email=f'owner@{slug}.test',
    )

    if create_schema:
        tenant.create_schema()

    # Create primary domain
    Domain.objects.create(
        tenant=tenant,
        domain=f'{slug}.zumodra.test',
        is_primary=True
    )

    return tenant


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
            # If participants were passed, add them
            for user in extracted:
                self.participants.add(user)
        else:
            # Default: create one participant
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
    """Provide PlanFactory for tests."""
    return PlanFactory


@pytest.fixture
def free_plan_factory(db):
    """Provide FreePlanFactory for tests."""
    return FreePlanFactory


@pytest.fixture
def enterprise_plan_factory(db):
    """Provide EnterprisePlanFactory for tests."""
    return EnterprisePlanFactory


@pytest.fixture
def tenant_factory(db):
    """Provide TenantFactory for tests."""
    return TenantFactory


@pytest.fixture
def tenant_settings_factory(db):
    """Provide TenantSettingsFactory for tests."""
    return TenantSettingsFactory


@pytest.fixture
def domain_factory(db):
    """Provide DomainFactory for tests."""
    return DomainFactory


@pytest.fixture
def tenant_invitation_factory(db):
    """Provide TenantInvitationFactory for tests."""
    return TenantInvitationFactory


@pytest.fixture
def tenant_user_factory(db):
    """Provide TenantUserFactory for tests."""
    return TenantUserFactory


@pytest.fixture
def user_profile_factory(db):
    """Provide UserProfileFactory for tests."""
    return UserProfileFactory


@pytest.fixture
def kyc_verification_factory(db):
    """Provide KYCVerificationFactory for tests."""
    return KYCVerificationFactory


@pytest.fixture
def progressive_consent_factory(db):
    """Provide ProgressiveConsentFactory for tests."""
    return ProgressiveConsentFactory


@pytest.fixture
def login_history_factory(db):
    """Provide LoginHistoryFactory for tests."""
    return LoginHistoryFactory


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
def interview_feedback_factory(db):
    """Provide InterviewFeedbackFactory for tests."""
    return InterviewFeedbackFactory


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
def onboarding_checklist_factory(db):
    """Provide OnboardingChecklistFactory for tests."""
    return OnboardingChecklistFactory


@pytest.fixture
def onboarding_task_factory(db):
    """Provide OnboardingTaskFactory for tests."""
    return OnboardingTaskFactory


@pytest.fixture
def employee_onboarding_factory(db):
    """Provide EmployeeOnboardingFactory for tests."""
    return EmployeeOnboardingFactory


@pytest.fixture
def document_template_factory(db):
    """Provide DocumentTemplateFactory for tests."""
    return DocumentTemplateFactory


@pytest.fixture
def employee_document_factory(db):
    """Provide EmployeeDocumentFactory for tests."""
    return EmployeeDocumentFactory


@pytest.fixture
def offboarding_factory(db):
    """Provide OffboardingFactory for tests."""
    return OffboardingFactory


@pytest.fixture
def performance_review_factory(db):
    """Provide PerformanceReviewFactory for tests."""
    return PerformanceReviewFactory


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
    """Create a standard plan."""
    return PlanFactory()


@pytest.fixture
def free_plan(db):
    """Create a free plan."""
    return FreePlanFactory()


@pytest.fixture
def tenant(db, plan):
    """Create a tenant with a plan."""
    return TenantFactory(plan=plan)


@pytest.fixture
def tenant_with_settings(db, plan):
    """Create a tenant with settings."""
    tenant = TenantFactory(plan=plan)
    TenantSettingsFactory(tenant=tenant)
    return tenant


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
    """Create a tenant user membership."""
    return TenantUserFactory(user=user, tenant=tenant)


@pytest.fixture
def recruiter_user(db, tenant):
    """Create a recruiter user with tenant membership."""
    user = UserFactory()
    RecruiterTenantUserFactory(user=user, tenant=tenant)
    return user


@pytest.fixture
def hr_manager_user(db, tenant):
    """Create an HR manager user with tenant membership."""
    user = UserFactory()
    HRManagerTenantUserFactory(user=user, tenant=tenant)
    return user


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


@pytest.fixture
def conversation_factory(db):
    """Provide ConversationFactory for tests."""
    return ConversationFactory


# ============================================================================
# ENHANCED TENANT FIXTURES
# ============================================================================

@pytest.fixture
def owner_tenant_user_factory(db):
    """Provide OwnerTenantUserFactory for tests."""
    return OwnerTenantUserFactory


@pytest.fixture
def viewer_tenant_user_factory(db):
    """Provide ViewerTenantUserFactory for tests."""
    return ViewerTenantUserFactory


@pytest.fixture
def hiring_manager_tenant_user_factory(db):
    """Provide HiringManagerTenantUserFactory for tests."""
    return HiringManagerTenantUserFactory


@pytest.fixture
def tenant_request_factory(db, tenant, user):
    """Provide TenantRequestFactory with default tenant and user."""
    return TenantRequestFactory(tenant=tenant, user=user)


@pytest.fixture
def two_tenants(db, plan):
    """Create two separate tenants for isolation testing."""
    tenant1 = TenantFactory(
        name='Company Alpha',
        slug='company-alpha',
        plan=plan
    )
    tenant2 = TenantFactory(
        name='Company Beta',
        slug='company-beta',
        plan=plan
    )
    return tenant1, tenant2


@pytest.fixture
def tenant_with_all_roles(db, plan):
    """
    Create a tenant with users for all roles.
    Returns dict with tenant and users keyed by role.
    """
    tenant = TenantFactory(plan=plan)

    users = {}
    roles = ['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'employee', 'viewer']

    for role in roles:
        user = UserFactory()
        TenantUserFactory(user=user, tenant=tenant, role=role)
        users[role] = user

    return {
        'tenant': tenant,
        'users': users
    }


@pytest.fixture
def owner_user(db, tenant):
    """Create an owner user with tenant membership."""
    user = UserFactory()
    OwnerTenantUserFactory(user=user, tenant=tenant)
    return user


@pytest.fixture
def admin_tenant_user(db, tenant):
    """Create an admin user with tenant membership."""
    user = UserFactory()
    AdminTenantUserFactory(user=user, tenant=tenant)
    return user


@pytest.fixture
def viewer_user(db, tenant):
    """Create a viewer (read-only) user with tenant membership."""
    user = UserFactory()
    ViewerTenantUserFactory(user=user, tenant=tenant)
    return user


@pytest.fixture
def hiring_manager(db, tenant):
    """Create a hiring manager user with tenant membership."""
    user = UserFactory()
    HiringManagerTenantUserFactory(user=user, tenant=tenant)
    return user


@pytest.fixture
def tenant_api_client(db, api_client, tenant, owner_user):
    """
    API client authenticated as tenant owner with tenant context.
    Note: Use TenantRequestFactory for unit tests requiring tenant context.
    """
    api_client.force_authenticate(user=owner_user)
    return api_client


@pytest.fixture
def verified_kyc_user(db, user):
    """Create a user with verified KYC."""
    VerifiedKYCFactory(user=user)
    return user


@pytest.fixture
def trial_tenant(db, plan):
    """Create a tenant on trial."""
    return TrialTenantFactory(plan=plan)


@pytest.fixture
def enterprise_tenant(db):
    """Create a tenant with enterprise plan."""
    plan = EnterprisePlanFactory()
    return TenantFactory(plan=plan, status='active')


@pytest.fixture
def mock_tenant_request(db, tenant, user):
    """Provide MockTenantRequest for permission testing."""
    return MockTenantRequest(user=user, tenant=tenant)


@pytest.fixture
def complete_tenant_setup(db):
    """
    Create a complete tenant setup with:
    - Enterprise plan
    - Tenant with settings
    - Domain
    - Users for all roles
    - Usage tracking

    Returns a comprehensive dict with all created objects.
    """
    # Create enterprise plan
    plan = EnterprisePlanFactory()

    # Create tenant
    tenant = TenantFactory(
        name='Complete Corp',
        slug='complete-corp',
        plan=plan,
        status='active'
    )

    # Create settings
    settings = TenantSettingsFactory(tenant=tenant)

    # Create domain
    domain = DomainFactory(tenant=tenant)

    # Create usage tracking
    usage = TenantUsageFactory(tenant=tenant)

    # Create users for all roles
    users = {}
    roles = ['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'employee', 'viewer']

    for role in roles:
        user = UserFactory()
        tenant_user = TenantUserFactory(user=user, tenant=tenant, role=role)
        UserProfileFactory(user=user)
        users[role] = {
            'user': user,
            'tenant_user': tenant_user
        }

    return {
        'plan': plan,
        'tenant': tenant,
        'settings': settings,
        'domain': domain,
        'usage': usage,
        'users': users
    }


@pytest.fixture
def user_with_mfa(db):
    """Create a user with MFA enabled."""
    return UserFactory(mfa_enabled=True)


@pytest.fixture
def consent_setup(db, user, tenant):
    """
    Create consent setup for testing progressive revelation.
    Returns grantor, grantee, and various consent records.
    """
    grantor = UserFactory()
    grantee = user

    consents = {
        'granted': ProgressiveConsentFactory(
            grantor=grantor,
            grantee_user=grantee,
            grantee_tenant=tenant,
            data_category='basic',
            status='granted'
        ),
        'pending': ProgressiveConsentFactory(
            grantor=grantor,
            grantee_user=grantee,
            grantee_tenant=tenant,
            data_category='contact',
            status='pending'
        ),
        'denied': ProgressiveConsentFactory(
            grantor=grantor,
            grantee_user=grantee,
            grantee_tenant=tenant,
            data_category='resume',
            status='denied'
        ),
    }

    return {
        'grantor': grantor,
        'grantee': grantee,
        'tenant': tenant,
        'consents': consents
    }


# ============================================================================
# TEST HELPER FIXTURES
# ============================================================================

@pytest.fixture
def login_history_data(db, user):
    """Create login history records for testing."""
    successful = LoginHistoryFactory(user=user, result='success')
    failed = LoginHistoryFactory(user=user, result='failed', failure_reason='Invalid password')
    blocked = LoginHistoryFactory(user=user, result='blocked', failure_reason='Too many attempts')

    return {
        'user': user,
        'successful': successful,
        'failed': failed,
        'blocked': blocked
    }


@pytest.fixture
def audit_log_data(db, tenant, user):
    """Create audit log records for testing."""
    logs = [
        AuditLogFactory(tenant=tenant, user=user, action='create', resource_type='JobPosting'),
        AuditLogFactory(tenant=tenant, user=user, action='update', resource_type='Candidate'),
        AuditLogFactory(tenant=tenant, user=user, action='delete', resource_type='Application'),
        AuditLogFactory(tenant=tenant, user=user, action='login', resource_type='User'),
    ]
    return {'tenant': tenant, 'user': user, 'logs': logs}


# ============================================================================
# LOAD TEST FIXTURES (100+ Concurrent Users)
# ============================================================================

@pytest.fixture
def concurrent_users_setup(db, plan):
    """
    Create setup for testing 100+ concurrent users.

    Returns a tenant with 100+ users across different roles,
    suitable for load testing and concurrency verification.
    """
    tenant = TenantFactory(plan=plan, status='active')

    users = []
    tenant_users = []

    # Create 100 users with varied roles
    roles = ['employee', 'recruiter', 'hr_manager', 'hiring_manager', 'viewer', 'admin']

    for i in range(105):
        user = UserFactory(
            username=f"loadtest_user_{i}",
            email=f"loadtest_{i}@example.com"
        )
        role = roles[i % len(roles)]
        tenant_user = TenantUserFactory(
            user=user,
            tenant=tenant,
            role=role,
            is_active=True
        )
        users.append(user)
        tenant_users.append(tenant_user)

    return {
        'tenant': tenant,
        'users': users,
        'tenant_users': tenant_users,
        'count': len(users)
    }


@pytest.fixture
def bulk_job_postings(db, plan):
    """
    Create bulk job postings for load testing.

    Creates 100+ job postings with applications and candidates
    for testing pagination and query optimization.
    """
    tenant = TenantFactory(plan=plan, status='active')
    pipeline = DefaultPipelineFactory()
    stages = [
        PipelineStageFactory(pipeline=pipeline, name='New', stage_type='new', order=0),
        PipelineStageFactory(pipeline=pipeline, name='Review', stage_type='screening', order=1),
        PipelineStageFactory(pipeline=pipeline, name='Interview', stage_type='interview', order=2),
    ]

    jobs = []
    applications = []
    candidates = []

    # Create 50 job postings
    for i in range(50):
        job = JobPostingFactory(
            title=f"Load Test Job {i}",
            pipeline=pipeline,
            status='open'
        )
        jobs.append(job)

        # Create 10 applications per job (500 total)
        for j in range(10):
            candidate = CandidateFactory(
                first_name=f"Candidate_{i}_{j}",
                email=f"candidate_{i}_{j}@test.com"
            )
            candidates.append(candidate)

            application = ApplicationFactory(
                candidate=candidate,
                job=job,
                current_stage=stages[j % len(stages)],
                status='new'
            )
            applications.append(application)

    return {
        'tenant': tenant,
        'jobs': jobs,
        'applications': applications,
        'candidates': candidates,
        'pipeline': pipeline,
        'stages': stages,
        'counts': {
            'jobs': len(jobs),
            'applications': len(applications),
            'candidates': len(candidates)
        }
    }


@pytest.fixture
def high_volume_employees(db, plan):
    """
    Create high volume of employees for HR load testing.

    Creates 200+ employees with time-off requests and performance reviews
    for testing HR module scalability.
    """
    tenant = TenantFactory(plan=plan, status='active')
    vacation_type = VacationTypeFactory()
    sick_type = SickLeaveTypeFactory()

    employees = []
    time_off_requests = []
    reviews = []

    for i in range(200):
        user = UserFactory(
            username=f"employee_{i}",
            email=f"employee_{i}@company.com"
        )
        employee = EmployeeFactory(
            user=user,
            employee_id=f"EMP{i:05d}",
            status='active' if i % 10 != 0 else 'probation'
        )
        employees.append(employee)

        # Create time-off requests (50% of employees)
        if i % 2 == 0:
            request = TimeOffRequestFactory(
                employee=employee,
                time_off_type=vacation_type if i % 3 != 0 else sick_type,
                status='pending' if i % 4 == 0 else 'approved'
            )
            time_off_requests.append(request)

        # Create performance reviews (30% of employees)
        if i % 3 == 0:
            review = PerformanceReviewFactory(
                employee=employee,
                status='draft' if i % 6 == 0 else 'completed'
            )
            reviews.append(review)

    return {
        'tenant': tenant,
        'employees': employees,
        'time_off_requests': time_off_requests,
        'performance_reviews': reviews,
        'counts': {
            'employees': len(employees),
            'time_off_requests': len(time_off_requests),
            'reviews': len(reviews)
        }
    }


# ============================================================================
# LOAD TEST CONFIGURATION
# ============================================================================

class LoadTestConfig:
    """Configuration for load testing scenarios."""

    # Number of concurrent requests to simulate
    CONCURRENT_REQUESTS = 100

    # Request timeout in seconds
    REQUEST_TIMEOUT = 30

    # Maximum acceptable response time (ms) for pass/fail
    MAX_RESPONSE_TIME_MS = 500

    # Target requests per second
    TARGET_RPS = 50

    # Ramp-up period (seconds)
    RAMP_UP_SECONDS = 10

    # Test duration (seconds)
    TEST_DURATION_SECONDS = 60

    # Query count threshold (for N+1 detection)
    MAX_QUERIES_PER_REQUEST = 10

    @classmethod
    def get_scenario_config(cls, scenario: str) -> dict:
        """Get configuration for specific test scenario."""
        scenarios = {
            'api_list': {
                'concurrent': 100,
                'rps': 50,
                'max_response_ms': 300,
                'max_queries': 5,
            },
            'api_detail': {
                'concurrent': 150,
                'rps': 100,
                'max_response_ms': 200,
                'max_queries': 3,
            },
            'api_create': {
                'concurrent': 50,
                'rps': 20,
                'max_response_ms': 500,
                'max_queries': 10,
            },
            'dashboard': {
                'concurrent': 75,
                'rps': 30,
                'max_response_ms': 1000,
                'max_queries': 15,
            },
            'search': {
                'concurrent': 100,
                'rps': 40,
                'max_response_ms': 500,
                'max_queries': 8,
            },
        }
        return scenarios.get(scenario, {
            'concurrent': cls.CONCURRENT_REQUESTS,
            'rps': cls.TARGET_RPS,
            'max_response_ms': cls.MAX_RESPONSE_TIME_MS,
            'max_queries': cls.MAX_QUERIES_PER_REQUEST,
        })


@pytest.fixture
def load_test_config():
    """Provide LoadTestConfig for tests."""
    return LoadTestConfig


@pytest.fixture
def load_test_metrics():
    """
    Fixture to track load test metrics during test execution.

    Usage:
        def test_api_performance(load_test_metrics, client):
            with load_test_metrics.track('list_employees'):
                response = client.get('/api/v1/employees/')
            metrics = load_test_metrics.get_summary()
            assert metrics['avg_response_ms'] < 300
    """
    from collections import defaultdict
    import time

    class MetricsTracker:
        def __init__(self):
            self.metrics = defaultdict(list)
            self.query_counts = defaultdict(list)
            self._start_time = None
            self._operation = None

        def track(self, operation: str):
            """Context manager to track a single operation."""
            self._operation = operation
            return self

        def __enter__(self):
            self._start_time = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            elapsed_ms = (time.time() - self._start_time) * 1000
            self.metrics[self._operation].append({
                'duration_ms': elapsed_ms,
                'success': exc_type is None,
                'timestamp': time.time()
            })
            self._operation = None
            self._start_time = None

        def record_queries(self, operation: str, query_count: int):
            """Record query count for an operation."""
            self.query_counts[operation].append(query_count)

        def get_summary(self, operation: str = None) -> dict:
            """Get summary statistics for metrics."""
            if operation:
                data = self.metrics.get(operation, [])
            else:
                data = [m for metrics in self.metrics.values() for m in metrics]

            if not data:
                return {}

            durations = [m['duration_ms'] for m in data]
            successes = [m['success'] for m in data]

            return {
                'count': len(data),
                'success_rate': sum(successes) / len(successes) * 100,
                'avg_response_ms': sum(durations) / len(durations),
                'min_response_ms': min(durations),
                'max_response_ms': max(durations),
                'p95_response_ms': sorted(durations)[int(len(durations) * 0.95)] if len(durations) > 20 else max(durations),
                'p99_response_ms': sorted(durations)[int(len(durations) * 0.99)] if len(durations) > 100 else max(durations),
            }

        def assert_performance(self, operation: str, config: dict):
            """Assert performance meets configuration requirements."""
            summary = self.get_summary(operation)
            assert summary['avg_response_ms'] < config.get('max_response_ms', 500), \
                f"Average response time {summary['avg_response_ms']:.2f}ms exceeds limit"
            assert summary['success_rate'] >= 99, \
                f"Success rate {summary['success_rate']:.2f}% below 99%"

    return MetricsTracker()


# ============================================================================
# SECURITY TEST FIXTURES
# ============================================================================

@pytest.fixture
def security_test_payloads():
    """
    Common security test payloads for penetration testing.

    Includes SQL injection, XSS, CSRF, and other attack vectors.
    """
    return {
        'sql_injection': [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' AND '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --",
            "1; SELECT * FROM users",
            "' OR 1=1 --",
            "') OR ('1'='1",
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "'\"><script>alert(1)</script>",
            "<a href=\"javascript:alert('XSS')\">Click</a>",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "/etc/passwd%00.jpg",
            "..%252f..%252f..%252fetc/passwd",
        ],
        'command_injection': [
            "; ls -la",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "& dir",
            "|| ping -c 10 127.0.0.1",
        ],
        'ldap_injection': [
            "*)(objectClass=*",
            "admin)(&)",
            "*)(&",
            "admin)(|(password=*))",
        ],
        'header_injection': [
            "value\r\nHeader-Injection: true",
            "value%0d%0aSet-Cookie: injected=true",
            "value\nX-Injected: header",
        ],
        'ssrf': [
            "http://localhost:22",
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://[::1]:80/",
        ],
    }


@pytest.fixture
def security_test_headers():
    """Security headers that should be present in responses."""
    return {
        'required': {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
        },
        'recommended': {
            'Strict-Transport-Security': None,  # Any value is good
            'Content-Security-Policy': None,
            'Referrer-Policy': None,
        },
        'forbidden': [
            'Server',  # Should not expose server info
            'X-Powered-By',  # Should not expose framework
        ]
    }


@pytest.fixture
def rate_limit_test_config():
    """Configuration for rate limiting tests."""
    return {
        'anonymous': {
            'requests_per_minute': 60,
            'requests_per_hour': 500,
        },
        'authenticated': {
            'requests_per_minute': 120,
            'requests_per_hour': 5000,
        },
        'burst': {
            'max_burst': 10,
            'recovery_rate': 1,  # per second
        }
    }


@pytest.fixture
def auth_test_scenarios():
    """Common authentication test scenarios."""
    return {
        'valid_credentials': {
            'email': 'test@example.com',
            'password': 'ValidP@ssw0rd123',
            'expected_status': 200,
        },
        'invalid_password': {
            'email': 'test@example.com',
            'password': 'WrongPassword',
            'expected_status': 401,
        },
        'invalid_email': {
            'email': 'nonexistent@example.com',
            'password': 'AnyPassword',
            'expected_status': 401,
        },
        'empty_credentials': {
            'email': '',
            'password': '',
            'expected_status': 400,
        },
        'sql_injection_email': {
            'email': "admin'--",
            'password': 'password',
            'expected_status': 401,
        },
        'locked_account': {
            'email': 'locked@example.com',
            'password': 'ValidP@ssw0rd123',
            'expected_status': 403,
            'max_attempts': 5,
        },
    }


@pytest.fixture
def permission_test_matrix():
    """
    Permission test matrix for RBAC testing.

    Maps roles to allowed/denied actions for each resource.
    """
    return {
        'job_posting': {
            'owner': {'create': True, 'read': True, 'update': True, 'delete': True},
            'admin': {'create': True, 'read': True, 'update': True, 'delete': True},
            'hr_manager': {'create': True, 'read': True, 'update': True, 'delete': False},
            'recruiter': {'create': True, 'read': True, 'update': True, 'delete': False},
            'hiring_manager': {'create': False, 'read': True, 'update': False, 'delete': False},
            'employee': {'create': False, 'read': True, 'update': False, 'delete': False},
            'viewer': {'create': False, 'read': True, 'update': False, 'delete': False},
        },
        'employee': {
            'owner': {'create': True, 'read': True, 'update': True, 'delete': True},
            'admin': {'create': True, 'read': True, 'update': True, 'delete': True},
            'hr_manager': {'create': True, 'read': True, 'update': True, 'delete': False},
            'recruiter': {'create': False, 'read': True, 'update': False, 'delete': False},
            'hiring_manager': {'create': False, 'read': True, 'update': False, 'delete': False},
            'employee': {'create': False, 'read': False, 'update': False, 'delete': False},  # Own profile only
            'viewer': {'create': False, 'read': True, 'update': False, 'delete': False},
        },
        'candidate': {
            'owner': {'create': True, 'read': True, 'update': True, 'delete': True},
            'admin': {'create': True, 'read': True, 'update': True, 'delete': True},
            'hr_manager': {'create': True, 'read': True, 'update': True, 'delete': False},
            'recruiter': {'create': True, 'read': True, 'update': True, 'delete': False},
            'hiring_manager': {'create': False, 'read': True, 'update': False, 'delete': False},
            'employee': {'create': False, 'read': False, 'update': False, 'delete': False},
            'viewer': {'create': False, 'read': False, 'update': False, 'delete': False},
        },
    }


@pytest.fixture
def tenant_isolation_setup(db):
    """
    Create setup for tenant isolation security testing.

    Creates two separate tenants with users and data to verify
    that cross-tenant data access is properly prevented.
    """
    plan = PlanFactory()

    # Tenant A setup
    tenant_a = TenantFactory(
        name='Tenant A',
        slug='tenant-a',
        plan=plan
    )
    user_a = UserFactory(email='user_a@tenant-a.com')
    TenantUserFactory(user=user_a, tenant=tenant_a, role='admin')

    # Create some data for Tenant A
    jobs_a = [
        JobPostingFactory(title=f'Tenant A Job {i}')
        for i in range(3)
    ]
    candidates_a = [
        CandidateFactory(email=f'candidate_a_{i}@test.com')
        for i in range(5)
    ]

    # Tenant B setup
    tenant_b = TenantFactory(
        name='Tenant B',
        slug='tenant-b',
        plan=plan
    )
    user_b = UserFactory(email='user_b@tenant-b.com')
    TenantUserFactory(user=user_b, tenant=tenant_b, role='admin')

    # Create some data for Tenant B
    jobs_b = [
        JobPostingFactory(title=f'Tenant B Job {i}')
        for i in range(3)
    ]
    candidates_b = [
        CandidateFactory(email=f'candidate_b_{i}@test.com')
        for i in range(5)
    ]

    return {
        'tenant_a': {
            'tenant': tenant_a,
            'user': user_a,
            'jobs': jobs_a,
            'candidates': candidates_a,
        },
        'tenant_b': {
            'tenant': tenant_b,
            'user': user_b,
            'jobs': jobs_b,
            'candidates': candidates_b,
        },
    }


@pytest.fixture
def csrf_test_client(db, client):
    """
    Client configured for CSRF testing.

    Returns client without CSRF enforcement for testing CSRF protection.
    """
    from django.test import Client
    return Client(enforce_csrf_checks=True)


# ============================================================================
# INTEGRATION TEST FIXTURES (New for comprehensive test coverage)
# ============================================================================

@pytest.fixture
def webhook_subscription(db, tenant):
    """
    Create test webhook subscription for integration testing.

    Returns an active OutboundWebhook configured for testing webhook dispatch,
    signature verification, and retry logic.
    """
    from integrations.models import OutboundWebhook

    webhook = OutboundWebhook.objects.create(
        tenant=tenant,
        name='Test Webhook',
        url='https://webhook.example.com/test',
        secret='test_secret_key_12345',
        status='active',
        events=['job.created', 'job.updated', 'application.created'],
        description='Test webhook for automated testing'
    )
    return webhook


@pytest.fixture
def celery_config():
    """
    Celery configuration for testing.

    Configures Celery to execute tasks synchronously in tests
    for predictable and fast test execution.
    """
    return {
        'broker_url': 'memory://',
        'result_backend': 'cache+memory://',
        'task_always_eager': True,  # Execute tasks synchronously
        'task_eager_propagates': True,  # Propagate exceptions
        'task_store_eager_result': True,
        'broker_connection_retry_on_startup': True,
    }


@pytest.fixture
def mock_stripe():
    """
    Mock Stripe API for testing payment integrations.

    Provides mocked Stripe Account and PaymentIntent objects
    for testing Stripe Connect and payment flows without
    making actual API calls.

    Usage:
        def test_create_payment(mock_stripe):
            mock_stripe['payment'].create.return_value = {'id': 'pi_test123'}
            # Test code here
    """
    from unittest.mock import patch, MagicMock

    with patch('stripe.Account') as mock_account, \
         patch('stripe.PaymentIntent') as mock_payment, \
         patch('stripe.AccountLink') as mock_account_link, \
         patch('stripe.Payout') as mock_payout:

        # Configure default return values
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

    # Availability
    availability_status = 'available'
    availability_hours_per_week = 40

    # Pricing
    hourly_rate = factory.Faker('pydecimal', left_digits=3, right_digits=2, positive=True, min_value=15, max_value=500)
    hourly_rate_currency = 'CAD'
    minimum_project_budget = factory.Faker('pydecimal', left_digits=4, right_digits=2, positive=True, min_value=500, max_value=10000)

    # Skills
    skills = factory.LazyFunction(
        lambda: [
            'Python', 'Django', 'React', 'JavaScript', 'PostgreSQL'
        ][:factory.Faker('random_int', min=1, max=5).evaluate(None, None, {})]
    )

    # Portfolio
    portfolio_url = factory.LazyAttribute(lambda o: f"https://portfolio.{o.user.username}.com")
    github_url = factory.LazyAttribute(lambda o: f"https://github.com/{o.user.username}")
    linkedin_url = factory.LazyAttribute(lambda o: f"https://linkedin.com/in/{o.user.username}")

    # Location
    city = factory.Faker('city')
    country = 'Canada'
    timezone = 'America/Toronto'
    remote_only = True
    willing_to_relocate = False

    # Verification
    is_verified = False
    identity_verified = False
    payment_method_verified = False

    # Stats
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

    # More established freelancers
    years_of_experience = factory.Faker('random_int', min=3, max=15)
    completed_projects = factory.Faker('random_int', min=5, max=50)
    completed_services = factory.Faker('random_int', min=2, max=30)
    total_earnings = factory.Faker('pydecimal', left_digits=5, right_digits=2, positive=True, min_value=5000, max_value=250000)
    average_rating = factory.Faker('pydecimal', left_digits=1, right_digits=2, positive=True, min_value=3.5, max_value=5.0)
    total_reviews = factory.Faker('random_int', min=5, max=100)


class BusyFreelancerProfileFactory(VerifiedFreelancerProfileFactory):
    """Factory for busy/unavailable freelancers."""

    availability_status = 'busy'
    availability_hours_per_week = 10


class RemoteOnlyFreelancerProfileFactory(VerifiedFreelancerProfileFactory):
    """Factory for remote-only freelancers."""

    remote_only = True
    willing_to_relocate = False
    city = ''
    country = ''


class WillingToRelocateFreelancerProfileFactory(VerifiedFreelancerProfileFactory):
    """Factory for freelancers willing to relocate."""

    remote_only = False
    willing_to_relocate = True
    city = factory.Faker('city')
    country = 'Canada'
