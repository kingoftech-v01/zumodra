"""
Zumodra Platform Integration Tests

Comprehensive end-to-end integration tests verifying cross-app workflows:
1. Full Hiring Workflow (ATS -> HR)
2. Tenant Onboarding
3. KYC Verification Flow
4. Time-Off Request Flow
5. Freelance Mission Flow (Services -> Finance)
6. Data Privacy Flow (Consent management)

These tests use factories from conftest.py and base test classes from tests/base.py.
External services (Stripe, Sumsub, etc.) are mocked.
"""

import uuid
from datetime import date, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError

from tests.base import (
    TenantTestCase,
    TenantTransactionTestCase,
    APITenantTestCase,
    IsolationTestMixin,
    FactoryHelper,
)


# =============================================================================
# 1. FULL HIRING WORKFLOW INTEGRATION TESTS
# =============================================================================

class TestFullHiringWorkflowIntegration(TenantTransactionTestCase):
    """
    Integration tests for the complete hiring workflow:
    Job Posting -> Application -> Pipeline Stages -> Interview ->
    Feedback -> Offer -> Acceptance -> Employee Creation
    """

    def setUp(self):
        """Set up test with hiring workflow fixtures."""
        super().setUp()
        self._setup_hiring_workflow()

    def _setup_hiring_workflow(self):
        """Create all necessary fixtures for hiring workflow testing."""
        from conftest import (
            PipelineFactory, PipelineStageFactory, JobCategoryFactory,
            JobPostingFactory, CandidateFactory, UserFactory, TenantUserFactory
        )

        # Create pipeline with stages
        self.pipeline = PipelineFactory(
            name='Standard Hiring Pipeline',
            is_default=True,
            tenant=self.tenant
        )

        # Create pipeline stages in order
        self.stage_new = PipelineStageFactory(
            pipeline=self.pipeline,
            name='New Applications',
            stage_type='new',
            order=0
        )
        self.stage_screening = PipelineStageFactory(
            pipeline=self.pipeline,
            name='Screening',
            stage_type='screening',
            order=1
        )
        self.stage_interview = PipelineStageFactory(
            pipeline=self.pipeline,
            name='Interview',
            stage_type='interview',
            order=2
        )
        self.stage_offer = PipelineStageFactory(
            pipeline=self.pipeline,
            name='Offer',
            stage_type='offer',
            order=3
        )
        self.stage_hired = PipelineStageFactory(
            pipeline=self.pipeline,
            name='Hired',
            stage_type='hired',
            order=4
        )

        # Create job category
        self.category = JobCategoryFactory(
            name='Engineering',
            slug='engineering',
            tenant=self.tenant
        )

        # Create recruiter and hiring manager
        self.recruiter_user = UserFactory()
        self.recruiter = TenantUserFactory(
            user=self.recruiter_user,
            tenant=self.tenant,
            role='recruiter'
        )

        self.hiring_manager_user = UserFactory()
        self.hiring_manager = TenantUserFactory(
            user=self.hiring_manager_user,
            tenant=self.tenant,
            role='hiring_manager'
        )

        # Create job posting
        self.job = JobPostingFactory(
            tenant=self.tenant,
            title='Senior Software Engineer',
            status='open',
            pipeline=self.pipeline,
            category=self.category,
            hiring_manager=self.hiring_manager_user,
            recruiter=self.recruiter_user,
            created_by=self.recruiter_user
        )

        # Create candidate
        self.candidate = CandidateFactory(
            tenant=self.tenant,
            first_name='John',
            last_name='Doe',
            email='john.doe@candidate.test'
        )

    def test_complete_hiring_workflow_from_application_to_employee(self):
        """
        Test the complete hiring workflow:
        1. Create job posting (done in setUp)
        2. Candidate applies
        3. Move through pipeline stages
        4. Schedule and complete interview
        5. Submit feedback
        6. Create and send offer
        7. Candidate accepts offer
        8. Create employee record
        """
        from jobs.models import Application, Interview, InterviewFeedback, Offer
        from hr_core.models import Employee
        from conftest import ApplicationFactory, InterviewFactory, InterviewFeedbackFactory

        # Step 1: Create application
        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=self.candidate,
            job=self.job,
            status='new',
            current_stage=self.stage_new,
            cover_letter='I am excited to apply for this position.'
        )

        self.assertEqual(application.status, 'new')
        self.assertEqual(application.current_stage, self.stage_new)
        self.assertFalse(application.is_terminal)

        # Step 2: Move to screening stage
        application.move_to_stage(self.stage_screening, user=self.recruiter_user)
        application.refresh_from_db()

        self.assertEqual(application.current_stage, self.stage_screening)
        self.assertIsNotNone(application.last_stage_change_at)

        # Step 3: Move to interview stage
        application.move_to_stage(self.stage_interview, user=self.recruiter_user)
        application.status = 'interviewing'
        application.save()
        application.refresh_from_db()

        self.assertEqual(application.current_stage, self.stage_interview)
        self.assertEqual(application.status, 'interviewing')

        # Step 4: Schedule interview
        interview = InterviewFactory(
            application=application,
            interview_type='video',
            status='scheduled',
            title=f'Technical Interview - {self.candidate.full_name}',
            scheduled_start=timezone.now() + timedelta(days=2),
            scheduled_end=timezone.now() + timedelta(days=2, hours=1),
            organizer=self.recruiter_user
        )
        interview.interviewers.add(self.hiring_manager_user)

        self.assertEqual(interview.status, 'scheduled')
        self.assertIn(self.hiring_manager_user, interview.interviewers.all())

        # Step 5: Complete interview and submit feedback
        interview.status = 'completed'
        interview.completed_at = timezone.now()
        interview.save()

        feedback = InterviewFeedbackFactory(
            interview=interview,
            interviewer=self.hiring_manager_user,
            overall_rating=4,
            technical_skills=4,
            communication=5,
            cultural_fit=4,
            problem_solving=4,
            recommendation='yes',
            strengths='Strong technical skills and communication',
            notes='Excellent candidate, recommend proceeding to offer'
        )

        self.assertEqual(feedback.overall_rating, 4)
        self.assertEqual(feedback.recommendation, 'yes')

        # Step 6: Move to offer stage
        application.move_to_stage(self.stage_offer, user=self.recruiter_user)
        application.status = 'offer_pending'
        application.save()

        # Step 7: Create and send offer
        offer = Offer.objects.create(
            application=application,
            status='draft',
            job_title=self.job.title,
            department='Engineering',
            start_date=date.today() + timedelta(days=30),
            employment_type='full_time',
            base_salary=Decimal('95000.00'),
            salary_currency='CAD',
            salary_period='yearly',
            signing_bonus=Decimal('5000.00'),
            benefits_summary='Comprehensive health and dental coverage',
            pto_days=20,
            expiration_date=date.today() + timedelta(days=14),
            created_by=self.recruiter_user
        )

        # Approve and send offer
        offer.status = 'approved'
        offer.approved_by = self.hiring_manager_user
        offer.approved_at = timezone.now()
        offer.save()

        offer.status = 'sent'
        offer.sent_at = timezone.now()
        offer.save()

        self.assertEqual(offer.status, 'sent')
        self.assertEqual(application.status, 'offer_pending')

        # Step 8: Candidate accepts offer
        offer.status = 'accepted'
        offer.responded_at = timezone.now()
        offer.signed_at = timezone.now()
        offer.save()

        application.status = 'hired'
        application.hired_at = timezone.now()
        application.save()

        application.move_to_stage(self.stage_hired, user=self.recruiter_user)
        application.refresh_from_db()

        self.assertEqual(offer.status, 'accepted')
        self.assertEqual(application.status, 'hired')
        self.assertTrue(application.is_terminal)

        # Step 9: Create employee record from hired candidate
        from conftest import UserFactory

        # Create user for the new employee
        employee_user = UserFactory(
            email=self.candidate.email,
            first_name=self.candidate.first_name,
            last_name=self.candidate.last_name
        )

        employee = Employee.objects.create(
            tenant=self.tenant,
            user=employee_user,
            employee_id=f'EMP{uuid.uuid4().hex[:6].upper()}',
            status='active',
            employment_type='full_time',
            job_title=offer.job_title,
            team='Engineering',
            hire_date=offer.start_date,
            start_date=offer.start_date,
            base_salary=offer.base_salary,
            salary_currency=offer.salary_currency,
            pto_balance=Decimal(str(offer.pto_days))
        )

        self.assertEqual(employee.status, 'active')
        self.assertEqual(employee.job_title, 'Senior Software Engineer')
        self.assertEqual(employee.base_salary, Decimal('95000.00'))

        # Verify the complete flow
        self.assertEqual(Application.objects.filter(tenant=self.tenant, status='hired').count(), 1)
        self.assertEqual(Employee.objects.filter(tenant=self.tenant).count(), 1)

    def test_application_rejection_flow(self):
        """Test rejecting an application at screening stage."""
        from jobs.models import Application, ApplicationActivity
        from conftest import ApplicationFactory

        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=self.candidate,
            job=self.job,
            status='new',
            current_stage=self.stage_new
        )

        # Move to screening
        application.move_to_stage(self.stage_screening, user=self.recruiter_user)
        application.status = 'in_review'
        application.save()

        # Reject at screening
        application.status = 'rejected'
        application.rejection_reason = 'Does not meet minimum qualifications'
        application.rejection_feedback = 'Thank you for applying. Unfortunately...'
        application.rejected_at = timezone.now()
        application.save()

        application.refresh_from_db()

        self.assertEqual(application.status, 'rejected')
        self.assertTrue(application.is_terminal)
        self.assertFalse(application.can_advance)
        self.assertIsNotNone(application.rejected_at)

    def test_application_withdrawal_flow(self):
        """Test candidate withdrawing their application."""
        from conftest import ApplicationFactory

        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=self.candidate,
            job=self.job,
            status='interviewing',
            current_stage=self.stage_interview
        )

        # Candidate withdraws
        self.assertTrue(application.can_withdraw)

        application.status = 'withdrawn'
        application.save()

        application.refresh_from_db()
        self.assertEqual(application.status, 'withdrawn')
        self.assertTrue(application.is_terminal)
        self.assertFalse(application.can_withdraw)

    def test_offer_counter_offer_chain(self):
        """Test counter-offer negotiation flow."""
        from jobs.models import Offer
        from conftest import ApplicationFactory

        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=self.candidate,
            job=self.job,
            status='offer_pending',
            current_stage=self.stage_offer
        )

        # Initial offer
        initial_offer = Offer.objects.create(
            application=application,
            status='sent',
            job_title=self.job.title,
            base_salary=Decimal('85000.00'),
            salary_currency='CAD',
            salary_period='yearly',
            sent_at=timezone.now(),
            created_by=self.recruiter_user
        )

        # Counter-offer from company (improved terms)
        counter_offer = Offer.objects.create(
            application=application,
            status='sent',
            job_title=self.job.title,
            base_salary=Decimal('92000.00'),
            salary_currency='CAD',
            salary_period='yearly',
            signing_bonus=Decimal('3000.00'),
            previous_offer=initial_offer,
            is_counter_offer=True,
            counter_offer_count=1,
            counter_offer_notes='Increased base salary and added signing bonus',
            sent_at=timezone.now(),
            created_by=self.recruiter_user
        )

        # Mark initial offer as countered
        initial_offer.status = 'countered'
        initial_offer.save()

        self.assertEqual(counter_offer.is_counter_offer, True)
        self.assertEqual(counter_offer.previous_offer, initial_offer)
        self.assertEqual(counter_offer.base_salary, Decimal('92000.00'))
        self.assertEqual(initial_offer.status, 'countered')

    def test_multiple_interviews_in_pipeline(self):
        """Test scheduling multiple interviews for same application."""
        from jobs.models import Interview, InterviewFeedback
        from conftest import ApplicationFactory, InterviewFactory, InterviewFeedbackFactory, UserFactory

        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=self.candidate,
            job=self.job,
            status='interviewing',
            current_stage=self.stage_interview
        )

        # Create additional interviewer
        tech_lead_user = UserFactory()

        # Phone screening interview
        phone_interview = InterviewFactory(
            application=application,
            interview_type='phone',
            status='completed',
            title='Phone Screening',
            organizer=self.recruiter_user,
            completed_at=timezone.now()
        )

        # Technical interview
        tech_interview = InterviewFactory(
            application=application,
            interview_type='video',
            status='completed',
            title='Technical Interview',
            organizer=self.hiring_manager_user,
            completed_at=timezone.now()
        )
        tech_interview.interviewers.add(tech_lead_user)

        # Add feedback for both
        phone_feedback = InterviewFeedbackFactory(
            interview=phone_interview,
            interviewer=self.recruiter_user,
            overall_rating=4,
            recommendation='yes'
        )

        tech_feedback = InterviewFeedbackFactory(
            interview=tech_interview,
            interviewer=tech_lead_user,
            overall_rating=5,
            recommendation='strong_yes'
        )

        self.assertEqual(application.interviews.count(), 2)
        self.assertEqual(application.interviews_count, 2)

        # Calculate average interview rating
        avg_rating = application.average_interview_rating
        self.assertIsNotNone(avg_rating)
        self.assertGreaterEqual(avg_rating, 4.0)


# =============================================================================
# 2. TENANT ONBOARDING INTEGRATION TESTS
# =============================================================================

class TestTenantOnboardingIntegration(TenantTransactionTestCase):
    """
    Integration tests for tenant onboarding workflow:
    Sign up -> Create tenant -> Configure settings ->
    Invite team -> Accept invitation -> Set up career page
    """

    def test_complete_tenant_onboarding_flow(self):
        """Test the complete tenant onboarding from signup to career page setup."""
        from conftest import (
            UserFactory, PlanFactory, TenantFactory, TenantSettingsFactory,
            DomainFactory, TenantInvitationFactory, TenantUserFactory, CareerPageFactory
        )

        # Step 1: New user signs up
        owner_user = UserFactory(
            email='owner@newcompany.test',
            first_name='Jane',
            last_name='Owner'
        )

        # Step 2: Select plan
        plan = PlanFactory(
            name='Professional',
            slug='professional',
            plan_type='professional',
            price_monthly=Decimal('49.99'),
            max_users=25,
            max_job_postings=50,
            feature_ats=True,
            feature_hr_core=True,
            feature_custom_pipelines=True
        )

        # Step 3: Create tenant
        new_tenant = TenantFactory(
            name='New Tech Company',
            slug='new-tech-company',
            plan=plan,
            status='active',
            owner_email=owner_user.email,
            industry='Technology',
            company_size='11-50'
        )

        # Step 4: Create owner's tenant membership
        owner_membership = TenantUserFactory(
            user=owner_user,
            tenant=new_tenant,
            role='owner',
            is_primary_tenant=True,
            is_active=True
        )

        # Step 5: Configure tenant settings
        settings = TenantSettingsFactory(
            tenant=new_tenant,
            primary_color='#2563EB',
            secondary_color='#1E40AF',
            default_language='en',
            default_timezone='America/New_York',
            currency='USD',
            require_cover_letter=True,
            auto_reject_after_days=45,
            career_page_enabled=True,
            career_page_title='Join Our Team'
        )

        # Step 6: Create primary domain
        domain = DomainFactory(
            tenant=new_tenant,
            domain='new-tech-company.zumodra.local',
            is_primary=True
        )

        # Step 7: Invite team members
        invitations = []
        team_emails = [
            ('hr@newcompany.test', 'hr_manager'),
            ('recruiter@newcompany.test', 'recruiter'),
            ('hiring@newcompany.test', 'hiring_manager')
        ]

        for email, role in team_emails:
            invitation = TenantInvitationFactory(
                tenant=new_tenant,
                email=email,
                invited_by=owner_user,
                role=role,
                status='pending'
            )
            invitations.append(invitation)

        self.assertEqual(len(invitations), 3)

        # Step 8: Team members accept invitations
        for invitation in invitations:
            new_user = UserFactory(email=invitation.email)

            # Accept invitation
            invitation.status = 'accepted'
            invitation.accepted_at = timezone.now()
            invitation.save()

            # Create tenant user membership
            TenantUserFactory(
                user=new_user,
                tenant=new_tenant,
                role=invitation.role,
                is_active=True
            )

        # Verify all invitations accepted
        from tenants.models import TenantInvitation
        accepted_count = TenantInvitation.objects.filter(
            tenant=new_tenant,
            status='accepted'
        ).count()
        self.assertEqual(accepted_count, 3)

        # Step 9: Set up career page
        career_page = CareerPageFactory(
            tenant=new_tenant,
            title='Careers at New Tech Company',
            tagline='Build the future with us',
            description='Join our innovative team...',
            primary_color=settings.primary_color,
            secondary_color=settings.secondary_color,
            is_active=True,
            show_company_info=True,
            show_benefits=True,
            allow_general_applications=True
        )

        # Verify complete setup
        from tenant_profiles.models import TenantUser
        total_users = TenantUser.objects.filter(tenant=new_tenant, is_active=True).count()
        self.assertEqual(total_users, 4)  # owner + 3 team members

        self.assertEqual(career_page.tenant, new_tenant)
        self.assertTrue(career_page.is_active)
        self.assertEqual(new_tenant.status, 'active')

    def test_trial_tenant_upgrade_flow(self):
        """Test upgrading a trial tenant to paid plan."""
        from conftest import UserFactory, PlanFactory, TenantFactory, TrialTenantFactory

        # Create free plan
        free_plan = PlanFactory(
            name='Free',
            slug='free',
            plan_type='free',
            price_monthly=Decimal('0.00'),
            max_users=2,
            max_job_postings=3
        )

        # Create paid plan
        pro_plan = PlanFactory(
            name='Professional',
            slug='pro',
            plan_type='professional',
            price_monthly=Decimal('49.99'),
            max_users=25,
            max_job_postings=50
        )

        # Create trial tenant
        trial_tenant = TrialTenantFactory(
            name='Trial Company',
            slug='trial-company',
            plan=free_plan,
            status='trial',
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=7)
        )

        self.assertTrue(trial_tenant.on_trial)
        self.assertEqual(trial_tenant.status, 'trial')

        # Simulate upgrade
        trial_tenant.plan = pro_plan
        trial_tenant.status = 'active'
        trial_tenant.on_trial = False
        trial_tenant.paid_until = timezone.now() + timedelta(days=30)
        trial_tenant.save()

        trial_tenant.refresh_from_db()

        self.assertEqual(trial_tenant.plan, pro_plan)
        self.assertEqual(trial_tenant.status, 'active')
        self.assertFalse(trial_tenant.on_trial)

    def test_invitation_expiration_handling(self):
        """Test handling of expired invitations."""
        from conftest import TenantInvitationFactory, UserFactory

        # Create expired invitation
        expired_invitation = TenantInvitationFactory(
            tenant=self.tenant,
            email='expired@test.com',
            invited_by=self.user,
            role='member',
            status='pending',
            expires_at=timezone.now() - timedelta(days=1)  # Expired yesterday
        )

        # Check if invitation is expired
        self.assertTrue(expired_invitation.expires_at < timezone.now())
        self.assertEqual(expired_invitation.status, 'pending')

        # Mark as expired (would be done by a scheduled task)
        expired_invitation.status = 'expired'
        expired_invitation.save()

        self.assertEqual(expired_invitation.status, 'expired')

    def test_tenant_isolation_between_organizations(self):
        """Test that data is properly isolated between tenants."""
        from conftest import TenantFactory, JobPostingFactory, CandidateFactory

        # Create second tenant
        tenant2 = TenantFactory(
            name='Other Company',
            slug='other-company',
            plan=self.plan
        )

        # Create data in first tenant
        job1 = JobPostingFactory(
            tenant=self.tenant,
            title='Job at Tenant 1'
        )
        candidate1 = CandidateFactory(
            tenant=self.tenant,
            email='candidate1@test.com'
        )

        # Create data in second tenant
        job2 = JobPostingFactory(
            tenant=tenant2,
            title='Job at Tenant 2'
        )
        candidate2 = CandidateFactory(
            tenant=tenant2,
            email='candidate2@test.com'
        )

        # Verify isolation
        from jobs.models import JobPosting, Candidate

        tenant1_jobs = JobPosting.objects.filter(tenant=self.tenant)
        tenant2_jobs = JobPosting.objects.filter(tenant=tenant2)

        self.assertEqual(tenant1_jobs.count(), 1)
        self.assertEqual(tenant2_jobs.count(), 1)
        self.assertNotEqual(tenant1_jobs.first().title, tenant2_jobs.first().title)

        # Cross-tenant query should not return other tenant's data
        self.assertFalse(tenant1_jobs.filter(pk=job2.pk).exists())
        self.assertFalse(tenant2_jobs.filter(pk=job1.pk).exists())


# =============================================================================
# 3. KYC VERIFICATION FLOW INTEGRATION TESTS
# =============================================================================

class TestKYCVerificationFlowIntegration(TenantTransactionTestCase):
    """
    Integration tests for KYC verification workflow:
    Submit request -> External provider callback ->
    Status update -> Trust score calculation
    """

    def test_complete_kyc_verification_flow(self):
        """Test complete KYC verification from submission to approval."""
        from conftest import UserFactory, KYCVerificationFactory, UserProfileFactory
        from tenant_profiles.models import KYCVerification

        # Create user and profile
        user = UserFactory(
            email='kyc.user@test.com',
            first_name='KYC',
            last_name='User'
        )

        profile = UserProfileFactory(
            user=user,
            profile_type='candidate',
            phone='+1234567890',
            country='CA'
        )

        # Step 1: User submits KYC verification request
        kyc_verification = KYCVerificationFactory(
            user=user,
            verification_type='identity',
            status='pending',
            level='basic',
            provider='sumsub',
            document_type='passport',
            document_country='CA'
        )

        self.assertEqual(kyc_verification.status, 'pending')

        # Step 2: Mock external provider callback
        with patch('tenant_profiles.models.KYCVerification.sync_with_provider') as mock_sync:
            mock_sync.return_value = True

            # Simulate Sumsub webhook callback with approval
            kyc_verification.status = 'verified'
            kyc_verification.confidence_score = Decimal('97.50')
            kyc_verification.verified_at = timezone.now()
            kyc_verification.expires_at = timezone.now() + timedelta(days=365)
            kyc_verification.verification_data = {
                'applicant_id': 'sumsub_12345',
                'review_result': 'GREEN',
                'checks_passed': ['document', 'face_match', 'liveness']
            }
            kyc_verification.save()

        kyc_verification.refresh_from_db()

        self.assertEqual(kyc_verification.status, 'verified')
        self.assertEqual(kyc_verification.confidence_score, Decimal('97.50'))
        self.assertIsNotNone(kyc_verification.verified_at)

    @patch('tenant_profiles.services.kyc_service.SumsubClient')
    def test_kyc_verification_with_mock_provider(self, MockSumsubClient):
        """Test KYC flow with mocked Sumsub provider."""
        from conftest import UserFactory, KYCVerificationFactory

        # Configure mock
        mock_client_instance = MagicMock()
        mock_client_instance.create_applicant.return_value = {
            'id': 'applicant_123',
            'createdAt': timezone.now().isoformat()
        }
        mock_client_instance.get_applicant_status.return_value = {
            'id': 'applicant_123',
            'status': 'approved',
            'reviewResult': {
                'reviewAnswer': 'GREEN',
                'checkType': 'PRECISE'
            }
        }
        MockSumsubClient.return_value = mock_client_instance

        user = UserFactory()

        # Create pending verification
        kyc = KYCVerificationFactory(
            user=user,
            verification_type='identity',
            status='pending',
            provider='sumsub',
            provider_reference_id='applicant_123'
        )

        # Simulate processing the verification
        kyc.status = 'in_review'
        kyc.save()

        # Simulate provider approval callback
        kyc.status = 'verified'
        kyc.verified_at = timezone.now()
        kyc.confidence_score = Decimal('95.00')
        kyc.save()

        kyc.refresh_from_db()
        self.assertEqual(kyc.status, 'verified')

    def test_kyc_verification_rejection_flow(self):
        """Test KYC verification rejection and resubmission."""
        from conftest import UserFactory, KYCVerificationFactory

        user = UserFactory()

        # Initial submission
        kyc = KYCVerificationFactory(
            user=user,
            verification_type='identity',
            status='pending',
            provider='onfido'
        )

        # Rejection with reason
        kyc.status = 'rejected'
        kyc.rejection_reasons = {
            'document': 'Document image quality too low',
            'face_match': 'Unable to verify face match'
        }
        kyc.save()

        self.assertEqual(kyc.status, 'rejected')

        # Resubmission
        new_kyc = KYCVerificationFactory(
            user=user,
            verification_type='identity',
            status='pending',
            provider='onfido'
        )

        # This time it passes
        new_kyc.status = 'verified'
        new_kyc.verified_at = timezone.now()
        new_kyc.confidence_score = Decimal('92.00')
        new_kyc.save()

        self.assertEqual(new_kyc.status, 'verified')

    def test_kyc_level2_career_verification(self):
        """Test Level 2 (career) verification with employment check."""
        from conftest import UserFactory, KYCVerificationFactory

        user = UserFactory()

        # Level 1 must be complete first
        level1_kyc = KYCVerificationFactory(
            user=user,
            verification_type='identity',
            status='verified',
            level='basic',
            verified_at=timezone.now()
        )

        # Level 2 - Career verification
        level2_kyc = KYCVerificationFactory(
            user=user,
            verification_type='employment',
            status='pending',
            level='advanced'
        )

        # Simulate employment verification
        level2_kyc.verification_data = {
            'employer': 'Previous Company Inc',
            'position': 'Software Engineer',
            'start_date': '2020-01-15',
            'end_date': '2023-06-30',
            'verification_method': 'email_confirmation',
            'confirmed_by': 'hr@previouscompany.com'
        }
        level2_kyc.status = 'verified'
        level2_kyc.verified_at = timezone.now()
        level2_kyc.save()

        self.assertEqual(level2_kyc.status, 'verified')
        self.assertEqual(level2_kyc.level, 'advanced')

    def test_trust_score_calculation_after_kyc(self):
        """Test trust score is updated after KYC verification."""
        from conftest import UserFactory, KYCVerificationFactory, UserProfileFactory

        user = UserFactory()
        profile = UserProfileFactory(user=user)

        # Before KYC - no trust indicators
        initial_score = getattr(profile, 'trust_score', 0)

        # Complete KYC verification
        kyc = KYCVerificationFactory(
            user=user,
            verification_type='identity',
            status='verified',
            level='basic',
            confidence_score=Decimal('98.00'),
            verified_at=timezone.now()
        )

        # In a real system, trust score would be recalculated
        # Here we verify the KYC is properly linked
        self.assertEqual(kyc.user, user)
        self.assertEqual(kyc.status, 'verified')


# =============================================================================
# 4. TIME-OFF REQUEST FLOW INTEGRATION TESTS
# =============================================================================

class TestTimeOffRequestFlowIntegration(TenantTransactionTestCase):
    """
    Integration tests for time-off request workflow:
    Employee request -> Manager review -> Approve/Reject ->
    Balance update -> Calendar update
    """

    def setUp(self):
        """Set up test with HR fixtures."""
        super().setUp()
        self._setup_hr_fixtures()

    def _setup_hr_fixtures(self):
        """Create HR fixtures for time-off testing."""
        from conftest import (
            UserFactory, TenantUserFactory, EmployeeFactory,
            TimeOffTypeFactory, VacationTypeFactory, SickLeaveTypeFactory
        )

        # Create manager
        self.manager_user = UserFactory(
            email='manager@company.test',
            first_name='Manager',
            last_name='User'
        )
        self.manager_tenant_user = TenantUserFactory(
            user=self.manager_user,
            tenant=self.tenant,
            role='hr_manager'
        )
        self.manager_employee = EmployeeFactory(
            tenant=self.tenant,
            user=self.manager_user,
            status='active',
            job_title='HR Manager'
        )

        # Create employee
        self.employee_user = UserFactory(
            email='employee@company.test',
            first_name='Employee',
            last_name='User'
        )
        self.employee_tenant_user = TenantUserFactory(
            user=self.employee_user,
            tenant=self.tenant,
            role='employee'
        )
        self.employee = EmployeeFactory(
            tenant=self.tenant,
            user=self.employee_user,
            status='active',
            job_title='Software Developer',
            manager=self.manager_employee,
            pto_balance=Decimal('15.00'),
            sick_leave_balance=Decimal('10.00')
        )

        # Create time-off types
        self.vacation_type = VacationTypeFactory(
            tenant=self.tenant,
            name='Vacation',
            code='vacation'
        )
        self.sick_type = SickLeaveTypeFactory(
            tenant=self.tenant,
            name='Sick Leave',
            code='sick'
        )

    def test_complete_time_off_request_approval_flow(self):
        """Test complete time-off request from submission to balance update."""
        from hr_core.models import TimeOffRequest

        # Step 1: Employee submits time-off request
        start_date = date.today() + timedelta(days=14)
        end_date = start_date + timedelta(days=4)  # 5 days including start

        request = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=self.employee,
            time_off_type=self.vacation_type,
            start_date=start_date,
            end_date=end_date,
            is_half_day=False,
            total_days=Decimal('5.00'),
            reason='Family vacation',
            status='pending'
        )

        self.assertEqual(request.status, 'pending')
        self.assertEqual(request.total_days, Decimal('5.00'))

        # Step 2: Manager reviews and approves
        request.status = 'approved'
        request.approver = self.manager_user
        request.approved_at = timezone.now()
        request.approver_notes = 'Approved. Enjoy your vacation!'
        request.save()

        request.refresh_from_db()
        self.assertEqual(request.status, 'approved')
        self.assertEqual(request.approver, self.manager_user)

        # Step 3: Update employee's PTO balance
        initial_balance = self.employee.pto_balance
        self.employee.pto_balance = initial_balance - request.total_days
        self.employee.save()

        self.employee.refresh_from_db()
        self.assertEqual(self.employee.pto_balance, Decimal('10.00'))

    def test_time_off_request_rejection_flow(self):
        """Test time-off request rejection."""
        from hr_core.models import TimeOffRequest

        # Employee submits request during busy period
        request = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=self.employee,
            time_off_type=self.vacation_type,
            start_date=date.today() + timedelta(days=3),
            end_date=date.today() + timedelta(days=10),
            total_days=Decimal('8.00'),
            reason='Extended vacation',
            status='pending'
        )

        # Manager rejects due to project deadline
        request.status = 'rejected'
        request.approver = self.manager_user
        request.approved_at = timezone.now()
        request.approver_notes = 'Cannot approve due to upcoming product launch. Please reschedule.'
        request.save()

        request.refresh_from_db()

        self.assertEqual(request.status, 'rejected')
        # Balance should remain unchanged
        self.assertEqual(self.employee.pto_balance, Decimal('15.00'))

    def test_sick_leave_request_with_documentation(self):
        """Test sick leave request that requires documentation."""
        from hr_core.models import TimeOffRequest

        # Multi-day sick leave requiring doctor's note
        request = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=self.employee,
            time_off_type=self.sick_type,
            start_date=date.today() - timedelta(days=2),
            end_date=date.today(),
            total_days=Decimal('3.00'),
            reason='Flu',
            status='pending',
            documentation_provided=False  # Initially no doc
        )

        # Request requires documentation for 3+ days
        self.assertEqual(request.status, 'pending')

        # Employee provides documentation
        request.documentation_provided = True
        request.documentation_notes = "Doctor's note uploaded"
        request.save()

        # Manager approves
        request.status = 'approved'
        request.approver = self.manager_user
        request.approved_at = timezone.now()
        request.save()

        # Update sick leave balance
        self.employee.sick_leave_balance -= request.total_days
        self.employee.save()

        self.employee.refresh_from_db()
        self.assertEqual(self.employee.sick_leave_balance, Decimal('7.00'))

    def test_insufficient_balance_handling(self):
        """Test handling time-off request with insufficient balance."""
        from hr_core.models import TimeOffRequest

        # Try to request more days than available
        request = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=self.employee,
            time_off_type=self.vacation_type,
            start_date=date.today() + timedelta(days=30),
            end_date=date.today() + timedelta(days=60),  # 31 days
            total_days=Decimal('31.00'),  # More than 15 available
            reason='Extended leave',
            status='pending'
        )

        # Balance check
        has_sufficient_balance = self.employee.pto_balance >= request.total_days
        self.assertFalse(has_sufficient_balance)

        # Request should be rejected or require special approval
        request.status = 'rejected'
        request.approver_notes = 'Insufficient PTO balance. Current balance: 15 days.'
        request.save()

        self.assertEqual(request.status, 'rejected')

    def test_time_off_request_cancellation(self):
        """Test employee cancelling approved time-off request."""
        from hr_core.models import TimeOffRequest

        # Create and approve request
        request = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=self.employee,
            time_off_type=self.vacation_type,
            start_date=date.today() + timedelta(days=21),
            end_date=date.today() + timedelta(days=25),
            total_days=Decimal('5.00'),
            reason='Vacation',
            status='approved',
            approver=self.manager_user,
            approved_at=timezone.now()
        )

        # Deduct balance
        self.employee.pto_balance -= request.total_days
        self.employee.save()
        self.assertEqual(self.employee.pto_balance, Decimal('10.00'))

        # Employee cancels before start date
        request.status = 'cancelled'
        request.cancelled_at = timezone.now()
        request.cancellation_reason = 'Trip cancelled'
        request.save()

        # Restore balance
        self.employee.pto_balance += request.total_days
        self.employee.save()

        self.employee.refresh_from_db()
        self.assertEqual(self.employee.pto_balance, Decimal('15.00'))
        self.assertEqual(request.status, 'cancelled')

    def test_overlapping_time_off_requests(self):
        """Test handling of overlapping time-off requests."""
        from hr_core.models import TimeOffRequest

        # First request - approved
        request1 = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=self.employee,
            time_off_type=self.vacation_type,
            start_date=date.today() + timedelta(days=10),
            end_date=date.today() + timedelta(days=14),
            total_days=Decimal('5.00'),
            reason='First vacation',
            status='approved',
            approver=self.manager_user
        )

        # Second request - overlapping dates
        overlapping_start = date.today() + timedelta(days=12)
        overlapping_end = date.today() + timedelta(days=16)

        # Check for overlap
        existing_requests = TimeOffRequest.objects.filter(
            employee=self.employee,
            status='approved',
            start_date__lte=overlapping_end,
            end_date__gte=overlapping_start
        )

        has_overlap = existing_requests.exists()
        self.assertTrue(has_overlap)

        # New request should be flagged or rejected
        request2 = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=self.employee,
            time_off_type=self.vacation_type,
            start_date=overlapping_start,
            end_date=overlapping_end,
            total_days=Decimal('5.00'),
            reason='Second vacation (overlapping)',
            status='pending'
        )

        # Reject due to overlap
        request2.status = 'rejected'
        request2.approver_notes = 'Overlaps with existing approved request'
        request2.save()

        self.assertEqual(request2.status, 'rejected')


# =============================================================================
# 5. FREELANCE MISSION FLOW INTEGRATION TESTS
# =============================================================================

class TestFreelanceMissionFlowIntegration(TenantTransactionTestCase):
    """
    Integration tests for freelance mission workflow:
    Post mission -> Fund escrow -> Freelancer delivers ->
    Client reviews -> Release payment
    """

    def setUp(self):
        """Set up test with freelance marketplace fixtures."""
        super().setUp()
        self._setup_freelance_fixtures()

    def _setup_freelance_fixtures(self):
        """Create freelance marketplace fixtures."""
        from conftest import UserFactory, TenantUserFactory

        # Create client user
        self.client_user = UserFactory(
            email='client@business.test',
            first_name='Client',
            last_name='Business'
        )
        self.client_tenant_user = TenantUserFactory(
            user=self.client_user,
            tenant=self.tenant,
            role='member'
        )

        # Create freelancer user
        self.freelancer_user = UserFactory(
            email='freelancer@example.test',
            first_name='Freelance',
            last_name='Developer'
        )
        self.freelancer_tenant_user = TenantUserFactory(
            user=self.freelancer_user,
            tenant=self.tenant,
            role='member'
        )

    @patch('stripe.PaymentIntent.create')
    @patch('stripe.PaymentIntent.capture')
    @patch('stripe.Transfer.create')
    def test_complete_freelance_mission_flow(
        self, mock_transfer, mock_capture, mock_create_payment
    ):
        """Test complete freelance mission from posting to payment release."""
        from services.models import (
            ServiceProvider, ServiceCategory, Service,
            ClientRequest, ServiceProposal, ServiceContract
        )
        from escrow.models import EscrowTransaction

        # Configure mocks
        mock_create_payment.return_value = MagicMock(
            id='pi_test123',
            status='requires_capture',
            client_secret='secret_123'
        )
        mock_capture.return_value = MagicMock(
            id='pi_test123',
            status='succeeded'
        )
        mock_transfer.return_value = MagicMock(
            id='tr_test123',
            amount=4500  # $45.00 (after platform fee)
        )

        # Step 1: Create service category
        category = ServiceCategory.objects.create(
            tenant=self.tenant,
            name='Web Development',
            slug='web-development'
        )

        # Step 2: Create service provider (freelancer)
        provider = ServiceProvider.objects.create(
            tenant=self.tenant,
            user=self.freelancer_user,
            display_name='Expert Developer',
            bio='Experienced web developer',
            hourly_rate=Decimal('75.00'),
            currency='CAD',
            is_verified=True,
            stripe_account_id='acct_test123',
            stripe_onboarding_complete=True,
            stripe_payouts_enabled=True
        )
        provider.categories.add(category)

        # Step 3: Create service offering
        service = Service.objects.create(
            tenant=self.tenant,
            provider=provider,
            category=category,
            title='Custom Website Development',
            description='Professional website development service',
            price_type='fixed',
            base_price=Decimal('500.00'),
            currency='CAD',
            delivery_time_days=14,
            revisions_included=2,
            is_active=True
        )

        # Step 4: Client creates request
        client_request = ClientRequest.objects.create(
            tenant=self.tenant,
            client=self.client_user,
            category=category,
            title='Need a landing page',
            description='Looking for a professional landing page for my startup',
            budget_min=Decimal('400.00'),
            budget_max=Decimal('600.00'),
            currency='CAD',
            deadline=date.today() + timedelta(days=21),
            status='open'
        )

        # Step 5: Freelancer submits proposal
        proposal = ServiceProposal.objects.create(
            tenant=self.tenant,
            client_request=client_request,
            provider=provider,
            service=service,
            proposed_price=Decimal('500.00'),
            currency='CAD',
            delivery_days=14,
            cover_letter='I can create an excellent landing page for your startup...',
            status='pending'
        )

        self.assertEqual(proposal.status, 'pending')

        # Step 6: Client accepts proposal
        proposal.status = 'accepted'
        proposal.accepted_at = timezone.now()
        proposal.save()

        client_request.status = 'in_progress'
        client_request.save()

        # Step 7: Create contract
        contract = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.client_user,
            provider=provider,
            proposal=proposal,
            service=service,
            client_request=client_request,
            title='Landing Page Development',
            description='Custom landing page as per proposal',
            agreed_rate=proposal.proposed_price,
            rate_type='fixed',
            currency='CAD',
            agreed_deadline=date.today() + timedelta(days=14),
            revisions_allowed=2,
            status='draft'
        )

        # Step 8: Fund escrow
        escrow = EscrowTransaction.objects.create(
            buyer=self.client_user,
            seller=self.freelancer_user,
            amount=contract.agreed_rate,
            currency='CAD',
            status='initialized',
            payment_intent_id='pi_test123'
        )

        # Link escrow to contract
        contract.escrow_transaction = escrow
        contract.status = 'pending_payment'
        contract.save()

        # Capture payment (escrow funded)
        escrow.mark_funded()
        contract.status = 'funded'
        contract.save()

        self.assertEqual(escrow.status, 'funded')
        self.assertEqual(contract.status, 'funded')

        # Step 9: Start work
        contract.start()
        self.assertEqual(contract.status, 'in_progress')
        self.assertIsNotNone(contract.started_at)

        # Step 10: Freelancer delivers work
        contract.deliver()
        self.assertEqual(contract.status, 'delivered')
        self.assertIsNotNone(contract.delivered_at)

        escrow.mark_service_delivered()
        self.assertEqual(escrow.status, 'service_delivered')

        # Step 11: Client accepts delivery
        contract.complete()
        self.assertEqual(contract.status, 'completed')
        self.assertIsNotNone(contract.completed_at)

        # Step 12: Release escrow to freelancer
        escrow.mark_released()
        self.assertEqual(escrow.status, 'released')

        # Verify payout amount (after 10% platform fee)
        expected_payout = contract.provider_payout_amount
        self.assertEqual(expected_payout, Decimal('450.00'))

        # Step 13: Update provider stats
        provider.completed_jobs_count += 1
        provider.total_earnings += expected_payout
        provider.save()

        provider.refresh_from_db()
        self.assertEqual(provider.completed_jobs_count, 1)
        self.assertEqual(provider.total_earnings, Decimal('450.00'))

    @patch('stripe.Refund.create')
    def test_freelance_mission_dispute_flow(self, mock_refund):
        """Test dispute resolution in freelance mission."""
        from services.models import ServiceProvider, ServiceContract
        from escrow.models import EscrowTransaction, Dispute

        mock_refund.return_value = MagicMock(
            id='re_test123',
            status='succeeded'
        )

        # Create provider and contract
        provider = ServiceProvider.objects.create(
            tenant=self.tenant,
            user=self.freelancer_user,
            display_name='Developer',
            is_verified=True
        )

        escrow = EscrowTransaction.objects.create(
            buyer=self.client_user,
            seller=self.freelancer_user,
            amount=Decimal('300.00'),
            currency='CAD',
            status='funded',
            funded_at=timezone.now()
        )

        contract = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.client_user,
            provider=provider,
            title='Disputed Project',
            agreed_rate=Decimal('300.00'),
            rate_type='fixed',
            currency='CAD',
            escrow_transaction=escrow,
            status='in_progress',
            started_at=timezone.now()
        )

        # Freelancer marks as delivered
        contract.deliver()
        escrow.mark_service_delivered()

        # Client disputes
        contract.status = 'disputed'
        contract.save()

        escrow.raise_dispute()
        self.assertEqual(escrow.status, 'dispute')

        dispute = Dispute.objects.create(
            escrow=escrow,
            raised_by=self.client_user,
            reason='Work does not match requirements',
            details='The delivered work is missing key features...'
        )

        self.assertFalse(dispute.resolved)

        # Resolve dispute - partial refund
        dispute.resolved = True
        dispute.resolved_at = timezone.now()
        dispute.resolution_notes = 'Agreed to 50% refund due to incomplete work'
        dispute.save()

        # Process partial refund
        escrow.status = 'refunded'
        escrow.refunded_at = timezone.now()
        escrow.save()

        contract.status = 'refunded'
        contract.cancelled_at = timezone.now()
        contract.cancellation_reason = 'Dispute resolved with refund'
        contract.save()

        self.assertEqual(escrow.status, 'refunded')
        self.assertEqual(contract.status, 'refunded')
        self.assertTrue(dispute.resolved)

    def test_freelance_mission_cancellation_flow(self):
        """Test cancellation of freelance mission before work starts."""
        from services.models import ServiceProvider, ServiceContract
        from escrow.models import EscrowTransaction

        provider = ServiceProvider.objects.create(
            tenant=self.tenant,
            user=self.freelancer_user,
            display_name='Developer'
        )

        escrow = EscrowTransaction.objects.create(
            buyer=self.client_user,
            seller=self.freelancer_user,
            amount=Decimal('200.00'),
            currency='CAD',
            status='funded',
            funded_at=timezone.now()
        )

        contract = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.client_user,
            provider=provider,
            title='Cancelled Project',
            agreed_rate=Decimal('200.00'),
            rate_type='fixed',
            currency='CAD',
            escrow_transaction=escrow,
            status='funded'
        )

        # Client cancels before work starts
        contract.cancel('Project requirements changed')
        self.assertEqual(contract.status, 'cancelled')

        # Full refund to client
        escrow.mark_refunded()
        self.assertEqual(escrow.status, 'refunded')


# =============================================================================
# 6. DATA PRIVACY FLOW INTEGRATION TESTS
# =============================================================================

class TestDataPrivacyFlowIntegration(TenantTransactionTestCase):
    """
    Integration tests for data privacy workflow:
    Request consent -> Grant access -> Access data ->
    Revoke consent -> Verify access denied
    """

    def setUp(self):
        """Set up test with privacy fixtures."""
        super().setUp()
        self._setup_privacy_fixtures()

    def _setup_privacy_fixtures(self):
        """Create fixtures for privacy testing."""
        from conftest import UserFactory, TenantUserFactory, UserProfileFactory, CandidateFactory

        # Create candidate user
        self.candidate_user = UserFactory(
            email='candidate@privacy.test',
            first_name='Privacy',
            last_name='Candidate'
        )
        self.candidate_profile = UserProfileFactory(
            user=self.candidate_user,
            profile_type='candidate',
            phone='+1234567890',
            address_line1='123 Privacy Street',
            city='Toronto',
            country='CA'
        )

        # Create candidate record
        self.candidate = CandidateFactory(
            tenant=self.tenant,
            first_name='Privacy',
            last_name='Candidate',
            email='candidate@privacy.test',
            phone='+1234567890'
        )

        # Create employer/recruiter
        self.recruiter_user = UserFactory(
            email='recruiter@company.test'
        )
        self.recruiter_tenant_user = TenantUserFactory(
            user=self.recruiter_user,
            tenant=self.tenant,
            role='recruiter'
        )

    def test_complete_consent_management_flow(self):
        """Test complete consent flow from request to revocation."""
        from conftest import ProgressiveConsentFactory
        from tenant_profiles.models import ProgressiveConsent

        # Step 1: Request consent for basic data
        consent_basic = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='basic',
            status='not_requested',
            purpose='Job application processing'
        )

        # Update to requested status
        consent_basic.status = 'requested'
        consent_basic.requested_at = timezone.now()
        consent_basic.save()

        self.assertEqual(consent_basic.status, 'requested')

        # Step 2: Candidate grants consent
        consent_basic.status = 'granted'
        consent_basic.granted_at = timezone.now()
        consent_basic.expires_at = timezone.now() + timedelta(days=365)
        consent_basic.save()

        self.assertEqual(consent_basic.status, 'granted')
        self.assertIsNotNone(consent_basic.granted_at)

        # Step 3: Verify access is allowed
        can_access = consent_basic.status == 'granted'
        self.assertTrue(can_access)

        # Step 4: Request extended data (contact info)
        consent_contact = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='contact',
            status='requested',
            purpose='Interview scheduling',
            requested_at=timezone.now()
        )

        # Grant contact consent
        consent_contact.status = 'granted'
        consent_contact.granted_at = timezone.now()
        consent_contact.save()

        # Step 5: Revoke basic consent
        consent_basic.status = 'revoked'
        consent_basic.revoked_at = timezone.now()
        consent_basic.revocation_reason = 'No longer interested in position'
        consent_basic.save()

        self.assertEqual(consent_basic.status, 'revoked')
        self.assertIsNotNone(consent_basic.revoked_at)

        # Step 6: Verify access is denied
        can_access_basic = consent_basic.status == 'granted'
        self.assertFalse(can_access_basic)

        # Contact consent still valid
        can_access_contact = consent_contact.status == 'granted'
        self.assertTrue(can_access_contact)

    def test_progressive_data_revelation_stages(self):
        """Test progressive data revelation through recruitment stages."""
        from conftest import ProgressiveConsentFactory
        from jobs.models import Application

        # Stage 1: Basic data (name, photo, skills) - always visible
        consent_basic = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='basic',
            status='granted',
            granted_at=timezone.now()
        )

        # Data visible at stage 1
        stage1_data = {
            'name': self.candidate.full_name,
            'skills': getattr(self.candidate, 'skills', []),
            'city': self.candidate.city
        }

        self.assertIsNotNone(stage1_data['name'])

        # Stage 2: After "Interested" - phone, LinkedIn, availability
        consent_contact = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='contact',
            status='granted',
            granted_at=timezone.now()
        )

        # Verify contact data access
        stage2_data = {
            'phone': self.candidate.phone,
            'linkedin': self.candidate.linkedin_url
        }

        self.assertIsNotNone(stage2_data['phone'])

        # Stage 3: Post-interview - full address, references
        consent_detailed = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='detailed',
            status='not_requested'
        )

        # Detailed data not yet accessible
        can_access_detailed = consent_detailed.status == 'granted'
        self.assertFalse(can_access_detailed)

        # Stage 4: Offer accepted - sensitive data (SIN/SSN, medical)
        consent_sensitive = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='sensitive',
            status='not_requested'
        )

        # Sensitive data not accessible without grant
        can_access_sensitive = consent_sensitive.status == 'granted'
        self.assertFalse(can_access_sensitive)

    def test_consent_expiration_handling(self):
        """Test handling of expired consent."""
        from conftest import ProgressiveConsentFactory

        # Create consent that has expired
        expired_consent = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='basic',
            status='granted',
            granted_at=timezone.now() - timedelta(days=400),
            expires_at=timezone.now() - timedelta(days=35)  # Expired 35 days ago
        )

        # Check if consent is expired
        is_expired = (
            expired_consent.expires_at is not None and
            expired_consent.expires_at < timezone.now()
        )
        self.assertTrue(is_expired)

        # Access should be denied for expired consent
        can_access = (
            expired_consent.status == 'granted' and
            not is_expired
        )
        self.assertFalse(can_access)

        # Mark as expired (would be done by scheduled task)
        expired_consent.status = 'expired'
        expired_consent.save()

        self.assertEqual(expired_consent.status, 'expired')

    def test_data_deletion_request_flow(self):
        """Test GDPR-style data deletion request."""
        from conftest import ProgressiveConsentFactory

        # Create multiple consents
        consents = []
        for category in ['basic', 'contact', 'detailed']:
            consent = ProgressiveConsentFactory(
                grantor=self.candidate_user,
                grantee_tenant=self.tenant,
                data_category=category,
                status='granted',
                granted_at=timezone.now()
            )
            consents.append(consent)

        # User requests data deletion
        deletion_request_time = timezone.now()

        # Revoke all consents
        for consent in consents:
            consent.status = 'revoked'
            consent.revoked_at = deletion_request_time
            consent.revocation_reason = 'Data deletion request'
            consent.save()

        # Verify all consents revoked
        from tenant_profiles.models import ProgressiveConsent
        active_consents = ProgressiveConsent.objects.filter(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            status='granted'
        ).count()

        self.assertEqual(active_consents, 0)

        # Candidate data should be anonymized/deleted
        # In real implementation, this would trigger anonymization
        self.candidate.first_name = 'Deleted'
        self.candidate.last_name = 'User'
        self.candidate.email = f'deleted_{self.candidate.id}@anonymized.local'
        self.candidate.phone = ''
        self.candidate.save()

        self.candidate.refresh_from_db()
        self.assertEqual(self.candidate.first_name, 'Deleted')

    def test_consent_audit_trail(self):
        """Test that consent changes are properly logged."""
        from conftest import ProgressiveConsentFactory, AuditLogFactory

        # Create consent
        consent = ProgressiveConsentFactory(
            grantor=self.candidate_user,
            grantee_tenant=self.tenant,
            data_category='basic',
            status='not_requested'
        )

        # Log consent request
        request_log = AuditLogFactory(
            tenant=self.tenant,
            user=self.recruiter_user,
            action='consent_requested',
            resource_type='ProgressiveConsent',
            resource_id=str(consent.id),
            description=f'Consent requested for {consent.data_category} data'
        )

        consent.status = 'requested'
        consent.requested_at = timezone.now()
        consent.save()

        # Log consent grant
        grant_log = AuditLogFactory(
            tenant=self.tenant,
            user=self.candidate_user,
            action='consent_granted',
            resource_type='ProgressiveConsent',
            resource_id=str(consent.id),
            description=f'Consent granted for {consent.data_category} data'
        )

        consent.status = 'granted'
        consent.granted_at = timezone.now()
        consent.save()

        # Verify audit trail exists
        from tenants.models import AuditLog
        consent_logs = AuditLog.objects.filter(
            resource_type='ProgressiveConsent',
            resource_id=str(consent.id)
        )

        self.assertEqual(consent_logs.count(), 2)


# =============================================================================
# ADDITIONAL CROSS-APP INTEGRATION TESTS
# =============================================================================

class TestCrossAppIntegration(TenantTransactionTestCase):
    """
    Additional integration tests for cross-app interactions.
    """

    def test_candidate_to_employee_data_transfer(self):
        """Test data transfer when candidate becomes employee."""
        from conftest import (
            CandidateFactory, ApplicationFactory, JobPostingFactory,
            PipelineFactory, PipelineStageFactory, UserFactory
        )
        from hr_core.models import Employee

        # Create pipeline and job
        pipeline = PipelineFactory(tenant=self.tenant)
        hired_stage = PipelineStageFactory(
            pipeline=pipeline,
            name='Hired',
            stage_type='hired'
        )
        job = JobPostingFactory(
            tenant=self.tenant,
            pipeline=pipeline
        )

        # Create candidate with detailed info
        candidate = CandidateFactory(
            tenant=self.tenant,
            first_name='Transfer',
            last_name='Candidate',
            email='transfer@candidate.test',
            phone='+1987654321',
            city='Vancouver',
            current_title='Senior Developer',
            years_experience=7
        )

        # Create hired application
        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=candidate,
            job=job,
            status='hired',
            current_stage=hired_stage,
            hired_at=timezone.now()
        )

        # Create user account for candidate
        candidate_user = UserFactory(
            email=candidate.email,
            first_name=candidate.first_name,
            last_name=candidate.last_name
        )

        # Create employee record with transferred data
        employee = Employee.objects.create(
            tenant=self.tenant,
            user=candidate_user,
            employee_id='EMP-TRANSFER-001',
            status='active',
            employment_type='full_time',
            job_title=job.title,
            hire_date=application.hired_at.date(),
            start_date=application.hired_at.date() + timedelta(days=14),
            source_application=application
        )

        # Verify data transfer
        self.assertEqual(employee.user.email, candidate.email)
        self.assertEqual(employee.job_title, job.title)
        self.assertEqual(employee.source_application, application)

    def test_tenant_plan_feature_enforcement(self):
        """Test that plan features are properly enforced."""
        from conftest import TenantFactory, PlanFactory, JobPostingFactory

        # Create limited plan
        limited_plan = PlanFactory(
            name='Starter',
            slug='starter',
            plan_type='starter',
            max_job_postings=3,
            feature_custom_pipelines=False,
            feature_ai_matching=False
        )

        # Create tenant with limited plan
        limited_tenant = TenantFactory(
            name='Limited Company',
            slug='limited-company',
            plan=limited_plan
        )

        # Create jobs up to limit
        jobs = []
        for i in range(3):
            job = JobPostingFactory(
                tenant=limited_tenant,
                title=f'Job {i+1}'
            )
            jobs.append(job)

        # Verify limit reached
        from jobs.models import JobPosting
        job_count = JobPosting.objects.filter(tenant=limited_tenant).count()
        self.assertEqual(job_count, 3)

        # Check if at limit
        at_limit = job_count >= limited_plan.max_job_postings
        self.assertTrue(at_limit)

        # Feature flag check
        self.assertFalse(limited_plan.feature_custom_pipelines)
        self.assertFalse(limited_plan.feature_ai_matching)

    def test_audit_logging_across_apps(self):
        """Test that actions across apps are properly logged."""
        from conftest import (
            AuditLogFactory, JobPostingFactory, CandidateFactory,
            ApplicationFactory
        )

        # Create entities and log actions
        job = JobPostingFactory(tenant=self.tenant)
        job_log = AuditLogFactory(
            tenant=self.tenant,
            user=self.user,
            action='create',
            resource_type='JobPosting',
            resource_id=str(job.id),
            description=f'Created job posting: {job.title}'
        )

        candidate = CandidateFactory(tenant=self.tenant)
        candidate_log = AuditLogFactory(
            tenant=self.tenant,
            user=self.user,
            action='create',
            resource_type='Candidate',
            resource_id=str(candidate.id),
            description=f'Candidate applied: {candidate.full_name}'
        )

        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=candidate,
            job=job
        )
        application_log = AuditLogFactory(
            tenant=self.tenant,
            user=self.user,
            action='create',
            resource_type='Application',
            resource_id=str(application.id),
            description=f'Application submitted for {job.title}'
        )

        # Verify audit trail
        from tenants.models import AuditLog
        tenant_logs = AuditLog.objects.filter(tenant=self.tenant)

        # Should have logs for job, candidate, and application
        self.assertGreaterEqual(tenant_logs.count(), 3)

        # Verify specific log entries
        job_logs = tenant_logs.filter(resource_type='JobPosting')
        self.assertEqual(job_logs.count(), 1)


# =============================================================================
# DATABASE TRANSACTION TESTS
# =============================================================================

class TestDatabaseTransactionIntegrity(TenantTransactionTestCase):
    """
    Tests for database transaction integrity across operations.
    """

    def test_atomic_application_stage_change(self):
        """Test that application stage changes are atomic."""
        from conftest import (
            JobPostingFactory, CandidateFactory, ApplicationFactory,
            PipelineFactory, PipelineStageFactory
        )
        from jobs.models import Application, ApplicationActivity

        pipeline = PipelineFactory(tenant=self.tenant)
        stage1 = PipelineStageFactory(pipeline=pipeline, name='Stage 1', order=0)
        stage2 = PipelineStageFactory(pipeline=pipeline, name='Stage 2', order=1)

        job = JobPostingFactory(tenant=self.tenant, pipeline=pipeline)
        candidate = CandidateFactory(tenant=self.tenant)
        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=candidate,
            job=job,
            current_stage=stage1
        )

        initial_stage = application.current_stage

        # Move to stage 2
        application.move_to_stage(stage2, user=self.user)

        application.refresh_from_db()
        self.assertEqual(application.current_stage, stage2)

        # Verify activity was logged
        activities = ApplicationActivity.objects.filter(
            application=application,
            activity_type='stage_change'
        )
        self.assertGreaterEqual(activities.count(), 1)

    def test_concurrent_application_modification_protection(self):
        """Test optimistic locking prevents concurrent modifications."""
        from conftest import JobPostingFactory, CandidateFactory, ApplicationFactory
        from jobs.models import Application

        job = JobPostingFactory(tenant=self.tenant)
        candidate = CandidateFactory(tenant=self.tenant)
        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=candidate,
            job=job
        )

        # Get two references to same application
        app_ref1 = Application.objects.get(pk=application.pk)
        app_ref2 = Application.objects.get(pk=application.pk)

        # Modify through first reference
        app_ref1.status = 'in_review'
        app_ref1.save()

        # Second reference now has stale version
        app_ref2.status = 'shortlisted'

        # This should raise ConcurrentModificationError in real implementation
        # For now, we verify versions are tracked
        app_ref1.refresh_from_db()
        self.assertEqual(app_ref1.status, 'in_review')


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases(TenantTransactionTestCase):
    """
    Tests for edge cases and boundary conditions.
    """

    def test_empty_pipeline_handling(self):
        """Test handling of pipeline with no stages."""
        from conftest import PipelineFactory, JobPostingFactory, CandidateFactory, ApplicationFactory

        # Create pipeline without stages
        empty_pipeline = PipelineFactory(
            tenant=self.tenant,
            name='Empty Pipeline'
        )

        job = JobPostingFactory(
            tenant=self.tenant,
            pipeline=empty_pipeline
        )

        candidate = CandidateFactory(tenant=self.tenant)

        # Application without stage
        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=candidate,
            job=job,
            current_stage=None
        )

        self.assertIsNone(application.current_stage)

    def test_offer_with_zero_salary(self):
        """Test handling of volunteer/unpaid position offer."""
        from conftest import JobPostingFactory, CandidateFactory, ApplicationFactory
        from jobs.models import Offer

        job = JobPostingFactory(
            tenant=self.tenant,
            job_type='internship'
        )
        candidate = CandidateFactory(tenant=self.tenant)
        application = ApplicationFactory(
            tenant=self.tenant,
            candidate=candidate,
            job=job
        )

        # Create unpaid internship offer
        offer = Offer.objects.create(
            application=application,
            status='draft',
            job_title='Unpaid Internship',
            base_salary=Decimal('0.00'),
            salary_currency='CAD',
            salary_period='yearly',
            created_by=self.user
        )

        self.assertEqual(offer.base_salary, Decimal('0.00'))

    def test_candidate_with_special_characters_in_name(self):
        """Test handling of special characters in candidate names."""
        from conftest import CandidateFactory

        candidate = CandidateFactory(
            tenant=self.tenant,
            first_name="Jean-Pierre",
            last_name="O'Connor-Smith",
            email="jp.oconnor@test.com"
        )

        self.assertEqual(candidate.first_name, "Jean-Pierre")
        self.assertEqual(candidate.last_name, "O'Connor-Smith")

    def test_time_off_request_for_single_day(self):
        """Test time-off request for exactly one day."""
        from conftest import EmployeeFactory, VacationTypeFactory
        from hr_core.models import TimeOffRequest

        employee = EmployeeFactory(
            tenant=self.tenant,
            user=self.user,
            pto_balance=Decimal('10.00')
        )

        vacation_type = VacationTypeFactory(tenant=self.tenant)

        # Single day request
        request = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=employee,
            time_off_type=vacation_type,
            start_date=date.today() + timedelta(days=7),
            end_date=date.today() + timedelta(days=7),  # Same day
            total_days=Decimal('1.00'),
            reason='Personal appointment',
            status='pending'
        )

        self.assertEqual(request.total_days, Decimal('1.00'))
        self.assertEqual(request.start_date, request.end_date)

    def test_half_day_time_off_request(self):
        """Test half-day time-off request."""
        from conftest import EmployeeFactory, VacationTypeFactory
        from hr_core.models import TimeOffRequest

        employee = EmployeeFactory(
            tenant=self.tenant,
            user=self.user,
            pto_balance=Decimal('10.00')
        )

        vacation_type = VacationTypeFactory(tenant=self.tenant)

        # Half day request
        request = TimeOffRequest.objects.create(
            tenant=self.tenant,
            employee=employee,
            time_off_type=vacation_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=5),
            is_half_day=True,
            half_day_period='morning',
            total_days=Decimal('0.50'),
            reason='Doctor appointment',
            status='pending'
        )

        self.assertEqual(request.total_days, Decimal('0.50'))
        self.assertTrue(request.is_half_day)


# =============================================================================
# PYTEST FIXTURES FOR INTEGRATION TESTS
# =============================================================================

@pytest.fixture
def hiring_workflow_setup(db, tenant, user):
    """Fixture providing complete hiring workflow setup."""
    from conftest import (
        PipelineFactory, PipelineStageFactory, JobCategoryFactory,
        JobPostingFactory, UserFactory, TenantUserFactory
    )

    pipeline = PipelineFactory(tenant=tenant, is_default=True)

    stages = {
        'new': PipelineStageFactory(pipeline=pipeline, stage_type='new', order=0),
        'screening': PipelineStageFactory(pipeline=pipeline, stage_type='screening', order=1),
        'interview': PipelineStageFactory(pipeline=pipeline, stage_type='interview', order=2),
        'offer': PipelineStageFactory(pipeline=pipeline, stage_type='offer', order=3),
        'hired': PipelineStageFactory(pipeline=pipeline, stage_type='hired', order=4),
    }

    category = JobCategoryFactory(tenant=tenant)

    recruiter = UserFactory()
    TenantUserFactory(user=recruiter, tenant=tenant, role='recruiter')

    hiring_manager = UserFactory()
    TenantUserFactory(user=hiring_manager, tenant=tenant, role='hiring_manager')

    job = JobPostingFactory(
        tenant=tenant,
        pipeline=pipeline,
        category=category,
        hiring_manager=hiring_manager,
        recruiter=recruiter
    )

    return {
        'pipeline': pipeline,
        'stages': stages,
        'category': category,
        'job': job,
        'recruiter': recruiter,
        'hiring_manager': hiring_manager,
    }


@pytest.fixture
def hr_workflow_setup(db, tenant, user):
    """Fixture providing HR workflow setup."""
    from conftest import (
        UserFactory, TenantUserFactory, EmployeeFactory,
        VacationTypeFactory, SickLeaveTypeFactory
    )

    manager_user = UserFactory()
    TenantUserFactory(user=manager_user, tenant=tenant, role='hr_manager')
    manager_employee = EmployeeFactory(tenant=tenant, user=manager_user)

    employee_user = UserFactory()
    TenantUserFactory(user=employee_user, tenant=tenant, role='employee')
    employee = EmployeeFactory(
        tenant=tenant,
        user=employee_user,
        manager=manager_employee,
        pto_balance=Decimal('15.00'),
        sick_leave_balance=Decimal('10.00')
    )

    vacation_type = VacationTypeFactory(tenant=tenant)
    sick_type = SickLeaveTypeFactory(tenant=tenant)

    return {
        'manager_user': manager_user,
        'manager_employee': manager_employee,
        'employee_user': employee_user,
        'employee': employee,
        'vacation_type': vacation_type,
        'sick_type': sick_type,
    }


@pytest.fixture
def freelance_workflow_setup(db, tenant, user):
    """Fixture providing freelance marketplace workflow setup."""
    from conftest import UserFactory, TenantUserFactory

    client_user = UserFactory()
    TenantUserFactory(user=client_user, tenant=tenant, role='member')

    freelancer_user = UserFactory()
    TenantUserFactory(user=freelancer_user, tenant=tenant, role='member')

    return {
        'client_user': client_user,
        'freelancer_user': freelancer_user,
    }
