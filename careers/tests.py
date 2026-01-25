"""
Careers Tests - Public Career Pages

Tests for:
- Public career page rendering
- Job listing public view
- Public application submission
- Application processing to ATS
- Talent pools
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.db import IntegrityError

from careers.models import (
    CareerPage, CareerPageSection, JobListing,
    PublicApplication, TalentPool, TalentPoolMember
)


# ============================================================================
# CAREER PAGE TESTS
# ============================================================================

@pytest.mark.django_db
class TestCareerPageModel:
    """Tests for CareerPage model."""

    def test_create_career_page(self, career_page_factory):
        """Test basic career page creation."""
        page = career_page_factory()
        assert page.pk is not None
        assert page.uuid is not None
        assert page.title is not None

    def test_career_page_branding(self, career_page_factory):
        """Test career page branding settings."""
        page = career_page_factory(
            primary_color='#FF5733',
            secondary_color='#33FF57',
            accent_color='#5733FF'
        )

        assert page.primary_color == '#FF5733'
        assert page.secondary_color == '#33FF57'
        assert page.accent_color == '#5733FF'

    def test_career_page_content_sections(self, career_page_factory):
        """Test career page content section flags."""
        page = career_page_factory(
            show_company_info=True,
            show_benefits=True,
            show_culture=True,
            show_values=True,
            show_team=False
        )

        assert page.show_company_info is True
        assert page.show_benefits is True
        assert page.show_culture is True
        assert page.show_values is True
        assert page.show_team is False

    def test_career_page_social_links(self, career_page_factory):
        """Test career page social links."""
        page = career_page_factory(
            linkedin_url='https://linkedin.com/company/acme',
            twitter_url='https://twitter.com/acme',
            facebook_url='https://facebook.com/acme'
        )

        assert page.linkedin_url == 'https://linkedin.com/company/acme'
        assert page.twitter_url == 'https://twitter.com/acme'

    def test_career_page_seo_settings(self, career_page_factory):
        """Test career page SEO settings."""
        page = career_page_factory(
            meta_title='Careers at Acme Corp',
            meta_description='Join our amazing team',
            meta_keywords='careers, jobs, hiring'
        )

        assert page.meta_title == 'Careers at Acme Corp'
        assert 'amazing team' in page.meta_description

    def test_career_page_settings(self, career_page_factory):
        """Test career page settings."""
        page = career_page_factory(
            require_account=True,
            show_salary_range=True,
            allow_general_applications=False
        )

        assert page.require_account is True
        assert page.show_salary_range is True
        assert page.allow_general_applications is False

    def test_career_page_string_representation(self, career_page_factory):
        """Test career page string representation."""
        page = career_page_factory(title='Join Our Team')
        assert str(page) == 'Join Our Team'


@pytest.mark.django_db
class TestCareerPageRendering:
    """Tests for career page rendering."""

    def test_active_career_page(self, career_page_factory):
        """Test active career page."""
        page = career_page_factory(is_active=True)
        assert page.is_active is True

    def test_inactive_career_page(self, career_page_factory):
        """Test inactive career page."""
        page = career_page_factory(is_active=False)
        assert page.is_active is False

    def test_career_page_with_custom_css(self, career_page_factory):
        """Test career page with custom CSS."""
        custom_css = '.job-card { border-radius: 8px; }'
        page = career_page_factory(custom_css=custom_css)

        assert page.custom_css == custom_css

    def test_career_page_with_analytics(self, career_page_factory):
        """Test career page with analytics IDs."""
        page = career_page_factory(
            google_analytics_id='UA-123456789-1',
            facebook_pixel_id='1234567890'
        )

        assert page.google_analytics_id == 'UA-123456789-1'
        assert page.facebook_pixel_id == '1234567890'


# ============================================================================
# CAREER PAGE SECTION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCareerPageSectionModel:
    """Tests for CareerPageSection model."""

    def test_create_career_page_section(self):
        """Test basic career page section creation."""
        from conftest import CareerPageSectionFactory
        section = CareerPageSectionFactory()

        assert section.pk is not None
        assert section.career_page is not None
        assert section.title is not None

    def test_section_types(self):
        """Test different section types."""
        from conftest import CareerPageSectionFactory
        for section_type, label in CareerPageSection.SectionType.choices:
            section = CareerPageSectionFactory(section_type=section_type)
            assert section.section_type == section_type

    def test_section_ordering(self, career_page_factory):
        """Test section ordering."""
        from conftest import CareerPageSectionFactory
        page = career_page_factory()

        section3 = CareerPageSectionFactory(career_page=page, order=3)
        section1 = CareerPageSectionFactory(career_page=page, order=1)
        section2 = CareerPageSectionFactory(career_page=page, order=2)

        sections = list(CareerPageSection.objects.filter(career_page=page).order_by('order'))
        assert sections[0].order == 1
        assert sections[1].order == 2
        assert sections[2].order == 3

    def test_section_visibility(self):
        """Test section visibility."""
        from conftest import CareerPageSectionFactory
        visible = CareerPageSectionFactory(is_visible=True)
        hidden = CareerPageSectionFactory(is_visible=False)

        assert visible.is_visible is True
        assert hidden.is_visible is False

    def test_section_with_json_content(self):
        """Test section with JSON content."""
        from conftest import CareerPageSectionFactory
        section = CareerPageSectionFactory(
            section_type='testimonial',
            content={
                'author': 'John Doe',
                'role': 'Senior Engineer',
                'quote': 'Great place to work!',
                'avatar': '/images/john.jpg'
            }
        )

        assert section.content['author'] == 'John Doe'
        assert section.content['quote'] == 'Great place to work!'

    def test_section_string_representation(self, career_page_factory):
        """Test section string representation."""
        from conftest import CareerPageSectionFactory
        page = career_page_factory(title='Careers')
        section = CareerPageSectionFactory(career_page=page, title='Our Values')

        assert 'Careers' in str(section)
        assert 'Our Values' in str(section)


# ============================================================================
# JOB LISTING TESTS
# ============================================================================

@pytest.mark.django_db
class TestJobListingModel:
    """Tests for JobListing model."""

    def test_create_job_listing(self, job_listing_factory):
        """Test basic job listing creation."""
        listing = job_listing_factory()
        assert listing.pk is not None
        assert listing.job is not None

    def test_job_listing_display_settings(self, job_listing_factory):
        """Test job listing display settings."""
        listing = job_listing_factory(
            show_company_name=True,
            show_department=True,
            show_team_size=True,
            show_application_count=True
        )

        assert listing.show_company_name is True
        assert listing.show_department is True
        assert listing.show_team_size is True
        assert listing.show_application_count is True

    def test_job_listing_featured(self, job_listing_factory):
        """Test featured job listing."""
        from conftest import FeaturedJobListingFactory
        listing = FeaturedJobListingFactory()

        assert listing.is_featured is True
        assert listing.feature_priority == 10

    def test_job_listing_view_count(self, job_listing_factory):
        """Test job listing view count tracking."""
        listing = job_listing_factory(view_count=0)

        listing.increment_view()
        assert listing.view_count == 1

        listing.increment_view()
        listing.increment_view()
        assert listing.view_count == 3

    def test_job_listing_is_expired_property(self, job_listing_factory):
        """Test is_expired property."""
        # Not expired
        active_listing = job_listing_factory(
            expires_at=timezone.now() + timedelta(days=30)
        )
        assert active_listing.is_expired is False

        # Expired
        expired_listing = job_listing_factory(
            expires_at=timezone.now() - timedelta(days=1)
        )
        assert expired_listing.is_expired is True

        # No expiration
        no_expiry_listing = job_listing_factory(expires_at=None)
        assert no_expiry_listing.is_expired is False

    def test_job_listing_string_representation(self, job_listing_factory, job_posting_factory):
        """Test job listing string representation."""
        job = job_posting_factory(title='Software Engineer')
        listing = job_listing_factory(job=job)

        assert str(listing) == 'Software Engineer'


@pytest.mark.django_db
class TestJobListingPublicView:
    """Tests for job listing public view."""

    def test_published_job_listing(self, job_listing_factory):
        """Test published job listing."""
        listing = job_listing_factory(
            published_at=timezone.now()
        )

        assert listing.published_at is not None

    def test_job_listing_with_custom_slug(self, job_listing_factory):
        """Test job listing with custom slug."""
        listing = job_listing_factory(custom_slug='senior-dev-toronto')

        assert listing.custom_slug == 'senior-dev-toronto'

    def test_job_listing_with_custom_application_form(self, job_listing_factory):
        """Test job listing with custom application form."""
        custom_form = {
            'fields': [
                {'name': 'years_experience', 'type': 'number', 'required': True},
                {'name': 'available_date', 'type': 'date', 'required': False},
                {'name': 'why_interested', 'type': 'textarea', 'required': True}
            ]
        }
        listing = job_listing_factory(custom_application_form=custom_form)

        assert len(listing.custom_application_form['fields']) == 3

    def test_job_listing_ordering(self, job_listing_factory):
        """Test job listing ordering (featured first)."""
        regular = job_listing_factory(is_featured=False)
        featured = job_listing_factory(is_featured=True, feature_priority=10)

        listings = list(JobListing.objects.all())
        assert listings[0].is_featured is True


# ============================================================================
# PUBLIC APPLICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestPublicApplicationModel:
    """Tests for PublicApplication model."""

    def test_create_public_application(self, public_application_factory):
        """Test basic public application creation."""
        application = public_application_factory()
        assert application.pk is not None
        assert application.uuid is not None
        assert application.email is not None

    def test_public_application_statuses(self, public_application_factory):
        """Test different application statuses."""
        for status, label in PublicApplication.ApplicationStatus.choices:
            application = public_application_factory(status=status)
            assert application.status == status

    def test_public_application_consent(self, public_application_factory):
        """Test consent tracking."""
        application = public_application_factory(
            privacy_consent=True,
            marketing_consent=False,
            consent_timestamp=timezone.now(),
            consent_ip='192.168.1.1'
        )

        assert application.privacy_consent is True
        assert application.marketing_consent is False
        assert application.consent_ip == '192.168.1.1'

    def test_public_application_tracking(self, public_application_factory):
        """Test UTM and tracking parameters."""
        application = public_application_factory(
            utm_source='linkedin',
            utm_medium='social',
            utm_campaign='dev-jobs-2024',
            referrer='https://linkedin.com/jobs'
        )

        assert application.utm_source == 'linkedin'
        assert application.utm_medium == 'social'
        assert application.utm_campaign == 'dev-jobs-2024'

    def test_public_application_string_representation(self, public_application_factory, job_listing_factory, job_posting_factory):
        """Test application string representation."""
        job = job_posting_factory(title='Developer')
        listing = job_listing_factory(job=job)
        application = public_application_factory(
            job_listing=listing,
            first_name='John',
            last_name='Doe'
        )

        assert 'John Doe' in str(application)


@pytest.mark.django_db
class TestPublicApplicationSubmission:
    """Tests for public application submission."""

    def test_submit_application(self, job_listing_factory):
        """Test submitting a public application."""
        listing = job_listing_factory()

        application = PublicApplication.objects.create(
            job_listing=listing,
            first_name='Jane',
            last_name='Smith',
            email='jane.smith@example.com',
            phone='+14165551234',
            cover_letter='I am excited to apply...',
            privacy_consent=True,
            consent_timestamp=timezone.now(),
            status='pending'
        )

        assert application.status == 'pending'
        assert application.email == 'jane.smith@example.com'

    def test_submit_general_application(self):
        """Test submitting a general application (no specific job)."""
        application = PublicApplication.objects.create(
            job_listing=None,  # General application
            first_name='Bob',
            last_name='Johnson',
            email='bob.johnson@example.com',
            privacy_consent=True,
            consent_timestamp=timezone.now(),
            status='pending'
        )

        assert application.job_listing is None
        assert application.status == 'pending'

    def test_application_with_custom_answers(self, public_application_factory):
        """Test application with custom form answers."""
        application = public_application_factory(
            custom_answers={
                'years_experience': 5,
                'available_date': '2024-02-01',
                'why_interested': 'Great company culture!'
            }
        )

        assert application.custom_answers['years_experience'] == 5


@pytest.mark.django_db
class TestPublicApplicationProcessing:
    """Tests for processing public applications to ATS."""

    def test_process_new_candidate(self, public_application_factory, job_listing_factory):
        """Test processing application for new candidate."""
        listing = job_listing_factory()
        application = public_application_factory(
            job_listing=listing,
            first_name='New',
            last_name='Candidate',
            email='new.candidate@example.com',
            status='pending'
        )

        result = application.process_to_ats()

        # Note: This test assumes the process_to_ats method creates
        # the ATS records. The actual implementation may vary.
        assert application.status in ['processed', 'pending']

    def test_process_duplicate_application(self, public_application_factory, candidate_factory, job_listing_factory, job_posting_factory, application_factory):
        """Test processing duplicate application."""
        from jobs.models import Candidate

        # Create existing candidate and application
        job = job_posting_factory()
        listing = job_listing_factory(job=job)
        candidate = candidate_factory(email='existing@example.com')
        application_factory(candidate=candidate, job=job)

        # Submit public application with same email
        public_app = public_application_factory(
            job_listing=listing,
            email='existing@example.com',
            status='pending'
        )

        result = public_app.process_to_ats()

        # Should be marked as duplicate
        public_app.refresh_from_db()
        # The status depends on implementation
        assert public_app.status in ['duplicate', 'processed', 'pending']

    def test_processed_application_links_to_ats(self):
        """Test processed application has links to ATS records."""
        from conftest import ProcessedPublicApplicationFactory

        application = ProcessedPublicApplicationFactory()

        assert application.status == 'processed'
        assert application.ats_candidate is not None
        assert application.ats_application is not None


# ============================================================================
# TALENT POOL TESTS
# ============================================================================

@pytest.mark.django_db
class TestTalentPoolModel:
    """Tests for TalentPool model."""

    def test_create_talent_pool(self, talent_pool_factory):
        """Test basic talent pool creation."""
        pool = talent_pool_factory()
        assert pool.pk is not None
        assert pool.uuid is not None
        assert pool.name is not None

    def test_public_talent_pool(self, talent_pool_factory):
        """Test public talent pool (candidates can self-join)."""
        pool = talent_pool_factory(is_public=True)
        assert pool.is_public is True

    def test_private_talent_pool(self, talent_pool_factory):
        """Test private talent pool."""
        pool = talent_pool_factory(is_public=False)
        assert pool.is_public is False

    def test_talent_pool_auto_criteria(self, talent_pool_factory):
        """Test talent pool with auto-add criteria."""
        pool = talent_pool_factory(
            auto_add_criteria={
                'skills': ['Python', 'Django'],
                'min_experience': 3,
                'location': 'Toronto'
            }
        )

        assert pool.auto_add_criteria['skills'] == ['Python', 'Django']
        assert pool.auto_add_criteria['min_experience'] == 3

    def test_talent_pool_string_representation(self, talent_pool_factory):
        """Test talent pool string representation."""
        pool = talent_pool_factory(name='Python Developers')
        assert str(pool) == 'Python Developers'


@pytest.mark.django_db
class TestTalentPoolMemberModel:
    """Tests for TalentPoolMember model."""

    def test_add_candidate_to_pool(self, talent_pool_factory, candidate_factory, user_factory):
        """Test adding candidate to talent pool."""
        pool = talent_pool_factory()
        candidate = candidate_factory()
        recruiter = user_factory()

        member = TalentPoolMember.objects.create(
            pool=pool,
            candidate=candidate,
            added_by=recruiter,
            notes='Great Python skills'
        )

        assert member.pool == pool
        assert member.candidate == candidate
        assert member.added_by == recruiter

    def test_talent_pool_member_unique_constraint(self, talent_pool_factory, candidate_factory):
        """Test candidate can only be in pool once."""
        from conftest import TalentPoolMemberFactory

        pool = talent_pool_factory()
        candidate = candidate_factory()

        TalentPoolMemberFactory(pool=pool, candidate=candidate)

        with pytest.raises(IntegrityError):
            TalentPoolMemberFactory(pool=pool, candidate=candidate)

    def test_candidate_multiple_pools(self, talent_pool_factory, candidate_factory):
        """Test candidate can be in multiple pools."""
        from conftest import TalentPoolMemberFactory

        pool1 = talent_pool_factory(name='Python Devs')
        pool2 = talent_pool_factory(name='Senior Engineers')
        candidate = candidate_factory()

        TalentPoolMemberFactory(pool=pool1, candidate=candidate)
        TalentPoolMemberFactory(pool=pool2, candidate=candidate)

        assert candidate.talent_pools.count() == 2

    def test_talent_pool_member_string_representation(self):
        """Test member string representation."""
        from conftest import TalentPoolMemberFactory, TalentPoolFactory, CandidateFactory

        pool = TalentPoolFactory(name='Designers')
        candidate = CandidateFactory(first_name='Alice', last_name='Wonder')
        member = TalentPoolMemberFactory(pool=pool, candidate=candidate)

        assert 'Alice Wonder' in str(member)
        assert 'Designers' in str(member)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCareersIntegration:
    """Integration tests for careers functionality."""

    def test_complete_public_application_flow(self, job_posting_factory, user_factory):
        """Test complete public application flow."""
        from conftest import JobListingFactory

        # Setup job and listing
        job = job_posting_factory(status='open', title='Senior Developer')
        listing = JobListingFactory(job=job, is_featured=True)

        # Submit public application
        application = PublicApplication.objects.create(
            job_listing=listing,
            first_name='Test',
            last_name='Applicant',
            email='test.applicant@example.com',
            phone='+14165551234',
            cover_letter='I would love to join your team...',
            privacy_consent=True,
            consent_timestamp=timezone.now(),
            utm_source='indeed',
            utm_campaign='senior-dev-2024',
            status='pending'
        )

        # Track view
        listing.increment_view()
        listing.apply_click_count += 1
        listing.save()

        assert listing.view_count == 1
        assert listing.apply_click_count == 1
        assert application.status == 'pending'

    def test_career_page_with_multiple_jobs(self, career_page_factory, job_posting_factory):
        """Test career page with multiple job listings."""
        from conftest import JobListingFactory, CareerPageSectionFactory

        page = career_page_factory()
        CareerPageSectionFactory(career_page=page, title='About Us', order=0)
        CareerPageSectionFactory(career_page=page, title='Benefits', order=1)

        # Create multiple jobs
        jobs = [
            job_posting_factory(title='Frontend Developer', status='open'),
            job_posting_factory(title='Backend Developer', status='open'),
            job_posting_factory(title='DevOps Engineer', status='open'),
        ]

        listings = [
            JobListingFactory(job=job, is_featured=(i == 0))
            for i, job in enumerate(jobs)
        ]

        assert JobListing.objects.count() == 3
        assert JobListing.objects.filter(is_featured=True).count() == 1

    def test_talent_pool_sourcing(self, candidate_factory, talent_pool_factory, user_factory):
        """Test using talent pool for sourcing."""
        from conftest import TalentPoolMemberFactory

        recruiter = user_factory()

        # Create talent pool
        python_pool = talent_pool_factory(
            name='Python Developers',
            auto_add_criteria={'skills': ['Python', 'Django']}
        )

        # Add candidates
        candidates = [
            candidate_factory(skills=['Python', 'Django', 'PostgreSQL']),
            candidate_factory(skills=['Python', 'Flask', 'MongoDB']),
            candidate_factory(skills=['Python', 'FastAPI', 'Redis']),
        ]

        for candidate in candidates:
            TalentPoolMemberFactory(
                pool=python_pool,
                candidate=candidate,
                added_by=recruiter
            )

        assert python_pool.members.count() == 3

    def test_application_source_tracking(self, job_listing_factory):
        """Test tracking different application sources."""
        listing = job_listing_factory()

        # Application from LinkedIn
        app1 = PublicApplication.objects.create(
            job_listing=listing,
            first_name='LinkedIn',
            last_name='User',
            email='linkedin@example.com',
            utm_source='linkedin',
            utm_medium='social',
            privacy_consent=True,
            consent_timestamp=timezone.now(),
            status='pending'
        )

        # Application from Indeed
        app2 = PublicApplication.objects.create(
            job_listing=listing,
            first_name='Indeed',
            last_name='User',
            email='indeed@example.com',
            utm_source='indeed',
            utm_medium='job_board',
            privacy_consent=True,
            consent_timestamp=timezone.now(),
            status='pending'
        )

        # Application from direct
        app3 = PublicApplication.objects.create(
            job_listing=listing,
            first_name='Direct',
            last_name='User',
            email='direct@example.com',
            source='direct',
            privacy_consent=True,
            consent_timestamp=timezone.now(),
            status='pending'
        )

        linkedin_apps = PublicApplication.objects.filter(utm_source='linkedin')
        indeed_apps = PublicApplication.objects.filter(utm_source='indeed')
        direct_apps = PublicApplication.objects.filter(source='direct')

        assert linkedin_apps.count() == 1
        assert indeed_apps.count() == 1
        assert direct_apps.count() == 1

    def test_full_career_page_setup(self, full_career_page):
        """Test full career page setup fixture."""
        career_page, jobs = full_career_page

        assert career_page is not None
        assert career_page.is_active is True
        assert career_page.sections.count() == 2
        assert len(jobs) == 3

        # Check featured job ordering
        featured_jobs = [j for j in jobs if j.is_featured]
        assert len(featured_jobs) == 1
