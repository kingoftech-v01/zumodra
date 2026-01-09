"""
Tests for Configurations API.

This module tests the configurations API endpoints including:
- Skills
- Companies
- Sites
- Departments
- Roles
- Memberships
- Jobs
- Job Applications
- FAQs
- Testimonials
- Partnerships
- Leave Requests
"""

import pytest
from decimal import Decimal
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from configurations.models import (
    Skill, Company, Site, Department, Role, Membership,
    Job, JobPosition, JobApplication, FAQEntry,
    Testimonial, Partnership, TrustedCompany, LeaveRequest
)


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_factory):
    """Return authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


@pytest.fixture
def admin_authenticated_client(api_client, superuser_factory):
    """Return authenticated admin API client."""
    admin = superuser_factory()
    api_client.force_authenticate(user=admin)
    return api_client, admin


@pytest.fixture
def skill(db):
    """Create test skill."""
    return Skill.objects.create(
        name='Python',
        description='Python programming language',
        category='Programming',
        is_verified=True
    )


@pytest.fixture
def company(db):
    """Create test company."""
    return Company.objects.create(
        name='Test Company',
        description='A test company',
        industry='Technology',
        is_verified=True
    )


@pytest.fixture
def site(db, company):
    """Create test site."""
    return Site.objects.create(
        company=company,
        name='Headquarters',
        address='123 Main St',
        city='Toronto',
        country='CA',
        is_active=True
    )


@pytest.fixture
def faq(db):
    """Create test FAQ."""
    return FAQEntry.objects.create(
        question='What is Zumodra?',
        answer='Zumodra is a multi-tenant SaaS platform.',
        category='General',
        is_published=True,
        sort_order=1
    )


@pytest.fixture
def testimonial(db):
    """Create test testimonial."""
    return Testimonial.objects.create(
        author_name='John Doe',
        author_company='Acme Corp',
        content='Great platform!',
        rating=5,
        is_published=True,
        is_featured=True
    )


@pytest.fixture
def partnership(db):
    """Create test partnership."""
    return Partnership.objects.create(
        name='Partner Company',
        description='A strategic partner',
        is_featured=True,
        sort_order=1
    )


@pytest.fixture
def trusted_company(db):
    """Create test trusted company."""
    return TrustedCompany.objects.create(
        name='Trusted Corp',
        sort_order=1
    )


# =============================================================================
# SKILL TESTS
# =============================================================================

class TestSkillViewSet:
    """Tests for SkillViewSet."""

    @pytest.mark.django_db
    def test_list_skills(self, authenticated_client, skill):
        """Test listing skills."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:skill-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_skill(self, authenticated_client, skill):
        """Test retrieving a skill."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:skill-detail', args=[skill.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data.get('name') == skill.name

    @pytest.mark.django_db
    def test_create_skill(self, authenticated_client):
        """Test creating a skill."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:skill-list')
        response = client.post(url, {
            'name': 'JavaScript',
            'description': 'JavaScript programming language',
            'category': 'Programming'
        })

        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.django_db
    def test_filter_skills_by_category(self, authenticated_client, skill):
        """Test filtering skills by category."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:skill-list')
        response = client.get(url, {'category': 'Programming'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_search_skills(self, authenticated_client, skill):
        """Test searching skills."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:skill-list')
        response = client.get(url, {'search': 'Python'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_verify_skill(self, admin_authenticated_client, skill):
        """Test verifying a skill (admin action)."""
        client, admin = admin_authenticated_client
        skill.is_verified = False
        skill.save()

        url = reverse('api_v1:configurations:skill-verify', args=[skill.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        skill.refresh_from_db()
        assert skill.is_verified is True


# =============================================================================
# COMPANY TESTS
# =============================================================================

class TestCompanyViewSet:
    """Tests for CompanyViewSet."""

    @pytest.mark.django_db
    def test_list_companies(self, authenticated_client, company):
        """Test listing companies."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:company-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_company(self, authenticated_client, company):
        """Test retrieving a company."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:company-detail', args=[company.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data.get('name') == company.name

    @pytest.mark.django_db
    def test_filter_companies_by_industry(self, authenticated_client, company):
        """Test filtering companies by industry."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:company-list')
        response = client.get(url, {'industry': 'Technology'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_get_company_sites(self, authenticated_client, company, site):
        """Test getting company sites."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:company-sites', args=[company.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1


# =============================================================================
# SITE TESTS
# =============================================================================

class TestSiteViewSet:
    """Tests for SiteViewSet."""

    @pytest.mark.django_db
    def test_list_sites(self, authenticated_client, site):
        """Test listing sites."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:site-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_site(self, authenticated_client, site):
        """Test retrieving a site."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:site-detail', args=[site.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# FAQ TESTS
# =============================================================================

class TestFAQViewSet:
    """Tests for FAQViewSet."""

    @pytest.mark.django_db
    def test_list_faqs(self, authenticated_client, faq):
        """Test listing FAQs."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:faq-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_faq(self, authenticated_client, faq):
        """Test retrieving a FAQ."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:faq-detail', args=[faq.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data.get('question') == faq.question

    @pytest.mark.django_db
    def test_faqs_by_category(self, authenticated_client, faq):
        """Test getting FAQs by category."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:faq-by-category')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'General' in response.data

    @pytest.mark.django_db
    def test_unpublished_faqs_hidden_from_non_admin(self, authenticated_client):
        """Test unpublished FAQs are hidden from non-admin users."""
        client, user = authenticated_client
        FAQEntry.objects.create(
            question='Unpublished FAQ',
            answer='This is not published',
            is_published=False
        )

        url = reverse('api_v1:configurations:faq-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        # Should not include unpublished FAQs
        for faq in response.data:
            assert faq.get('is_published', True) is True


# =============================================================================
# TESTIMONIAL TESTS
# =============================================================================

class TestTestimonialViewSet:
    """Tests for TestimonialViewSet."""

    @pytest.mark.django_db
    def test_list_testimonials(self, authenticated_client, testimonial):
        """Test listing testimonials."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:testimonial-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_featured_testimonials(self, authenticated_client, testimonial):
        """Test getting featured testimonials."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:testimonial-featured')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        for t in response.data:
            assert t.get('is_featured') is True


# =============================================================================
# PARTNERSHIP TESTS
# =============================================================================

class TestPartnershipViewSet:
    """Tests for PartnershipViewSet."""

    @pytest.mark.django_db
    def test_list_partnerships(self, authenticated_client, partnership):
        """Test listing partnerships."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:partnership-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_featured_partnerships(self, authenticated_client, partnership):
        """Test getting featured partnerships."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:partnership-featured')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# TRUSTED COMPANY TESTS
# =============================================================================

class TestTrustedCompanyViewSet:
    """Tests for TrustedCompanyViewSet."""

    @pytest.mark.django_db
    def test_list_trusted_companies(self, authenticated_client, trusted_company):
        """Test listing trusted companies."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:trusted-company-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# ROLE TESTS (ADMIN ONLY)
# =============================================================================

class TestRoleViewSet:
    """Tests for RoleViewSet (admin only)."""

    @pytest.mark.django_db
    def test_list_roles_requires_admin(self, authenticated_client):
        """Test listing roles requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:role-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_roles_admin(self, admin_authenticated_client):
        """Test admin can list roles."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:configurations:role-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# JOB TESTS
# =============================================================================

class TestJobViewSet:
    """Tests for JobViewSet."""

    @pytest.fixture
    def job(self, db, company):
        """Create test job."""
        return Job.objects.create(
            company=company,
            title='Software Developer',
            description='A great job opportunity',
            requirements='Python, Django experience',
            salary_from=Decimal('60000'),
            salary_to=Decimal('80000'),
            is_active=True
        )

    @pytest.mark.django_db
    def test_list_jobs(self, authenticated_client, job):
        """Test listing jobs."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:job-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_job(self, authenticated_client, job):
        """Test retrieving a job."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:job-detail', args=[job.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_jobs_by_company(self, authenticated_client, job, company):
        """Test filtering jobs by company."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:job-list')
        response = client.get(url, {'company': company.id})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_filter_jobs_by_salary(self, authenticated_client, job):
        """Test filtering jobs by salary range."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:job-list')
        response = client.get(url, {'min_salary': 50000, 'max_salary': 90000})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_close_job(self, authenticated_client, job):
        """Test closing a job."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:job-close', args=[job.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        job.refresh_from_db()
        assert job.is_active is False

    @pytest.mark.django_db
    def test_reopen_job(self, authenticated_client, job):
        """Test reopening a job."""
        client, user = authenticated_client
        job.is_active = False
        job.save()

        url = reverse('api_v1:configurations:job-reopen', args=[job.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        job.refresh_from_db()
        assert job.is_active is True


# =============================================================================
# DEPARTMENT TESTS
# =============================================================================

class TestDepartmentViewSet:
    """Tests for DepartmentViewSet."""

    @pytest.fixture
    def company_profile(self, db, company):
        """Create company profile."""
        from configurations.models import CompanyProfile
        return CompanyProfile.objects.create(company=company)

    @pytest.fixture
    def department(self, db, company_profile):
        """Create test department."""
        return Department.objects.create(
            company=company_profile,
            name='Engineering',
            description='Engineering department'
        )

    @pytest.mark.django_db
    def test_list_departments(self, authenticated_client, department):
        """Test listing departments."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:department-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_get_department_members(self, authenticated_client, department):
        """Test getting department members."""
        client, user = authenticated_client

        url = reverse('api_v1:configurations:department-members', args=[department.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
