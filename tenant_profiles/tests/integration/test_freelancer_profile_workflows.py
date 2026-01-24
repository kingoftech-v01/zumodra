"""
Integration tests for FreelancerProfile workflows.

Tests complete user journeys and realistic scenarios.
Creates 10-20 demo freelancer profiles covering all possible options.
"""

import pytest
from decimal import Decimal
from rest_framework.test import APIClient
from django.urls import reverse

pytestmark = [pytest.mark.django_db, pytest.mark.integration]


@pytest.fixture
def comprehensive_freelancer_demo_data():
    """
    Create 20 demo freelancer profiles covering all possible configurations.

    Variations covered:
    - Different professional titles and skills
    - Different availability statuses (available, busy, unavailable)
    - Different verification statuses
    - Different locations and remote preferences
    - Different experience levels
    - Different hourly rates
    - Different portfolio configurations
    - Different stats (ratings, completed projects)
    """
    from conftest import (
        FreelancerProfileFactory,
        VerifiedFreelancerProfileFactory,
        BusyFreelancerProfileFactory,
        RemoteOnlyFreelancerProfileFactory,
        WillingToRelocateFreelancerProfileFactory
    )
    from services.models import ServiceCategory

    # Create some service categories for assignment
    web_dev = ServiceCategory.objects.create(name="Web Development", slug="web-development")
    mobile_dev = ServiceCategory.objects.create(name="Mobile Development", slug="mobile-development")
    design = ServiceCategory.objects.create(name="Design", slug="design")
    data_science = ServiceCategory.objects.create(name="Data Science", slug="data-science")

    profiles = []

    # 1. Junior Full-Stack Developer - Entry level, unverified, available
    p1 = FreelancerProfileFactory(
        professional_title="Junior Full-Stack Developer",
        bio="Recent bootcamp grad looking for first freelance projects",
        years_of_experience=1,
        hourly_rate=Decimal('35.00'),
        hourly_rate_currency='CAD',
        availability_status='available',
        availability_hours_per_week=40,
        skills=['HTML', 'CSS', 'JavaScript', 'React', 'Node.js'],
        city='Toronto',
        country='Canada',
        remote_only=True,
        is_verified=False,
        completed_projects=0,
        average_rating=None,
    )
    p1.categories.add(web_dev)
    profiles.append(p1)

    # 2. Senior Python Developer - Highly experienced, verified, busy
    p2 = VerifiedFreelancerProfileFactory(
        professional_title="Senior Python Developer",
        bio="15 years building scalable backend systems. Django expert.",
        years_of_experience=15,
        hourly_rate=Decimal('150.00'),
        hourly_rate_currency='USD',
        availability_status='busy',
        availability_hours_per_week=10,
        skills=['Python', 'Django', 'PostgreSQL', 'Docker', 'AWS'],
        city='San Francisco',
        country='USA',
        remote_only=False,
        willing_to_relocate=False,
        completed_projects=87,
        completed_services=45,
        total_earnings=Decimal('450000.00'),
        average_rating=Decimal('4.9'),
        total_reviews=132,
    )
    p2.categories.add(web_dev, data_science)
    profiles.append(p2)

    # 3. Mobile App Developer - Mid-level, verified, available
    p3 = VerifiedFreelancerProfileFactory(
        professional_title="Mobile App Developer (iOS & Android)",
        bio="Creating beautiful mobile experiences for 6 years",
        years_of_experience=6,
        hourly_rate=Decimal('95.00'),
        hourly_rate_currency='CAD',
        availability_status='available',
        availability_hours_per_week=35,
        skills=['Swift', 'Kotlin', 'React Native', 'Flutter', 'Firebase'],
        city='Vancouver',
        country='Canada',
        remote_only=True,
        completed_projects=34,
        completed_services=12,
        total_earnings=Decimal('185000.00'),
        average_rating=Decimal('4.7'),
        total_reviews=46,
    )
    p3.categories.add(mobile_dev)
    profiles.append(p3)

    # 4. UI/UX Designer - Verified, remote-only, available
    p4 = VerifiedFreelancerProfileFactory(
        professional_title="UI/UX Designer",
        bio="Designing user-centered interfaces. Portfolio: portfolio.com/designer4",
        years_of_experience=8,
        hourly_rate=Decimal('110.00'),
        hourly_rate_currency='EUR',
        availability_status='available',
        availability_hours_per_week=30,
        skills=['Figma', 'Adobe XD', 'Sketch', 'Prototyping', 'User Research'],
        city='',
        country='',
        remote_only=True,
        portfolio_url='https://portfolio.designer4.com',
        behance_url='https://behance.net/designer4',
        dribbble_url='https://dribbble.com/designer4',
        completed_projects=56,
        completed_services=23,
        total_earnings=Decimal('220000.00'),
        average_rating=Decimal('4.8'),
        total_reviews=79,
    )
    p4.categories.add(design)
    profiles.append(p4)

    # 5. Data Scientist - Verified, willing to relocate, available
    p5 = WillingToRelocateFreelancerProfileFactory(
        professional_title="Data Scientist & ML Engineer",
        bio="PhD in Machine Learning. Specializing in NLP and computer vision.",
        years_of_experience=10,
        hourly_rate=Decimal('140.00'),
        hourly_rate_currency='USD',
        availability_status='available',
        availability_hours_per_week=25,
        skills=['Python', 'TensorFlow', 'PyTorch', 'Scikit-learn', 'SQL', 'R'],
        city='Montreal',
        country='Canada',
        remote_only=False,
        willing_to_relocate=True,
        github_url='https://github.com/datascientist5',
        linkedin_url='https://linkedin.com/in/datascientist5',
        completed_projects=42,
        completed_services=18,
        total_earnings=Decimal('310000.00'),
        average_rating=Decimal('5.0'),
        total_reviews=60,
    )
    p5.categories.add(data_science)
    profiles.append(p5)

    # 6. DevOps Engineer - Verified, available, high hourly rate
    p6 = VerifiedFreelancerProfileFactory(
        professional_title="DevOps & Cloud Infrastructure Engineer",
        bio="Automating everything. AWS Certified Solutions Architect.",
        years_of_experience=12,
        hourly_rate=Decimal('160.00'),
        hourly_rate_currency='USD',
        availability_status='available',
        availability_hours_per_week=20,
        skills=['AWS', 'Kubernetes', 'Terraform', 'CI/CD', 'Ansible', 'Docker'],
        city='Austin',
        country='USA',
        remote_only=True,
        github_url='https://github.com/devops6',
        completed_projects=38,
        completed_services=25,
        total_earnings=Decimal('395000.00'),
        average_rating=Decimal('4.9'),
        total_reviews=63,
    )
    p6.categories.add(web_dev)
    profiles.append(p6)

    # 7. Frontend Developer - Entry level, unverified, available, low rate
    p7 = FreelancerProfileFactory(
        professional_title="Frontend Developer",
        bio="Building responsive websites with React",
        years_of_experience=2,
        hourly_rate=Decimal('45.00'),
        hourly_rate_currency='CAD',
        availability_status='available',
        availability_hours_per_week=40,
        skills=['React', 'TypeScript', 'Tailwind CSS', 'Next.js'],
        city='Calgary',
        country='Canada',
        remote_only=True,
        is_verified=False,
        completed_projects=3,
        average_rating=Decimal('4.3'),
        total_reviews=3,
    )
    p7.categories.add(web_dev)
    profiles.append(p7)

    # 8. WordPress Expert - Verified, available, moderate experience
    p8 = VerifiedFreelancerProfileFactory(
        professional_title="WordPress Developer & Consultant",
        bio="Custom themes, plugins, and WooCommerce solutions",
        years_of_experience=7,
        hourly_rate=Decimal('70.00'),
        hourly_rate_currency='GBP',
        availability_status='available',
        availability_hours_per_week=30,
        skills=['WordPress', 'PHP', 'WooCommerce', 'ACF', 'JavaScript'],
        city='London',
        country='UK',
        remote_only=False,
        portfolio_url='https://wpexpert8.com',
        completed_projects=92,
        completed_services=67,
        total_earnings=Decimal('340000.00'),
        average_rating=Decimal('4.6'),
        total_reviews=159,
    )
    p8.categories.add(web_dev)
    profiles.append(p8)

    # 9. Game Developer - Verified, unavailable (sabbatical)
    p9 = VerifiedFreelancerProfileFactory(
        professional_title="Game Developer (Unity & Unreal)",
        bio="Creating immersive gaming experiences. Currently on sabbatical.",
        years_of_experience=9,
        hourly_rate=Decimal('120.00'),
        hourly_rate_currency='USD',
        availability_status='unavailable',
        availability_hours_per_week=0,
        skills=['Unity', 'Unreal Engine', 'C#', 'C++', 'Blender'],
        city='Seattle',
        country='USA',
        remote_only=True,
        completed_projects=27,
        completed_services=8,
        total_earnings=Decimal('240000.00'),
        average_rating=Decimal('4.8'),
        total_reviews=35,
    )
    profiles.append(p9)

    # 10. Blockchain Developer - Verified, available, high rate, niche skills
    p10 = VerifiedFreelancerProfileFactory(
        professional_title="Blockchain & Smart Contract Developer",
        bio="Solidity expert. Building DeFi and NFT platforms.",
        years_of_experience=5,
        hourly_rate=Decimal('180.00'),
        hourly_rate_currency='USD',
        availability_status='available',
        availability_hours_per_week=20,
        skills=['Solidity', 'Ethereum', 'Web3.js', 'Hardhat', 'React'],
        city='Dubai',
        country='UAE',
        remote_only=True,
        github_url='https://github.com/blockchain10',
        completed_projects=19,
        completed_services=5,
        total_earnings=Decimal('210000.00'),
        average_rating=Decimal('4.9'),
        total_reviews=24,
    )
    profiles.append(p10)

    # 11. QA Automation Engineer - Verified, available
    p11 = VerifiedFreelancerProfileFactory(
        professional_title="QA Automation Engineer",
        bio="Ensuring software quality through comprehensive automated testing",
        years_of_experience=6,
        hourly_rate=Decimal('85.00'),
        hourly_rate_currency='CAD',
        availability_status='available',
        availability_hours_per_week=35,
        skills=['Selenium', 'Cypress', 'Jest', 'Python', 'CI/CD'],
        city='Ottawa',
        country='Canada',
        remote_only=True,
        completed_projects=31,
        completed_services=14,
        total_earnings=Decimal('160000.00'),
        average_rating=Decimal('4.7'),
        total_reviews=45,
    )
    profiles.append(p11)

    # 12. Technical Writer - Verified, available, unique skillset
    p12 = VerifiedFreelancerProfileFactory(
        professional_title="Technical Writer & Documentation Specialist",
        bio="Making complex technical concepts accessible through clear documentation",
        years_of_experience=8,
        hourly_rate=Decimal('75.00'),
        hourly_rate_currency='USD',
        availability_status='available',
        availability_hours_per_week=30,
        skills=['Technical Writing', 'Markdown', 'API Documentation', 'User Guides'],
        city='Boston',
        country='USA',
        remote_only=True,
        portfolio_url='https://techwriter12.com',
        completed_projects=78,
        completed_services=45,
        total_earnings=Decimal('280000.00'),
        average_rating=Decimal('4.9'),
        total_reviews=123,
    )
    profiles.append(p12)

    # 13. Cybersecurity Consultant - Verified, busy, high expertise
    p13 = VerifiedFreelancerProfileFactory(
        professional_title="Cybersecurity Consultant & Pentester",
        bio="OSCP certified. Protecting businesses from cyber threats.",
        years_of_experience=11,
        hourly_rate=Decimal('170.00'),
        hourly_rate_currency='USD',
        availability_status='busy',
        availability_hours_per_week=10,
        skills=['Penetration Testing', 'Network Security', 'Python', 'Linux', 'OWASP'],
        city='Washington DC',
        country='USA',
        remote_only=False,
        linkedin_url='https://linkedin.com/in/security13',
        completed_projects=55,
        completed_services=32,
        total_earnings=Decimal('420000.00'),
        average_rating=Decimal('5.0'),
        total_reviews=87,
    )
    profiles.append(p13)

    # 14. SEO Specialist - Verified, available
    p14 = VerifiedFreelancerProfileFactory(
        professional_title="SEO Specialist & Content Strategist",
        bio="Driving organic growth through data-driven SEO strategies",
        years_of_experience=5,
        hourly_rate=Decimal('65.00'),
        hourly_rate_currency='CAD',
        availability_status='available',
        availability_hours_per_week=25,
        skills=['SEO', 'Google Analytics', 'Content Strategy', 'Link Building'],
        city='Edmonton',
        country='Canada',
        remote_only=True,
        completed_projects=64,
        completed_services=89,
        total_earnings=Decimal('205000.00'),
        average_rating=Decimal('4.6'),
        total_reviews=153,
    )
    profiles.append(p14)

    # 15. iOS Developer - Verified, available, Apple ecosystem specialist
    p15 = VerifiedFreelancerProfileFactory(
        professional_title="iOS Developer (Swift & SwiftUI)",
        bio="Building native iOS apps with cutting-edge Apple technologies",
        years_of_experience=7,
        hourly_rate=Decimal('115.00'),
        hourly_rate_currency='USD',
        availability_status='available',
        availability_hours_per_week=30,
        skills=['Swift', 'SwiftUI', 'Combine', 'Core Data', 'UIKit'],
        city='Cupertino',
        country='USA',
        remote_only=True,
        github_url='https://github.com/iosdev15',
        completed_projects=41,
        completed_services=16,
        total_earnings=Decimal('295000.00'),
        average_rating=Decimal('4.8'),
        total_reviews=57,
    )
    p15.categories.add(mobile_dev)
    profiles.append(p15)

    # 16. E-commerce Specialist - Verified, available, Shopify expert
    p16 = VerifiedFreelancerProfileFactory(
        professional_title="E-commerce Developer (Shopify & WooCommerce)",
        bio="Launching and scaling online stores. 100+ stores built.",
        years_of_experience=6,
        hourly_rate=Decimal('80.00'),
        hourly_rate_currency='CAD',
        availability_status='available',
        availability_hours_per_week=35,
        skills=['Shopify', 'Liquid', 'WooCommerce', 'Stripe', 'PayPal Integration'],
        city='Winnipeg',
        country='Canada',
        remote_only=True,
        portfolio_url='https://ecommerce16.ca',
        completed_projects=104,
        completed_services=78,
        total_earnings=Decimal('385000.00'),
        average_rating=Decimal('4.7'),
        total_reviews=182,
    )
    p16.categories.add(web_dev)
    profiles.append(p16)

    # 17. AI/ML Engineer - Verified, available, cutting-edge skills
    p17 = VerifiedFreelancerProfileFactory(
        professional_title="AI/ML Engineer specializing in LLMs",
        bio="Building AI solutions with GPT, Claude, and custom models",
        years_of_experience=4,
        hourly_rate=Decimal('145.00'),
        hourly_rate_currency='USD',
        availability_status='available',
        availability_hours_per_week=25,
        skills=['Python', 'Transformers', 'LangChain', 'OpenAI API', 'Vector DBs'],
        city='Palo Alto',
        country='USA',
        remote_only=True,
        github_url='https://github.com/aiml17',
        linkedin_url='https://linkedin.com/in/aiml17',
        completed_projects=23,
        completed_services=9,
        total_earnings=Decimal('175000.00'),
        average_rating=Decimal('4.9'),
        total_reviews=32,
    )
    p17.categories.add(data_science)
    profiles.append(p17)

    # 18. Graphic Designer - Verified, available, visual branding
    p18 = VerifiedFreelancerProfileFactory(
        professional_title="Graphic Designer & Brand Identity Specialist",
        bio="Creating memorable brand identities and visual assets",
        years_of_experience=9,
        hourly_rate=Decimal('90.00'),
        hourly_rate_currency='EUR',
        availability_status='available',
        availability_hours_per_week=30,
        skills=['Adobe Illustrator', 'Photoshop', 'InDesign', 'Branding', 'Logo Design'],
        city='Berlin',
        country='Germany',
        remote_only=False,
        willing_to_relocate=False,
        portfolio_url='https://designer18.de',
        behance_url='https://behance.net/designer18',
        dribbble_url='https://dribbble.com/designer18',
        completed_projects=135,
        completed_services=98,
        total_earnings=Decimal('410000.00'),
        average_rating=Decimal('4.8'),
        total_reviews=233,
    )
    p18.categories.add(design)
    profiles.append(p18)

    # 19. Backend API Developer - Verified, available, REST & GraphQL expert
    p19 = VerifiedFreelancerProfileFactory(
        professional_title="Backend API Developer (REST & GraphQL)",
        bio="Designing and building scalable API architectures",
        years_of_experience=8,
        hourly_rate=Decimal('105.00'),
        hourly_rate_currency='CAD',
        availability_status='available',
        availability_hours_per_week=30,
        skills=['Node.js', 'Express', 'GraphQL', 'MongoDB', 'Redis'],
        city='Halifax',
        country='Canada',
        remote_only=True,
        github_url='https://github.com/backend19',
        completed_projects=47,
        completed_services=21,
        total_earnings=Decimal('265000.00'),
        average_rating=Decimal('4.7'),
        total_reviews=68,
    )
    p19.categories.add(web_dev)
    profiles.append(p19)

    # 20. Product Manager (Technical) - Verified, available, unique role
    p20 = VerifiedFreelancerProfileFactory(
        professional_title="Technical Product Manager",
        bio="Bridging business and engineering. Former developer turned PM.",
        years_of_experience=10,
        hourly_rate=Decimal('135.00'),
        hourly_rate_currency='USD',
        availability_status='available',
        availability_hours_per_week=25,
        skills=['Product Strategy', 'Agile/Scrum', 'Roadmapping', 'User Stories', 'SQL'],
        city='New York',
        country='USA',
        remote_only=False,
        willing_to_relocate=False,
        linkedin_url='https://linkedin.com/in/pm20',
        completed_projects=38,
        completed_services=15,
        total_earnings=Decimal('310000.00'),
        average_rating=Decimal('4.9'),
        total_reviews=53,
    )
    profiles.append(p20)

    return profiles


class TestFreelancerProfileOnboardingWorkflow:
    """Test complete onboarding workflow for new freelancers."""

    def test_complete_onboarding_journey(self, user_factory):
        """
        Test a new user creating and completing their freelancer profile.

        Steps:
        1. User registers
        2. User creates freelancer profile
        3. User adds portfolio links
        4. User updates skills
        5. Profile becomes searchable (when verified)
        """
        from custom_account_u.models import CustomUser
        from tenant_profiles.models import FreelancerProfile

        # Step 1: User registers
        client = APIClient()
        user = user_factory()
        client.force_authenticate(user=user)

        # Step 2: Create freelancer profile
        url = reverse('tenant_profiles:freelancer-profile-me')
        data = {
            'professional_title': 'Junior Python Developer',
            'bio': 'Recent CS grad looking to build my portfolio',
            'years_of_experience': 1,
            'hourly_rate': '40.00',
            'hourly_rate_currency': 'CAD',
            'availability_hours_per_week': 40,
            'skills': ['Python', 'Django', 'Git'],
            'city': 'Toronto',
            'country': 'Canada',
            'remote_only': True,
        }

        response = client.post(url, data, format='json')
        assert response.status_code == 201

        profile = FreelancerProfile.objects.get(user=user)
        assert profile.professional_title == 'Junior Python Developer'

        # Step 3: Add portfolio links
        update_data = {
            'github_url': 'https://github.com/newdev',
            'linkedin_url': 'https://linkedin.com/in/newdev',
            'portfolio_url': 'https://newdev.dev',
        }

        response = client.patch(url, update_data, format='json')
        assert response.status_code == 200

        profile.refresh_from_db()
        assert profile.has_portfolio is True

        # Step 4: Update skills
        skills_data = {
            'skills': ['Python', 'Django', 'PostgreSQL', 'Docker', 'REST APIs'],
        }

        response = client.patch(url, skills_data, format='json')
        assert response.status_code == 200

        profile.refresh_from_db()
        assert len(profile.skills) == 5

        # Step 5: Profile not searchable until verified
        public_url = reverse('tenant_profiles:freelancer-profile-list')
        response = client.get(public_url)
        assert response.status_code == 200
        # Should not appear in public list (not verified)
        assert len([p for p in response.data['results'] if p['uuid'] == str(profile.uuid)]) == 0


class TestFreelancerProfileSearchAndDiscovery:
    """Test searching and discovering freelancers with demo data."""

    def test_search_by_skills_comprehensive(self, api_client, comprehensive_freelancer_demo_data):
        """Test searching across 20 demo profiles by different skills."""
        url = reverse('tenant_profiles:freelancer-profile-list')

        # Search for Python developers
        response = api_client.get(url, {'search': 'Python'})
        assert response.status_code == 200
        python_devs = len(response.data['results'])
        assert python_devs > 0

        # Search for React developers
        response = api_client.get(url, {'search': 'React'})
        assert response.status_code == 200
        react_devs = len(response.data['results'])
        assert react_devs > 0

        # Search for designers
        response = api_client.get(url, {'search': 'Design'})
        assert response.status_code == 200
        designers = len(response.data['results'])
        assert designers > 0

    def test_filter_by_hourly_rate_range(self, api_client, comprehensive_freelancer_demo_data):
        """Test filtering by different hourly rate ranges."""
        url = reverse('tenant_profiles:freelancer-profile-list')

        # Get all profiles
        response = api_client.get(url)
        all_profiles = response.data['results']

        # Budget-friendly (< $60/hr CAD equivalent)
        budget_profiles = [p for p in all_profiles if p['hourly_rate'] and float(p['hourly_rate']) < 60]
        assert len(budget_profiles) > 0

        # Mid-range ($60-120/hr)
        mid_profiles = [p for p in all_profiles if p['hourly_rate'] and 60 <= float(p['hourly_rate']) <= 120]
        assert len(mid_profiles) > 0

        # Premium (> $120/hr)
        premium_profiles = [p for p in all_profiles if p['hourly_rate'] and float(p['hourly_rate']) > 120]
        assert len(premium_profiles) > 0

    def test_filter_available_freelancers(self, api_client, comprehensive_freelancer_demo_data):
        """Test filtering only available freelancers."""
        url = reverse('tenant_profiles:freelancer-profile-available')
        response = api_client.get(url)

        assert response.status_code == 200
        # All results should have availability_status = 'available'
        for profile in response.data['results']:
            assert profile['availability_status'] == 'available'

    def test_order_by_experience_desc(self, api_client, comprehensive_freelancer_demo_data):
        """Test ordering by years of experience (most experienced first)."""
        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'ordering': '-years_of_experience'})

        assert response.status_code == 200
        results = response.data['results']
        if len(results) >= 2:
            # Verify descending order
            for i in range(len(results) - 1):
                # Note: results may have same experience, so use >= not >
                assert results[i].get('years_of_experience', 0) >= results[i+1].get('years_of_experience', 0)

    def test_filter_remote_only_developers(self, api_client, comprehensive_freelancer_demo_data):
        """Test filtering only remote-only freelancers."""
        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'remote_only': 'true'})

        assert response.status_code == 200
        # All results should have remote_only = True
        for profile in response.data['results']:
            assert profile['remote_only'] is True


class TestFreelancerStatsUpdateWorkflow:
    """Test updating freelancer stats after completing work."""

    def test_complete_project_updates_stats(self):
        """Test that completing a project updates freelancer stats."""
        from conftest import VerifiedFreelancerProfileFactory

        profile = VerifiedFreelancerProfileFactory(
            completed_projects=10,
            total_earnings=Decimal('50000.00'),
            average_rating=Decimal('4.5'),
            total_reviews=15
        )

        # Complete a new project
        profile.update_stats(
            completed_projects=1,
            earnings=5000.00,
            rating=5.0
        )

        profile.refresh_from_db()
        assert profile.completed_projects == 11
        assert profile.total_earnings == Decimal('55000.00')
        assert profile.total_reviews == 16
        # Average should increase slightly
        assert profile.average_rating > Decimal('4.5')

    def test_low_rating_decreases_average(self):
        """Test that a low rating decreases overall average."""
        from conftest import VerifiedFreelancerProfileFactory

        profile = VerifiedFreelancerProfileFactory(
            average_rating=Decimal('4.8'),
            total_reviews=10
        )

        # Receive a low rating
        profile.update_stats(rating=2.0)

        profile.refresh_from_db()
        # Average should decrease
        assert profile.average_rating < Decimal('4.8')
