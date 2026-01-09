"""
Tests for Marketing API.

This module tests the marketing API endpoints including:
- Visit events
- Aggregated stats
- Prospects/Leads
- Newsletter campaigns
- Newsletter subscribers
- Conversion events
- Marketing analytics
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from marketing.models import (
    VisitEvent, AggregatedStats, Prospect,
    NewsletterCampaign, NewsletterSubscriber, NewsletterTracking,
    ConversionEvent
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
def visit_event(db):
    """Create test visit event."""
    return VisitEvent.objects.create(
        marketing_id='visit_123',
        url='/home',
        referrer='https://google.com',
        utm_source='google',
        utm_medium='cpc',
        utm_campaign='spring_sale',
        country='US',
        device_type='desktop',
        ip_address='192.168.1.1',
        user_agent='Mozilla/5.0'
    )


@pytest.fixture
def aggregated_stats(db):
    """Create test aggregated stats."""
    return AggregatedStats.objects.create(
        date=timezone.now().date(),
        total_visits=1000,
        unique_visitors=750,
        page_views=2500,
        avg_session_duration=180
    )


@pytest.fixture
def prospect(db):
    """Create test prospect."""
    return Prospect.objects.create(
        email='prospect@example.com',
        first_name='John',
        last_name='Doe',
        company='Acme Corp',
        status='new',
        source='website'
    )


@pytest.fixture
def newsletter_campaign(db):
    """Create test newsletter campaign."""
    return NewsletterCampaign.objects.create(
        title='Spring Newsletter',
        subject='Great deals for spring!',
        content='<h1>Spring Sale</h1><p>Check out our deals!</p>',
        sent=False
    )


@pytest.fixture
def newsletter_subscriber(db):
    """Create test newsletter subscriber."""
    return NewsletterSubscriber.objects.create(
        email='subscriber@example.com',
        active=True
    )


@pytest.fixture
def conversion_event(db):
    """Create test conversion event."""
    return ConversionEvent.objects.create(
        event_name='purchase',
        marketing_id='user_123',
        value=Decimal('99.99'),
        metadata={'product_id': 'prod_123'}
    )


# =============================================================================
# VISIT EVENT TESTS
# =============================================================================

class TestVisitEventViewSet:
    """Tests for VisitEventViewSet."""

    @pytest.mark.django_db
    def test_list_visits_requires_admin(self, authenticated_client, visit_event):
        """Test listing visits requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:marketing:visit-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_visits_admin(self, admin_authenticated_client, visit_event):
        """Test admin can list visits."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:visit-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_by_source(self, admin_authenticated_client, visit_event):
        """Test visits by source."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:visit-by-source')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)

    @pytest.mark.django_db
    def test_by_country(self, admin_authenticated_client, visit_event):
        """Test visits by country."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:visit-by-country')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)

    @pytest.mark.django_db
    def test_by_device(self, admin_authenticated_client, visit_event):
        """Test visits by device."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:visit-by-device')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)

    @pytest.mark.django_db
    def test_filter_by_utm_source(self, admin_authenticated_client, visit_event):
        """Test filtering visits by UTM source."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:visit-list')
        response = client.get(url, {'utm_source': 'google'})

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# AGGREGATED STATS TESTS
# =============================================================================

class TestAggregatedStatsViewSet:
    """Tests for AggregatedStatsViewSet."""

    @pytest.mark.django_db
    def test_list_stats_requires_admin(self, authenticated_client, aggregated_stats):
        """Test listing stats requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:marketing:aggregated-stats-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_stats_admin(self, admin_authenticated_client, aggregated_stats):
        """Test admin can list stats."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:aggregated-stats-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# PROSPECT TESTS
# =============================================================================

class TestProspectViewSet:
    """Tests for ProspectViewSet."""

    @pytest.mark.django_db
    def test_list_prospects_requires_admin(self, authenticated_client, prospect):
        """Test listing prospects requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:marketing:prospect-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_prospects_admin(self, admin_authenticated_client, prospect):
        """Test admin can list prospects."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:prospect-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_prospect(self, admin_authenticated_client):
        """Test creating a prospect."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:prospect-list')
        response = client.post(url, {
            'email': 'new@example.com',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'company': 'Test Corp',
            'source': 'website'
        })

        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.django_db
    def test_mark_contacted(self, admin_authenticated_client, prospect):
        """Test marking prospect as contacted."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:prospect-mark-contacted', args=[prospect.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        prospect.refresh_from_db()
        assert prospect.status == 'contacted'

    @pytest.mark.django_db
    def test_mark_qualified(self, admin_authenticated_client, prospect):
        """Test marking prospect as qualified."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:prospect-mark-qualified', args=[prospect.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        prospect.refresh_from_db()
        assert prospect.status == 'qualified'

    @pytest.mark.django_db
    def test_mark_converted(self, admin_authenticated_client, prospect):
        """Test marking prospect as converted."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:prospect-mark-converted', args=[prospect.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        prospect.refresh_from_db()
        assert prospect.status == 'converted'

    @pytest.mark.django_db
    def test_disqualify_prospect(self, admin_authenticated_client, prospect):
        """Test disqualifying prospect."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:prospect-disqualify', args=[prospect.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        prospect.refresh_from_db()
        assert prospect.status == 'disqualified'

    @pytest.mark.django_db
    def test_prospects_by_status(self, admin_authenticated_client, prospect):
        """Test getting prospects by status."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:prospect-by-status')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'new' in response.data


# =============================================================================
# NEWSLETTER CAMPAIGN TESTS
# =============================================================================

class TestNewsletterCampaignViewSet:
    """Tests for NewsletterCampaignViewSet."""

    @pytest.mark.django_db
    def test_list_campaigns_requires_admin(self, authenticated_client, newsletter_campaign):
        """Test listing campaigns requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:marketing:newsletter-campaign-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_campaigns_admin(self, admin_authenticated_client, newsletter_campaign):
        """Test admin can list campaigns."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:newsletter-campaign-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_campaign(self, admin_authenticated_client):
        """Test creating a campaign."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:newsletter-campaign-list')
        response = client.post(url, {
            'title': 'New Campaign',
            'subject': 'Check this out!',
            'content': '<h1>Hello</h1>'
        })

        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.django_db
    def test_send_campaign(self, admin_authenticated_client, newsletter_campaign):
        """Test sending a campaign."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:newsletter-campaign-send', args=[newsletter_campaign.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        newsletter_campaign.refresh_from_db()
        assert newsletter_campaign.sent is True

    @pytest.mark.django_db
    def test_cannot_send_already_sent_campaign(self, admin_authenticated_client, newsletter_campaign):
        """Test cannot send already sent campaign."""
        client, admin = admin_authenticated_client
        newsletter_campaign.sent = True
        newsletter_campaign.sent_on = timezone.now()
        newsletter_campaign.save()

        url = reverse('api_v1:marketing:newsletter-campaign-send', args=[newsletter_campaign.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.django_db
    def test_campaign_stats(self, admin_authenticated_client, newsletter_campaign):
        """Test campaign stats."""
        client, admin = admin_authenticated_client
        newsletter_campaign.sent = True
        newsletter_campaign.save()

        url = reverse('api_v1:marketing:newsletter-campaign-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# NEWSLETTER SUBSCRIBER TESTS
# =============================================================================

class TestNewsletterSubscriberViewSet:
    """Tests for NewsletterSubscriberViewSet."""

    @pytest.mark.django_db
    def test_list_subscribers_requires_admin(self, authenticated_client, newsletter_subscriber):
        """Test listing subscribers requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:marketing:newsletter-subscriber-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_subscribers_admin(self, admin_authenticated_client, newsletter_subscriber):
        """Test admin can list subscribers."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:newsletter-subscriber-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_unsubscribe(self, admin_authenticated_client, newsletter_subscriber):
        """Test unsubscribing a subscriber."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:newsletter-subscriber-unsubscribe', args=[newsletter_subscriber.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        newsletter_subscriber.refresh_from_db()
        assert newsletter_subscriber.active is False

    @pytest.mark.django_db
    def test_resubscribe(self, admin_authenticated_client, newsletter_subscriber):
        """Test resubscribing a subscriber."""
        client, admin = admin_authenticated_client
        newsletter_subscriber.active = False
        newsletter_subscriber.save()

        url = reverse('api_v1:marketing:newsletter-subscriber-resubscribe', args=[newsletter_subscriber.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        newsletter_subscriber.refresh_from_db()
        assert newsletter_subscriber.active is True


# =============================================================================
# CONVERSION EVENT TESTS
# =============================================================================

class TestConversionEventViewSet:
    """Tests for ConversionEventViewSet."""

    @pytest.mark.django_db
    def test_list_conversions_requires_admin(self, authenticated_client, conversion_event):
        """Test listing conversions requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:marketing:conversion-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_conversions_admin(self, admin_authenticated_client, conversion_event):
        """Test admin can list conversions."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:conversion-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_conversions_by_event(self, admin_authenticated_client, conversion_event):
        """Test conversions by event."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:conversion-by-event')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)

    @pytest.mark.django_db
    def test_revenue(self, admin_authenticated_client, conversion_event):
        """Test revenue endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:conversion-revenue')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'total_revenue' in response.data


# =============================================================================
# MARKETING ANALYTICS TESTS
# =============================================================================

class TestMarketingAnalyticsView:
    """Tests for MarketingAnalyticsView."""

    @pytest.mark.django_db
    def test_analytics_requires_admin(self, authenticated_client):
        """Test analytics requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:marketing:analytics')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_analytics_admin(self, admin_authenticated_client, visit_event, prospect, conversion_event):
        """Test admin can access analytics."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:analytics')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'total_visits' in response.data
        assert 'total_prospects' in response.data
        assert 'conversion_rate' in response.data

    @pytest.mark.django_db
    def test_analytics_with_days_param(self, admin_authenticated_client, visit_event):
        """Test analytics with custom days parameter."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:marketing:analytics')
        response = client.get(url, {'days': 7})

        assert response.status_code == status.HTTP_200_OK
