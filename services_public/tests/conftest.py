"""
Pytest fixtures for services_public tests.
"""
import uuid
import pytest
from decimal import Decimal
from django.contrib.gis.geos import Point
from django.utils import timezone

pytestmark = pytest.mark.django_db


@pytest.fixture
def sample_tenant():
    """Create a sample tenant."""
    from tenants.models import Tenant
    return Tenant.objects.create(
        schema_name='test_tenant',
        name='Test Tenant',
        is_active=True
    )


@pytest.fixture
def sample_public_service(sample_tenant):
    """Create a sample PublicService."""
    from services_public.models import PublicService
    return PublicService.objects.create(
        service_uuid=uuid.uuid4(),
        tenant_id=sample_tenant.id,
        tenant_schema_name=sample_tenant.schema_name,
        name='Test Service',
        provider_uuid=uuid.uuid4(),
        provider_name='Test Provider',
        category_slug='design',
        is_active=True,
        booking_url='https://test.example.com/book',
        detail_url='/browse-services/test/'
    )
