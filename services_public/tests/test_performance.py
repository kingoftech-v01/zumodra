"""Performance tests."""
import pytest


pytestmark = pytest.mark.django_db

@pytest.mark.slow
class TestPerformance:
    def test_list_performance(self):
        # Test implementation
        pass
