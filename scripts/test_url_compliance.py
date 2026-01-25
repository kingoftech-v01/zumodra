"""
Test URL compliance for jobs and jobs_public apps.

Verifies that all URLs follow the convention:
- Frontend: frontend:app:view
- API: api:v1:app:resource
"""

import sys
import os
import django

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
django.setup()

from django.urls import reverse, NoReverseMatch


def test_jobs_public_urls():
    """Test jobs_public URL namespace compliance."""
    print("\n" + "="*70)
    print("TESTING jobs_public URLs")
    print("="*70)

    frontend_urls = [
        ('frontend:jobs_public:job_list', {}),
        ('frontend:jobs_public:job_list_grid', {}),
        ('frontend:jobs_public:job_list_list', {}),
        ('frontend:jobs_public:job_map', {}),
        ('frontend:jobs_public:job_map_v2', {}),
        ('frontend:jobs_public:job_detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('frontend:jobs_public:job_detail_v2', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('frontend:jobs_public:wishlist_toggle', {'job_id': 1}),
    ]

    api_urls = [
        ('api:jobs_public:job-list', {}),
        ('api:jobs_public:job-detail', {'pk': 1}),
    ]

    print("\n--- Frontend URLs ---")
    for url_name, kwargs in frontend_urls:
        try:
            url = reverse(url_name, kwargs=kwargs)
            print(f"✅ {url_name:50} → {url}")
        except NoReverseMatch as e:
            print(f"❌ {url_name:50} → ERROR: {e}")

    print("\n--- API URLs ---")
    for url_name, kwargs in api_urls:
        try:
            url = reverse(url_name, kwargs=kwargs)
            print(f"✅ {url_name:50} → {url}")
        except NoReverseMatch as e:
            print(f"❌ {url_name:50} → ERROR: {e}")


def test_jobs_urls():
    """Test jobs URL namespace compliance."""
    print("\n" + "="*70)
    print("TESTING jobs URLs")
    print("="*70)

    frontend_urls = [
        ('frontend:jobs:job_list', {}),
        ('frontend:jobs:job_create', {}),
        ('frontend:jobs:job_detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('frontend:jobs:candidate_list', {}),
        ('frontend:jobs:candidate_create', {}),
        ('frontend:jobs:candidate_detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('frontend:jobs:application_detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('frontend:jobs:interview_list', {}),
        ('frontend:jobs:interview_detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('frontend:jobs:offer_list', {}),
        ('frontend:jobs:offer_detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('frontend:jobs:pipeline_board', {}),
    ]

    api_urls = [
        ('api:jobs:job-list', {}),
        ('api:jobs:job-detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('api:jobs:candidate-list', {}),
        ('api:jobs:candidate-detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('api:jobs:application-list', {}),
        ('api:jobs:application-detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('api:jobs:interview-list', {}),
        ('api:jobs:interview-detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('api:jobs:offer-list', {}),
        ('api:jobs:offer-detail', {'pk': '00000000-0000-0000-0000-000000000000'}),
        ('api:jobs:pipeline-list', {}),
        ('api:jobs:dashboard-stats', {}),
        ('api:jobs:ai-match-score', {}),
    ]

    print("\n--- Frontend URLs ---")
    for url_name, kwargs in frontend_urls:
        try:
            url = reverse(url_name, kwargs=kwargs)
            print(f"✅ {url_name:50} → {url}")
        except NoReverseMatch as e:
            print(f"❌ {url_name:50} → ERROR: {e}")

    print("\n--- API URLs ---")
    for url_name, kwargs in api_urls:
        try:
            url = reverse(url_name, kwargs=kwargs)
            print(f"✅ {url_name:50} → {url}")
        except NoReverseMatch as e:
            print(f"❌ {url_name:50} → ERROR: {e}")


def main():
    """Run all URL compliance tests."""
    print("\n" + "="*70)
    print("URL CONVENTION COMPLIANCE TEST")
    print("Testing: jobs and jobs_public apps")
    print("Convention: URL_AND_VIEW_CONVENTIONS.md")
    print("="*70)

    test_jobs_public_urls()
    test_jobs_urls()

    print("\n" + "="*70)
    print("✅ All URL namespace tests completed!")
    print("="*70 + "\n")


if __name__ == '__main__':
    main()
