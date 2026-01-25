#!/usr/bin/env python
"""
Detailed Tenant Testing Script

Tests the specific behavior of:
1. Freelancer Tenant functionality
2. 404 page behavior and middleware handling
3. Tenant switching and isolation
"""

import requests
from datetime import datetime
import json

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def test_with_follow_redirects(url, follow=False):
    """Test a URL and optionally follow redirects"""
    try:
        response = requests.get(url, verify=False, timeout=10, allow_redirects=follow)
        return {
            'success': True,
            'status': response.status_code,
            'url': response.url if follow else url,
            'final_url': response.url,
            'headers': dict(response.headers),
            'content_length': len(response.content),
            'sample': response.text[:500],
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
        }


def main():
    print("="*80)
    print("DETAILED ZUMODRA TENANT TESTING")
    print(f"Generated: {datetime.now().isoformat()}")
    print("="*80)

    # Test 1: Freelancer Tenant Homepage
    print("\n1. FREELANCER TENANT HOMEPAGE")
    print("-" * 80)
    url = "https://demo-freelancer.zumodra.rhematek-solutions.com/"
    result = test_with_follow_redirects(url)
    print(f"URL: {url}")
    print(f"Status: {result.get('status', 'ERROR')}")
    if result['success']:
        print(f"Content Length: {result['content_length']}")
        print(f"Sample Content:")
        print(result['sample'][:300])

    # Test 2: Nonexistent Tenant (without redirects)
    print("\n2. NONEXISTENT TENANT (no redirect follow)")
    print("-" * 80)
    url = "https://nonexistent-tenant.zumodra.rhematek-solutions.com/"
    result = test_with_follow_redirects(url, follow=False)
    print(f"URL: {url}")
    print(f"Status: {result.get('status', 'ERROR')}")
    if result['success']:
        print(f"Content Length: {result['content_length']}")
        print(f"Headers:")
        for k, v in result['headers'].items():
            if k.lower() in ['location', 'content-type', 'server']:
                print(f"  {k}: {v}")
        if result['status'] in [301, 302, 303, 307, 308]:
            print(f"Redirect Location: {result['headers'].get('location', 'N/A')}")

    # Test 3: Nonexistent Tenant (with redirect follow)
    print("\n3. NONEXISTENT TENANT (with redirect follow)")
    print("-" * 80)
    url = "https://nonexistent-tenant.zumodra.rhematek-solutions.com/"
    result = test_with_follow_redirects(url, follow=True)
    print(f"URL: {url}")
    print(f"Status: {result.get('status', 'ERROR')}")
    print(f"Final URL: {result.get('final_url', 'N/A')}")
    if result['success']:
        print(f"Content Length: {result['content_length']}")

    # Test 4: Freelancer Login Page
    print("\n4. FREELANCER TENANT LOGIN PAGE")
    print("-" * 80)
    url = "https://demo-freelancer.zumodra.rhematek-solutions.com/accounts/login/"
    result = test_with_follow_redirects(url)
    print(f"URL: {url}")
    print(f"Status: {result.get('status', 'ERROR')}")
    if result['success']:
        print(f"Has login form: {'form' in result['sample'].lower() or 'password' in result['sample'].lower()}")

    # Test 5: Freelancer Protected Page (should redirect to login)
    print("\n5. FREELANCER PROTECTED PAGE (dashboard - no redirect follow)")
    print("-" * 80)
    url = "https://demo-freelancer.zumodra.rhematek-solutions.com/app/dashboard/"
    result = test_with_follow_redirects(url, follow=False)
    print(f"URL: {url}")
    print(f"Status: {result.get('status', 'ERROR')}")
    if result['success'] and result['status'] in [301, 302]:
        print(f"Redirects to: {result['headers'].get('location', 'N/A')}")

    # Test 6: Company Tenant for comparison
    print("\n6. COMPANY TENANT HOMEPAGE")
    print("-" * 80)
    url = "https://demo-company.zumodra.rhematek-solutions.com/"
    result = test_with_follow_redirects(url)
    print(f"URL: {url}")
    print(f"Status: {result.get('status', 'ERROR')}")
    if result['success']:
        print(f"Content Length: {result['content_length']}")

    # Test 7: Check branding differences
    print("\n7. BRANDING COMPARISON")
    print("-" * 80)

    freelancer_resp = requests.get("https://demo-freelancer.zumodra.rhematek-solutions.com/", verify=False, timeout=10)
    company_resp = requests.get("https://demo-company.zumodra.rhematek-solutions.com/", verify=False, timeout=10)

    print(f"Freelancer Tenant:")
    print(f"  Zumodra mentions: {freelancer_resp.text.count('Zumodra')}")
    print(f"  FreelanHub mentions: {freelancer_resp.text.count('FreelanHub')}")
    print(f"  Has 'freelancer' text: {freelancer_resp.text.count('freelancer') > 0}")

    print(f"\nCompany Tenant:")
    print(f"  Zumodra mentions: {company_resp.text.count('Zumodra')}")
    print(f"  FreelanHub mentions: {company_resp.text.count('FreelanHub')}")
    print(f"  Has 'company' text: {company_resp.text.count('company') > 0}")

    print("\n" + "="*80)
    print("END OF DETAILED TESTING")
    print("="*80)


if __name__ == '__main__':
    main()
