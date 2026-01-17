"""
Check if the demo site is accessible and what URLs work
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import requests
from datetime import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

print("\n" + "="*60)
print("DEMO SITE ACCESSIBILITY CHECK")
print("="*60)
print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*60 + "\n")

# URLs to check
urls_to_check = [
    "https://demo-company.zumodra.rhematek-solutions.com",
    "https://demo-company.zumodra.rhematek-solutions.com/",
    "https://demo-company.zumodra.rhematek-solutions.com/accounts/login/",
    "https://demo-company.zumodra.rhematek-solutions.com/app/",
    "https://zumodra.rhematek-solutions.com",
    "https://www.zumodra.rhematek-solutions.com",
]

for url in urls_to_check:
    print(f"Checking: {url}")
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        print(f"  Status: {response.status_code}")
        print(f"  Final URL: {response.url}")
        print(f"  Response time: {response.elapsed.total_seconds():.2f}s")

        # Check content
        content_length = len(response.content)
        print(f"  Content length: {content_length} bytes")

        if response.status_code == 200:
            # Check for specific markers in the content
            content_lower = response.text.lower()
            if "zumodra" in content_lower:
                print(f"  ✅ Site accessible - Contains 'zumodra'")
            if "login" in content_lower:
                print(f"  🔐 Login page detected")
            if "error" in content_lower or "502" in content_lower or "503" in content_lower:
                print(f"  ⚠️  Error message in content")

    except requests.exceptions.Timeout:
        print(f"  ⏱️  Timeout - Server not responding")
    except requests.exceptions.ConnectionError as e:
        print(f"  ❌ Connection Error")
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")

    print()

print("\n" + "="*60)
print("Site Status Summary")
print("="*60)
print("\nIf all URLs return 502, the site may be down or in maintenance mode.")
print("If login page is accessible, authentication is required for testing.")
