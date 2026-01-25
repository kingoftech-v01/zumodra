"""
Simple HR Time-Off URL Testing
Tests accessibility of all time-off URLs
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import requests
from urllib.parse import urljoin
import json
from datetime import datetime

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"

# Test URLs based on code analysis
URLS_TO_TEST = [
    # From urls_frontend.py - hr namespace
    "/app/hr/time-off/calendar/",      # TimeOffCalendarView
    "/app/hr/time-off/request/",       # TimeOffRequestView
    "/app/hr/time-off/my/",            # MyTimeOffView
    "/app/hr/employees/",              # Employee directory
    "/app/hr/org-chart/",              # Org chart
    "/app/hr/onboarding/",             # Onboarding
]

results = {
    "timestamp": datetime.now().isoformat(),
    "base_url": BASE_URL,
    "tests": []
}

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings()

print("\n" + "="*60)
print("HR TIME-OFF MODULE - URL ACCESSIBILITY TEST")
print("="*60)
print(f"Testing site: {BASE_URL}")
print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*60 + "\n")

# Try to access each URL
for url_path in URLS_TO_TEST:
    full_url = urljoin(BASE_URL, url_path)
    print(f"Testing: {url_path}")

    try:
        response = requests.get(full_url, timeout=10, verify=False, allow_redirects=True)
        status_code = response.status_code

        result = {
            "url": full_url,
            "path": url_path,
            "status_code": status_code,
            "redirected": response.url != full_url,
            "final_url": response.url,
            "response_time": response.elapsed.total_seconds()
        }

        # Analyze response
        if status_code == 200:
            print(f"  ✅ 200 OK ({response.elapsed.total_seconds():.2f}s)")
            result["status"] = "success"
        elif status_code == 302 or status_code == 301:
            print(f"  🔀 {status_code} Redirect to: {response.url}")
            if "login" in response.url.lower():
                result["status"] = "redirect_to_login"
                print(f"     → Requires authentication")
            else:
                result["status"] = "redirect"
        elif status_code == 403:
            print(f"  🚫 403 Forbidden - Permission required")
            result["status"] = "forbidden"
        elif status_code == 404:
            print(f"  ❌ 404 Not Found - URL doesn't exist")
            result["status"] = "not_found"
        elif status_code == 500:
            print(f"  ❌ 500 Server Error")
            result["status"] = "server_error"
        else:
            print(f"  ⚠️  {status_code}")
            result["status"] = "other"

        results["tests"].append(result)

    except requests.exceptions.Timeout:
        print(f"  ⏱️  Timeout - Server not responding")
        results["tests"].append({
            "url": full_url,
            "path": url_path,
            "status": "timeout"
        })
    except requests.exceptions.ConnectionError as e:
        print(f"  ❌ Connection Error: {str(e)}")
        results["tests"].append({
            "url": full_url,
            "path": url_path,
            "status": "connection_error",
            "error": str(e)
        })
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
        results["tests"].append({
            "url": full_url,
            "path": url_path,
            "status": "error",
            "error": str(e)
        })

    print()

# Summary
print("="*60)
print("SUMMARY")
print("="*60)

success = sum(1 for t in results["tests"] if t.get("status") == "success")
redirects = sum(1 for t in results["tests"] if "redirect" in t.get("status", ""))
errors = sum(1 for t in results["tests"] if t.get("status") in ["not_found", "server_error", "error", "timeout", "connection_error"])
forbidden = sum(1 for t in results["tests"] if t.get("status") == "forbidden")

print(f"✅ Success: {success}")
print(f"🔀 Redirects: {redirects}")
print(f"🚫 Forbidden: {forbidden}")
print(f"❌ Errors: {errors}")
print(f"📊 Total: {len(results['tests'])}")

# Save results
output_file = "c:/Users/techn/OneDrive/Documents/zumodra/test_results/hr_timeoff/url_test_results.json"
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n📄 Results saved to: {output_file}")

# Check if site is accessible at all
if all(t.get("status") in ["timeout", "connection_error"] for t in results["tests"]):
    print("\n⚠️  WARNING: Site appears to be inaccessible or down")
    print("   Please verify the URL and try again")
elif redirects > 0:
    print("\n💡 Most URLs redirect to login - authentication is required for testing")
    print("   This is expected behavior for protected HR routes")
