#!/usr/bin/env python3
"""Services/Marketplace Module Tester"""
import requests, json, sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
SCREENSHOT_DIR = Path("test_results/services")
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

class Tester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.results = []
        
    def log(self, msg):
        print(f"[{datetime.now():%H:%M:%S}] {msg}")
        
    def save(self, resp, name):
        path = SCREENSHOT_DIR / name
        path.write_text(resp.text, encoding='utf-8')
        self.log(f"Saved: {path}")
        
    def get_csrf(self, text):
        import re
        m = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', text)
        if m:
            return m.group(1)
        m = re.search(r'value=["\']([^"\']+)["\'] name=["\']csrfmiddlewaretoken["\']', text)
        if m:
            return m.group(1)
        m = re.search(r'csrfmiddlewaretoken["\']:\s*["\']([^"\']+)["\']', text)
        return m.group(1) if m else None
        
    def login(self):
        self.log("Logging in...")
        url = urljoin(BASE_URL, "/accounts/login/")
        r = self.session.get(url, timeout=30)
        csrf = self.get_csrf(r.text)
        if not csrf:
            self.log("ERROR: No CSRF token")
            return False
        self.save(r, "01_login.html")
        
        r = self.session.post(url, data={
            'login': 'demo@zumodra.com',
            'password': 'DemoPass123!',
            'csrfmiddlewaretoken': csrf
        }, timeout=30, allow_redirects=True)
        self.save(r, "02_post_login.html")
        
        if "Sign Out" in r.text or "demo@zumodra.com" in r.text:
            self.log("Login OK")
            return True
        self.log("Login FAILED")
        return False
        
    def test_url(self, path, name, extract_uuids=False):
        url = urljoin(BASE_URL, path)
        self.log(f"Testing: {url}")
        try:
            r = self.session.get(url, timeout=30, allow_redirects=False)
            self.log(f"  Status: {r.status_code}")
            self.save(r, f"{name}.html")
            
            result = {'url': url, 'status': r.status_code, 'page': name}
            
            if extract_uuids and r.status_code == 200:
                import re
                uuids = re.findall(r'/services/[^/]+/([a-f0-9-]{36})/', r.text)
                ids = re.findall(r'/services/contract/(\d+)/', r.text)
                self.log(f"  Found {len(uuids)} UUIDs, {len(ids)} IDs")
                result['uuids'] = list(set(uuids))
                result['ids'] = list(set(ids))
                
            self.results.append(result)
            return result
        except Exception as e:
            self.log(f"  ERROR: {e}")
            self.results.append({'url': url, 'status': 'ERROR', 'page': name, 'error': str(e)})
            return None
            
    def run(self):
        self.log("="*60)
        self.log("SERVICES/MARKETPLACE MODULE TEST")
        self.log("="*60)
        
        if not self.login():
            return False
            
        # Test all service URLs
        self.test_url("/services/", "03_services_list", extract_uuids=True)
        
        # Get first UUID if any
        uuids = []
        if self.results and 'uuids' in self.results[-1]:
            uuids = self.results[-1].get('uuids', [])
            
        if uuids:
            self.test_url(f"/services/service/{uuids[0]}/", "04_service_detail")
            
        self.test_url("/services/providers/", "05_providers", extract_uuids=True)
        self.test_url("/services/provider/dashboard/", "06_provider_dash")
        self.test_url("/services/provider/create/", "07_create_provider")
        self.test_url("/services/service/create/", "08_create_service")
        self.test_url("/services/request/my-requests/", "09_my_requests", extract_uuids=True)
        self.test_url("/services/request/create/", "10_create_request")
        self.test_url("/services/contracts/", "11_contracts", extract_uuids=True)
        
        # Get first contract ID if any
        for r in self.results:
            if 'ids' in r and r['ids']:
                self.test_url(f"/services/contract/{r['ids'][0]}/", "12_contract_detail")
                break
                
        self.test_url("/services/nearby/", "13_nearby")
        
        # Report
        self.log("\\n" + "="*60)
        self.log("RESULTS")
        self.log("="*60)
        
        passed = sum(1 for r in self.results if r['status'] == 200)
        total = len(self.results)
        self.log(f"Passed: {passed}/{total}")
        
        for r in self.results:
            status = "PASS" if r['status'] == 200 else "REDIRECT" if r['status'] in [301,302] else "FAIL"
            self.log(f"[{status}] {r['page']}: {r['status']}")
            
        # Save JSON
        (SCREENSHOT_DIR / "report.json").write_text(json.dumps({
            'timestamp': datetime.now().isoformat(),
            'passed': passed,
            'total': total,
            'results': self.results
        }, indent=2))
        
        self.log(f"\\nScreenshots: {SCREENSHOT_DIR.absolute()}")
        return True

if __name__ == "__main__":
    t = Tester()
    sys.exit(0 if t.run() else 1)
