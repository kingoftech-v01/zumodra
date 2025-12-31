#!/usr/bin/env python3
"""
URL Health Check Script for Zumodra

Crawls and validates all internal URLs on a deployed Zumodra instance.
Detects 404/500 errors and generates a comprehensive report.

Usage:
    python scripts/url_health_check.py https://zumodra.example.com
    python scripts/url_health_check.py https://zumodra.example.com --output report.json
    python scripts/url_health_check.py https://zumodra.example.com --max-urls 100 --concurrency 5

Requirements:
    pip install requests beautifulsoup4 aiohttp
"""

import argparse
import asyncio
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Set, List, Dict
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    from bs4 import BeautifulSoup
    HAS_ASYNC = True
except ImportError:
    HAS_ASYNC = False
    import requests
    from bs4 import BeautifulSoup


@dataclass
class URLResult:
    """Result of checking a single URL."""
    url: str
    status_code: int
    response_time_ms: float
    final_url: Optional[str] = None
    error: Optional[str] = None
    content_type: Optional[str] = None

    @property
    def status(self) -> str:
        if self.error:
            return 'ERROR'
        if 200 <= self.status_code < 300:
            return 'OK'
        if 300 <= self.status_code < 400:
            return 'REDIRECT'
        if 400 <= self.status_code < 500:
            return '4XX'
        if 500 <= self.status_code < 600:
            return '5XX'
        return 'UNKNOWN'


class URLHealthChecker:
    """Crawl and check URLs on a target domain."""

    def __init__(
        self,
        base_url: str,
        max_urls: int = 500,
        concurrency: int = 10,
        timeout: int = 30,
        follow_redirects: bool = True,
        verbose: bool = False
    ):
        self.base_url = base_url.rstrip('/')
        self.base_domain = urlparse(base_url).netloc
        self.base_scheme = urlparse(base_url).scheme
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verbose = verbose

        self.discovered_urls: Set[str] = set()
        self.checked_urls: Set[str] = set()
        self.results: List[URLResult] = []
        self.to_check: asyncio.Queue = asyncio.Queue() if HAS_ASYNC else []

        # URL patterns to skip
        self.skip_patterns = [
            r'/static/',
            r'/media/',
            r'\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip)$',
            r'/admin/jsi18n/',
            r'/__debug__/',
            r'/api/v\d+/schema',
            r'/sitemap\.xml',
            r'/robots\.txt',
        ]

        # Common entry points to start crawling
        self.seed_urls = [
            '/',
            '/accounts/login/',
            '/accounts/register/',
            '/careers/',
            '/api/v1/',
            '/dashboard/',
            '/health/',
        ]

    def should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped based on patterns."""
        path = urlparse(url).path
        for pattern in self.skip_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False

    def normalize_url(self, url: str) -> Optional[str]:
        """Normalize and validate URL for the target domain."""
        if not url:
            return None

        # Handle relative URLs
        if url.startswith('/'):
            url = urljoin(self.base_url, url)
        elif not url.startswith(('http://', 'https://')):
            url = urljoin(self.base_url, '/' + url)

        parsed = urlparse(url)

        # Only accept URLs from our target domain
        if parsed.netloc != self.base_domain:
            return None

        # Skip fragments and query strings for uniqueness
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Remove trailing slashes for consistency (except root)
        if normalized != self.base_url and normalized.endswith('/'):
            normalized = normalized.rstrip('/')

        return normalized

    def extract_links(self, html: str, current_url: str) -> Set[str]:
        """Extract internal links from HTML content."""
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Find all anchor tags
            for anchor in soup.find_all('a', href=True):
                href = anchor['href']
                if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                normalized = self.normalize_url(href)
                if normalized and not self.should_skip_url(normalized):
                    links.add(normalized)

            # Find form actions
            for form in soup.find_all('form', action=True):
                action = form['action']
                if action and not action.startswith('#'):
                    normalized = self.normalize_url(action)
                    if normalized and not self.should_skip_url(normalized):
                        links.add(normalized)

        except Exception as e:
            if self.verbose:
                print(f"  Error parsing HTML from {current_url}: {e}")

        return links

    async def check_url_async(self, session: 'aiohttp.ClientSession', url: str) -> URLResult:
        """Check a single URL asynchronously."""
        start_time = time.time()
        try:
            async with session.get(
                url,
                allow_redirects=self.follow_redirects,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False  # Skip SSL verification for testing
            ) as response:
                elapsed = (time.time() - start_time) * 1000
                final_url = str(response.url) if response.url != url else None
                content_type = response.headers.get('content-type', '')

                # Get HTML content for link extraction
                html = None
                if 'text/html' in content_type and response.status == 200:
                    try:
                        html = await response.text()
                    except:
                        pass

                result = URLResult(
                    url=url,
                    status_code=response.status,
                    response_time_ms=elapsed,
                    final_url=final_url,
                    content_type=content_type.split(';')[0].strip()
                )

                # Extract links from HTML pages
                if html:
                    new_links = self.extract_links(html, url)
                    for link in new_links:
                        if link not in self.discovered_urls and len(self.discovered_urls) < self.max_urls:
                            self.discovered_urls.add(link)
                            await self.to_check.put(link)

                return result

        except asyncio.TimeoutError:
            elapsed = (time.time() - start_time) * 1000
            return URLResult(
                url=url,
                status_code=0,
                response_time_ms=elapsed,
                error='Timeout'
            )
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return URLResult(
                url=url,
                status_code=0,
                response_time_ms=elapsed,
                error=str(e)
            )

    def check_url_sync(self, url: str) -> URLResult:
        """Check a single URL synchronously (fallback without aiohttp)."""
        start_time = time.time()
        try:
            response = requests.get(
                url,
                allow_redirects=self.follow_redirects,
                timeout=self.timeout,
                verify=False
            )
            elapsed = (time.time() - start_time) * 1000
            final_url = response.url if response.url != url else None
            content_type = response.headers.get('content-type', '')

            result = URLResult(
                url=url,
                status_code=response.status_code,
                response_time_ms=elapsed,
                final_url=str(final_url) if final_url else None,
                content_type=content_type.split(';')[0].strip()
            )

            # Extract links from HTML pages
            if 'text/html' in content_type and response.status_code == 200:
                new_links = self.extract_links(response.text, url)
                for link in new_links:
                    if link not in self.discovered_urls and len(self.discovered_urls) < self.max_urls:
                        self.discovered_urls.add(link)
                        self.to_check.append(link)

            return result

        except requests.Timeout:
            elapsed = (time.time() - start_time) * 1000
            return URLResult(
                url=url,
                status_code=0,
                response_time_ms=elapsed,
                error='Timeout'
            )
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return URLResult(
                url=url,
                status_code=0,
                response_time_ms=elapsed,
                error=str(e)
            )

    async def worker(self, session: 'aiohttp.ClientSession', worker_id: int):
        """Worker coroutine for processing URLs."""
        while True:
            try:
                url = await asyncio.wait_for(self.to_check.get(), timeout=5.0)
            except asyncio.TimeoutError:
                break

            if url in self.checked_urls:
                self.to_check.task_done()
                continue

            self.checked_urls.add(url)
            result = await self.check_url_async(session, url)
            self.results.append(result)

            if self.verbose:
                status_symbol = '✓' if result.status == 'OK' else '✗' if result.status in ('4XX', '5XX', 'ERROR') else '→'
                print(f"  [{worker_id}] {status_symbol} {result.status_code} {url} ({result.response_time_ms:.0f}ms)")

            self.to_check.task_done()

    async def run_async(self):
        """Run the health check asynchronously."""
        print(f"\n🔍 Starting URL health check for: {self.base_url}")
        print(f"   Max URLs: {self.max_urls}, Concurrency: {self.concurrency}\n")

        # Add seed URLs
        for seed in self.seed_urls:
            url = self.normalize_url(seed)
            if url:
                self.discovered_urls.add(url)
                await self.to_check.put(url)

        # Create HTTP session
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create workers
            workers = [
                asyncio.create_task(self.worker(session, i))
                for i in range(self.concurrency)
            ]

            # Wait for all URLs to be processed
            await self.to_check.join()

            # Cancel workers
            for worker in workers:
                worker.cancel()

    def run_sync(self):
        """Run the health check synchronously (fallback)."""
        print(f"\n🔍 Starting URL health check for: {self.base_url}")
        print(f"   Max URLs: {self.max_urls} (sync mode)\n")

        # Add seed URLs
        for seed in self.seed_urls:
            url = self.normalize_url(seed)
            if url and url not in self.discovered_urls:
                self.discovered_urls.add(url)
                self.to_check.append(url)

        # Process URLs one by one
        while self.to_check and len(self.checked_urls) < self.max_urls:
            url = self.to_check.pop(0)

            if url in self.checked_urls:
                continue

            self.checked_urls.add(url)
            result = self.check_url_sync(url)
            self.results.append(result)

            if self.verbose:
                status_symbol = '✓' if result.status == 'OK' else '✗' if result.status in ('4XX', '5XX', 'ERROR') else '→'
                print(f"  {status_symbol} {result.status_code} {url} ({result.response_time_ms:.0f}ms)")

    def run(self):
        """Run the health check."""
        if HAS_ASYNC:
            asyncio.run(self.run_async())
        else:
            self.run_sync()

    def generate_report(self) -> Dict:
        """Generate a comprehensive report."""
        # Count by status
        status_counts = defaultdict(int)
        for result in self.results:
            status_counts[result.status] += 1

        # Group problematic URLs by Django app (guessed from path)
        problematic = []
        for result in self.results:
            if result.status in ('4XX', '5XX', 'ERROR'):
                path = urlparse(result.url).path
                app_guess = path.split('/')[1] if len(path.split('/')) > 1 else 'root'
                problematic.append({
                    'url': result.url,
                    'status_code': result.status_code,
                    'error': result.error,
                    'app_guess': app_guess
                })

        # Calculate statistics
        response_times = [r.response_time_ms for r in self.results if r.response_time_ms > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        report = {
            'generated_at': datetime.now().isoformat(),
            'base_url': self.base_url,
            'summary': {
                'total_urls_discovered': len(self.discovered_urls),
                'total_urls_checked': len(self.results),
                'status_2xx': status_counts.get('OK', 0),
                'status_3xx': status_counts.get('REDIRECT', 0),
                'status_4xx': status_counts.get('4XX', 0),
                'status_5xx': status_counts.get('5XX', 0),
                'errors': status_counts.get('ERROR', 0),
                'avg_response_time_ms': round(avg_response_time, 2),
                'all_healthy': status_counts.get('4XX', 0) == 0 and status_counts.get('5XX', 0) == 0 and status_counts.get('ERROR', 0) == 0
            },
            'problematic_urls': problematic,
            'all_results': [asdict(r) for r in self.results]
        }

        return report

    def print_summary(self):
        """Print a human-readable summary."""
        report = self.generate_report()
        summary = report['summary']

        print("\n" + "=" * 60)
        print("📊 URL HEALTH CHECK SUMMARY")
        print("=" * 60)
        print(f"Base URL: {self.base_url}")
        print(f"Generated: {report['generated_at']}")
        print("-" * 60)
        print(f"Total URLs Discovered: {summary['total_urls_discovered']}")
        print(f"Total URLs Checked:    {summary['total_urls_checked']}")
        print(f"Average Response Time: {summary['avg_response_time_ms']:.2f}ms")
        print("-" * 60)
        print("Status Breakdown:")
        print(f"  ✅ 2xx (OK):       {summary['status_2xx']}")
        print(f"  ➡️  3xx (Redirect): {summary['status_3xx']}")
        print(f"  ⚠️  4xx (Client):   {summary['status_4xx']}")
        print(f"  ❌ 5xx (Server):   {summary['status_5xx']}")
        print(f"  💥 Errors:         {summary['errors']}")
        print("-" * 60)

        if summary['all_healthy']:
            print("🎉 ALL URLS HEALTHY - No 4xx/5xx errors detected!")
        else:
            print("⚠️  ISSUES DETECTED:")
            for prob in report['problematic_urls'][:20]:  # Show first 20
                print(f"  - [{prob['status_code']}] {prob['url']}")
                if prob.get('error'):
                    print(f"    Error: {prob['error']}")
                print(f"    Likely app: {prob['app_guess']}")

            if len(report['problematic_urls']) > 20:
                print(f"  ... and {len(report['problematic_urls']) - 20} more issues")

        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Zumodra URL Health Check - Crawl and validate all internal URLs'
    )
    parser.add_argument('url', help='Base URL to check (e.g., https://zumodra.example.com)')
    parser.add_argument('--max-urls', type=int, default=500, help='Maximum URLs to check (default: 500)')
    parser.add_argument('--concurrency', type=int, default=10, help='Number of concurrent requests (default: 10)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--output', '-o', help='Output JSON report to file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--no-follow-redirects', action='store_true', help="Don't follow redirects")

    args = parser.parse_args()

    checker = URLHealthChecker(
        base_url=args.url,
        max_urls=args.max_urls,
        concurrency=args.concurrency,
        timeout=args.timeout,
        follow_redirects=not args.no_follow_redirects,
        verbose=args.verbose
    )

    checker.run()
    checker.print_summary()

    if args.output:
        report = checker.generate_report()
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📝 Full report saved to: {args.output}")

    # Exit with non-zero if there are issues
    summary = checker.generate_report()['summary']
    if not summary['all_healthy']:
        sys.exit(1)


if __name__ == '__main__':
    main()
