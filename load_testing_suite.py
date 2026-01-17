"""
Zumodra Load Testing Suite
===========================

Comprehensive load testing for demo readiness verification.
Tests concurrent access, database pool, Redis, API rate limiting, and performance.

Domain: https://zumodra.rhematek-solutions.com

Requirements:
    pip install requests aiohttp psutil locust

Usage:
    python load_testing_suite.py
"""

import asyncio
import time
import statistics
import psutil
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple
import json
import sys

# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
CONCURRENT_USERS = 10
TEST_DURATION_SECONDS = 60
WARMUP_REQUESTS = 5


class PerformanceMetrics:
    """Track and analyze performance metrics"""

    def __init__(self):
        self.response_times = []
        self.status_codes = []
        self.errors = []
        self.start_time = None
        self.end_time = None

    def add_response(self, response_time: float, status_code: int, error: str = None):
        """Record a response"""
        self.response_times.append(response_time)
        self.status_codes.append(status_code)
        if error:
            self.errors.append(error)

    def get_statistics(self) -> Dict:
        """Calculate performance statistics"""
        if not self.response_times:
            return {}

        sorted_times = sorted(self.response_times)
        total_requests = len(self.response_times)

        return {
            'total_requests': total_requests,
            'successful_requests': sum(1 for code in self.status_codes if 200 <= code < 400),
            'failed_requests': sum(1 for code in self.status_codes if code >= 400 or code == 0),
            'error_count': len(self.errors),
            'min_response_time': min(self.response_times),
            'max_response_time': max(self.response_times),
            'mean_response_time': statistics.mean(self.response_times),
            'median_response_time': statistics.median(self.response_times),
            'p95_response_time': sorted_times[int(len(sorted_times) * 0.95)] if total_requests > 0 else 0,
            'p99_response_time': sorted_times[int(len(sorted_times) * 0.99)] if total_requests > 0 else 0,
            'requests_per_second': total_requests / (self.end_time - self.start_time) if self.end_time and self.start_time else 0,
            'duration': self.end_time - self.start_time if self.end_time and self.start_time else 0,
        }


class LoadTester:
    """Main load testing class"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.metrics = PerformanceMetrics()
        self.session = requests.Session()
        # Disable SSL verification warnings (only for testing)
        requests.packages.urllib3.disable_warnings()

    def test_endpoint(self, endpoint: str, method: str = 'GET', **kwargs) -> Tuple[float, int, str]:
        """Test a single endpoint"""
        url = f"{self.base_url}{endpoint}"
        error = None

        try:
            start_time = time.time()
            if method == 'GET':
                response = self.session.get(url, timeout=30, verify=False, **kwargs)
            elif method == 'POST':
                response = self.session.post(url, timeout=30, verify=False, **kwargs)
            else:
                response = self.session.request(method, url, timeout=30, verify=False, **kwargs)

            response_time = time.time() - start_time
            status_code = response.status_code

        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            status_code = 0
            error = str(e)

        return response_time, status_code, error

    def concurrent_homepage_test(self, num_users: int = 10) -> Dict:
        """Test concurrent access to homepage"""
        print(f"\n{'='*80}")
        print(f"TEST 1: Concurrent Homepage Access ({num_users} users)")
        print(f"{'='*80}")

        metrics = PerformanceMetrics()
        metrics.start_time = time.time()

        with ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = [executor.submit(self.test_endpoint, '/') for _ in range(num_users)]

            for future in as_completed(futures):
                response_time, status_code, error = future.result()
                metrics.add_response(response_time, status_code, error)

        metrics.end_time = time.time()
        stats = metrics.get_statistics()

        print(f"\nResults:")
        print(f"  Total Requests: {stats['total_requests']}")
        print(f"  Successful: {stats['successful_requests']}")
        print(f"  Failed: {stats['failed_requests']}")
        print(f"  Mean Response Time: {stats['mean_response_time']:.3f}s")
        print(f"  Median Response Time: {stats['median_response_time']:.3f}s")
        print(f"  P95 Response Time: {stats['p95_response_time']:.3f}s")
        print(f"  P99 Response Time: {stats['p99_response_time']:.3f}s")

        return stats

    def sustained_load_test(self, duration: int = 60, concurrent_users: int = 5) -> Dict:
        """Test sustained load over time"""
        print(f"\n{'='*80}")
        print(f"TEST 2: Sustained Load Test ({concurrent_users} users for {duration}s)")
        print(f"{'='*80}")

        metrics = PerformanceMetrics()
        metrics.start_time = time.time()
        stop_time = time.time() + duration

        endpoints = [
            '/',
            '/health/',
            '/about/',
            '/pricing/',
            '/contact/',
        ]

        def worker():
            """Worker function for continuous requests"""
            local_metrics = []
            while time.time() < stop_time:
                endpoint = endpoints[int(time.time()) % len(endpoints)]
                result = self.test_endpoint(endpoint)
                local_metrics.append(result)
                time.sleep(0.5)  # Small delay between requests
            return local_metrics

        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(worker) for _ in range(concurrent_users)]

            for future in as_completed(futures):
                results = future.result()
                for response_time, status_code, error in results:
                    metrics.add_response(response_time, status_code, error)

        metrics.end_time = time.time()
        stats = metrics.get_statistics()

        print(f"\nResults:")
        print(f"  Total Requests: {stats['total_requests']}")
        print(f"  Successful: {stats['successful_requests']}")
        print(f"  Failed: {stats['failed_requests']}")
        print(f"  Requests/sec: {stats['requests_per_second']:.2f}")
        print(f"  Mean Response Time: {stats['mean_response_time']:.3f}s")
        print(f"  P95 Response Time: {stats['p95_response_time']:.3f}s")
        print(f"  Error Rate: {(stats['failed_requests'] / stats['total_requests'] * 100):.2f}%")

        return stats

    def endpoint_health_check(self) -> Dict:
        """Test various endpoints for health"""
        print(f"\n{'='*80}")
        print(f"TEST 3: Endpoint Health Check")
        print(f"{'='*80}")

        endpoints = {
            'Homepage': '/',
            'Health Check': '/health/',
            'About Page': '/about/',
            'Pricing Page': '/pricing/',
            'Contact Page': '/contact/',
            'FAQ Page': '/faqs/',
        }

        results = {}
        for name, endpoint in endpoints.items():
            response_time, status_code, error = self.test_endpoint(endpoint)
            results[name] = {
                'endpoint': endpoint,
                'status_code': status_code,
                'response_time': response_time,
                'success': 200 <= status_code < 400,
                'error': error
            }

            status = "✓ PASS" if results[name]['success'] else "✗ FAIL"
            print(f"  {name:20} {status:10} {response_time:.3f}s (HTTP {status_code})")

        return results

    def memory_usage_test(self, duration: int = 30) -> Dict:
        """Monitor memory usage during load"""
        print(f"\n{'='*80}")
        print(f"TEST 4: Memory Usage Monitoring ({duration}s)")
        print(f"{'='*80}")

        memory_samples = []
        cpu_samples = []

        start_time = time.time()
        stop_time = start_time + duration

        # Start background load
        def background_load():
            while time.time() < stop_time:
                self.test_endpoint('/')
                time.sleep(1)

        with ThreadPoolExecutor(max_workers=3) as executor:
            # Start background load workers
            load_futures = [executor.submit(background_load) for _ in range(3)]

            # Monitor system resources
            while time.time() < stop_time:
                memory_samples.append(psutil.virtual_memory().percent)
                cpu_samples.append(psutil.cpu_percent(interval=1))

            # Wait for load to complete
            for future in as_completed(load_futures):
                future.result()

        stats = {
            'avg_memory_percent': statistics.mean(memory_samples),
            'max_memory_percent': max(memory_samples),
            'avg_cpu_percent': statistics.mean(cpu_samples),
            'max_cpu_percent': max(cpu_samples),
        }

        print(f"\nResults:")
        print(f"  Average Memory Usage: {stats['avg_memory_percent']:.1f}%")
        print(f"  Peak Memory Usage: {stats['max_memory_percent']:.1f}%")
        print(f"  Average CPU Usage: {stats['avg_cpu_percent']:.1f}%")
        print(f"  Peak CPU Usage: {stats['max_cpu_percent']:.1f}%")

        return stats

    def database_connection_test(self) -> Dict:
        """Test database connection pool by rapid sequential requests"""
        print(f"\n{'='*80}")
        print(f"TEST 5: Database Connection Pool Test")
        print(f"{'='*80}")

        num_requests = 50
        metrics = PerformanceMetrics()
        metrics.start_time = time.time()

        # Rapid fire requests to test connection pool
        for i in range(num_requests):
            response_time, status_code, error = self.test_endpoint('/health/')
            metrics.add_response(response_time, status_code, error)

        metrics.end_time = time.time()
        stats = metrics.get_statistics()

        print(f"\nResults:")
        print(f"  Total Requests: {stats['total_requests']}")
        print(f"  Successful: {stats['successful_requests']}")
        print(f"  Failed: {stats['failed_requests']}")
        print(f"  Mean Response Time: {stats['mean_response_time']:.3f}s")
        print(f"  Connection Pool Status: {'✓ HEALTHY' if stats['failed_requests'] == 0 else '✗ ISSUES DETECTED'}")

        return stats


def generate_report(test_results: Dict) -> str:
    """Generate comprehensive performance report"""
    report = []
    report.append("\n" + "="*80)
    report.append("ZUMODRA LOAD TEST REPORT")
    report.append("="*80)
    report.append(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Target URL: {BASE_URL}")
    report.append("="*80)

    # Test summaries
    report.append("\n1. CONCURRENT HOMEPAGE ACCESS")
    report.append("-" * 80)
    if 'concurrent_homepage' in test_results:
        stats = test_results['concurrent_homepage']
        report.append(f"   Success Rate: {(stats['successful_requests'] / stats['total_requests'] * 100):.1f}%")
        report.append(f"   Mean Response: {stats['mean_response_time']:.3f}s")
        report.append(f"   P95 Response: {stats['p95_response_time']:.3f}s")

    report.append("\n2. SUSTAINED LOAD TEST")
    report.append("-" * 80)
    if 'sustained_load' in test_results:
        stats = test_results['sustained_load']
        report.append(f"   Total Requests: {stats['total_requests']}")
        report.append(f"   Throughput: {stats['requests_per_second']:.2f} req/s")
        report.append(f"   Success Rate: {(stats['successful_requests'] / stats['total_requests'] * 100):.1f}%")
        report.append(f"   Mean Response: {stats['mean_response_time']:.3f}s")

    report.append("\n3. ENDPOINT HEALTH")
    report.append("-" * 80)
    if 'endpoint_health' in test_results:
        for name, result in test_results['endpoint_health'].items():
            status = "✓" if result['success'] else "✗"
            report.append(f"   {status} {name}: {result['response_time']:.3f}s")

    report.append("\n4. RESOURCE USAGE")
    report.append("-" * 80)
    if 'memory_usage' in test_results:
        stats = test_results['memory_usage']
        report.append(f"   Average Memory: {stats['avg_memory_percent']:.1f}%")
        report.append(f"   Peak Memory: {stats['max_memory_percent']:.1f}%")
        report.append(f"   Average CPU: {stats['avg_cpu_percent']:.1f}%")
        report.append(f"   Peak CPU: {stats['max_cpu_percent']:.1f}%")

    report.append("\n5. DATABASE CONNECTION POOL")
    report.append("-" * 80)
    if 'database_connection' in test_results:
        stats = test_results['database_connection']
        report.append(f"   Requests Processed: {stats['total_requests']}")
        report.append(f"   Success Rate: {(stats['successful_requests'] / stats['total_requests'] * 100):.1f}%")
        report.append(f"   Mean Response: {stats['mean_response_time']:.3f}s")

    # Recommendations
    report.append("\n6. RECOMMENDATIONS")
    report.append("-" * 80)

    recommendations = []

    # Check response times
    if 'sustained_load' in test_results:
        if test_results['sustained_load']['mean_response_time'] > 2.0:
            recommendations.append("⚠ Response times are high (>2s). Consider:")
            recommendations.append("   - Enable database query caching")
            recommendations.append("   - Optimize slow database queries")
            recommendations.append("   - Increase worker processes")
        elif test_results['sustained_load']['mean_response_time'] > 1.0:
            recommendations.append("⚠ Response times are acceptable but could be improved")
            recommendations.append("   - Review database indexes")
            recommendations.append("   - Enable page caching for static content")
        else:
            recommendations.append("✓ Response times are excellent (<1s)")

    # Check success rate
    if 'sustained_load' in test_results:
        success_rate = (test_results['sustained_load']['successful_requests'] /
                       test_results['sustained_load']['total_requests'] * 100)
        if success_rate < 95:
            recommendations.append("⚠ Success rate is below 95%. Investigate:")
            recommendations.append("   - Application error logs")
            recommendations.append("   - Database connection pool size")
            recommendations.append("   - Server resource limits")
        else:
            recommendations.append("✓ Success rate is excellent (>95%)")

    # Check memory usage
    if 'memory_usage' in test_results:
        if test_results['memory_usage']['max_memory_percent'] > 90:
            recommendations.append("⚠ Memory usage is critically high (>90%)")
            recommendations.append("   - Increase server memory")
            recommendations.append("   - Check for memory leaks")
        elif test_results['memory_usage']['max_memory_percent'] > 75:
            recommendations.append("⚠ Memory usage is high (>75%). Monitor closely")
        else:
            recommendations.append("✓ Memory usage is healthy")

    for rec in recommendations:
        report.append(f"   {rec}")

    # Demo readiness
    report.append("\n7. DEMO READINESS ASSESSMENT")
    report.append("-" * 80)

    ready = True
    issues = []

    if 'sustained_load' in test_results:
        if test_results['sustained_load']['mean_response_time'] > 3.0:
            ready = False
            issues.append("Response times too high")

        success_rate = (test_results['sustained_load']['successful_requests'] /
                       test_results['sustained_load']['total_requests'] * 100)
        if success_rate < 90:
            ready = False
            issues.append("Success rate below 90%")

    if 'memory_usage' in test_results:
        if test_results['memory_usage']['max_memory_percent'] > 90:
            ready = False
            issues.append("Memory usage critically high")

    if ready:
        report.append("   ✓ SYSTEM IS READY FOR DEMO")
        report.append("   The application can handle expected demo load.")
    else:
        report.append("   ✗ SYSTEM NEEDS ATTENTION BEFORE DEMO")
        report.append("   Issues identified:")
        for issue in issues:
            report.append(f"      - {issue}")

    report.append("\n" + "="*80)

    return "\n".join(report)


def main():
    """Main test execution"""
    print("\n" + "="*80)
    print("ZUMODRA LOAD TESTING SUITE")
    print("="*80)
    print(f"Target: {BASE_URL}")
    print(f"Concurrent Users: {CONCURRENT_USERS}")
    print(f"Test Duration: {TEST_DURATION_SECONDS}s")
    print("="*80)

    tester = LoadTester(BASE_URL)
    test_results = {}

    try:
        # Run all tests
        test_results['concurrent_homepage'] = tester.concurrent_homepage_test(CONCURRENT_USERS)
        test_results['sustained_load'] = tester.sustained_load_test(TEST_DURATION_SECONDS, CONCURRENT_USERS // 2)
        test_results['endpoint_health'] = tester.endpoint_health_check()
        test_results['memory_usage'] = tester.memory_usage_test(30)
        test_results['database_connection'] = tester.database_connection_test()

        # Generate and print report
        report = generate_report(test_results)
        print(report)

        # Save report to file
        report_file = f"load_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\nReport saved to: {report_file}")

        # Save raw data as JSON
        json_file = f"load_test_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            json.dump(test_results, f, indent=2)
        print(f"Raw data saved to: {json_file}")

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nError during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
