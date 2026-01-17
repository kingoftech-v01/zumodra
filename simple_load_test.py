"""
Zumodra Simple Load Testing
============================

Quick load testing for demo readiness verification.
Domain: https://zumodra.rhematek-solutions.com
"""

import time
import statistics
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json

# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
CONCURRENT_USERS = 10
requests.packages.urllib3.disable_warnings()


def test_endpoint(url, timeout=30):
    """Test a single endpoint"""
    try:
        start_time = time.time()
        response = requests.get(url, timeout=timeout, verify=False)
        response_time = time.time() - start_time
        return {
            'success': True,
            'status_code': response.status_code,
            'response_time': response_time,
            'error': None
        }
    except Exception as e:
        return {
            'success': False,
            'status_code': 0,
            'response_time': time.time() - start_time,
            'error': str(e)
        }


def concurrent_homepage_test(num_users=10):
    """Test concurrent access to homepage"""
    print("\n" + "="*80)
    print(f"TEST 1: Concurrent Homepage Access ({num_users} users)")
    print("="*80)

    results = []
    with ThreadPoolExecutor(max_workers=num_users) as executor:
        futures = [executor.submit(test_endpoint, BASE_URL) for _ in range(num_users)]
        for future in as_completed(futures):
            results.append(future.result())

    successful = [r for r in results if r['success'] and 200 <= r['status_code'] < 400]
    failed = [r for r in results if not r['success'] or r['status_code'] >= 400]
    response_times = [r['response_time'] for r in results]

    print(f"\nResults:")
    print(f"  Total Requests: {len(results)}")
    print(f"  Successful: {len(successful)}")
    print(f"  Failed: {len(failed)}")

    if response_times:
        print(f"  Min Response Time: {min(response_times):.3f}s")
        print(f"  Max Response Time: {max(response_times):.3f}s")
        print(f"  Mean Response Time: {statistics.mean(response_times):.3f}s")
        print(f"  Median Response Time: {statistics.median(response_times):.3f}s")

    if failed:
        print(f"\nErrors:")
        for r in failed[:5]:  # Show first 5 errors
            print(f"  - {r['error']}")

    return {
        'total': len(results),
        'successful': len(successful),
        'failed': len(failed),
        'response_times': response_times
    }


def sustained_load_test(duration=60, concurrent_users=5):
    """Test sustained load over time"""
    print("\n" + "="*80)
    print(f"TEST 2: Sustained Load Test ({concurrent_users} users for {duration}s)")
    print("="*80)

    endpoints = [
        f"{BASE_URL}/",
        f"{BASE_URL}/health/",
        f"{BASE_URL}/about/",
        f"{BASE_URL}/pricing/",
        f"{BASE_URL}/contact/",
    ]

    results = []
    start_time = time.time()
    stop_time = start_time + duration

    def worker():
        local_results = []
        while time.time() < stop_time:
            endpoint = endpoints[len(local_results) % len(endpoints)]
            result = test_endpoint(endpoint, timeout=10)
            local_results.append(result)
            time.sleep(0.5)
        return local_results

    with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        futures = [executor.submit(worker) for _ in range(concurrent_users)]
        for future in as_completed(futures):
            results.extend(future.result())

    successful = [r for r in results if r['success'] and 200 <= r['status_code'] < 400]
    failed = [r for r in results if not r['success'] or r['status_code'] >= 400]
    response_times = [r['response_time'] for r in results if r['success']]

    elapsed = time.time() - start_time

    print(f"\nResults:")
    print(f"  Duration: {elapsed:.1f}s")
    print(f"  Total Requests: {len(results)}")
    print(f"  Successful: {len(successful)}")
    print(f"  Failed: {len(failed)}")
    print(f"  Requests/sec: {len(results) / elapsed:.2f}")

    if response_times:
        sorted_times = sorted(response_times)
        print(f"  Mean Response Time: {statistics.mean(response_times):.3f}s")
        print(f"  Median Response Time: {statistics.median(response_times):.3f}s")
        print(f"  P95 Response Time: {sorted_times[int(len(sorted_times) * 0.95)]:.3f}s")
        print(f"  Error Rate: {(len(failed) / len(results) * 100):.2f}%")

    if failed:
        print(f"\nSample Errors:")
        error_types = {}
        for r in failed:
            error_msg = r['error'] if r['error'] else f"HTTP {r['status_code']}"
            error_types[error_msg] = error_types.get(error_msg, 0) + 1

        for error, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True)[:3]:
            print(f"  - {error}: {count} occurrences")

    return {
        'total': len(results),
        'successful': len(successful),
        'failed': len(failed),
        'response_times': response_times,
        'requests_per_second': len(results) / elapsed if elapsed > 0 else 0
    }


def endpoint_health_check():
    """Test various endpoints for health"""
    print("\n" + "="*80)
    print("TEST 3: Endpoint Health Check")
    print("="*80)

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
        result = test_endpoint(f"{BASE_URL}{endpoint}", timeout=30)
        results[name] = result

        status = "PASS" if result['success'] and 200 <= result['status_code'] < 400 else "FAIL"
        print(f"  {name:20} {status:6} {result['response_time']:.3f}s (HTTP {result['status_code']})")

        if not result['success']:
            print(f"    Error: {result['error']}")

    return results


def database_connection_test():
    """Test database connection pool"""
    print("\n" + "="*80)
    print("TEST 4: Database Connection Pool Test")
    print("="*80)

    num_requests = 50
    results = []

    for i in range(num_requests):
        result = test_endpoint(f"{BASE_URL}/health/", timeout=10)
        results.append(result)

    successful = [r for r in results if r['success'] and 200 <= r['status_code'] < 400]
    failed = [r for r in results if not r['success'] or r['status_code'] >= 400]
    response_times = [r['response_time'] for r in results if r['success']]

    print(f"\nResults:")
    print(f"  Total Requests: {len(results)}")
    print(f"  Successful: {len(successful)}")
    print(f"  Failed: {len(failed)}")

    if response_times:
        print(f"  Mean Response Time: {statistics.mean(response_times):.3f}s")

    status = "HEALTHY" if len(failed) == 0 else "ISSUES DETECTED"
    print(f"  Connection Pool Status: {status}")

    return {
        'total': len(results),
        'successful': len(successful),
        'failed': len(failed),
        'response_times': response_times
    }


def generate_report(test_results):
    """Generate comprehensive performance report"""
    report = []
    report.append("\n" + "="*80)
    report.append("ZUMODRA LOAD TEST REPORT")
    report.append("="*80)
    report.append(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Target URL: {BASE_URL}")
    report.append("="*80)

    # Concurrent Homepage Test
    if 'concurrent_homepage' in test_results:
        report.append("\n1. CONCURRENT HOMEPAGE ACCESS")
        report.append("-" * 80)
        stats = test_results['concurrent_homepage']
        success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
        report.append(f"   Total Requests: {stats['total']}")
        report.append(f"   Success Rate: {success_rate:.1f}%")
        if stats['response_times']:
            report.append(f"   Mean Response: {statistics.mean(stats['response_times']):.3f}s")
            sorted_times = sorted(stats['response_times'])
            if len(sorted_times) > 0:
                report.append(f"   P95 Response: {sorted_times[int(len(sorted_times) * 0.95)]:.3f}s")

    # Sustained Load Test
    if 'sustained_load' in test_results:
        report.append("\n2. SUSTAINED LOAD TEST")
        report.append("-" * 80)
        stats = test_results['sustained_load']
        success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
        report.append(f"   Total Requests: {stats['total']}")
        report.append(f"   Throughput: {stats['requests_per_second']:.2f} req/s")
        report.append(f"   Success Rate: {success_rate:.1f}%")
        if stats['response_times']:
            report.append(f"   Mean Response: {statistics.mean(stats['response_times']):.3f}s")

    # Endpoint Health
    if 'endpoint_health' in test_results:
        report.append("\n3. ENDPOINT HEALTH")
        report.append("-" * 80)
        for name, result in test_results['endpoint_health'].items():
            status = "PASS" if result['success'] and 200 <= result['status_code'] < 400 else "FAIL"
            report.append(f"   {status} {name}: {result['response_time']:.3f}s")

    # Database Connection Pool
    if 'database_connection' in test_results:
        report.append("\n4. DATABASE CONNECTION POOL")
        report.append("-" * 80)
        stats = test_results['database_connection']
        success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
        report.append(f"   Requests Processed: {stats['total']}")
        report.append(f"   Success Rate: {success_rate:.1f}%")
        if stats['response_times']:
            report.append(f"   Mean Response: {statistics.mean(stats['response_times']):.3f}s")

    # Recommendations
    report.append("\n5. RECOMMENDATIONS")
    report.append("-" * 80)

    recommendations = []

    # Check success rate
    if 'sustained_load' in test_results:
        stats = test_results['sustained_load']
        success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0

        if success_rate < 50:
            recommendations.append("CRITICAL: Success rate is very low (<50%). Investigation required:")
            recommendations.append("   - Check if the server is running")
            recommendations.append("   - Verify domain DNS resolution")
            recommendations.append("   - Check firewall rules")
            recommendations.append("   - Review application error logs")
        elif success_rate < 95:
            recommendations.append("WARNING: Success rate is below 95%. Investigate:")
            recommendations.append("   - Application error logs")
            recommendations.append("   - Database connection pool size")
            recommendations.append("   - Server resource limits")
        else:
            recommendations.append("SUCCESS: Success rate is excellent (>95%)")

        # Check response times
        if stats['response_times']:
            mean_time = statistics.mean(stats['response_times'])
            if mean_time > 2.0:
                recommendations.append("WARNING: Response times are high (>2s). Consider:")
                recommendations.append("   - Enable database query caching")
                recommendations.append("   - Optimize slow database queries")
                recommendations.append("   - Increase worker processes")
            elif mean_time > 1.0:
                recommendations.append("INFO: Response times are acceptable but could be improved")
            else:
                recommendations.append("SUCCESS: Response times are excellent (<1s)")

    for rec in recommendations:
        report.append(f"   {rec}")

    # Demo Readiness
    report.append("\n6. DEMO READINESS ASSESSMENT")
    report.append("-" * 80)

    ready = True
    issues = []

    if 'sustained_load' in test_results:
        stats = test_results['sustained_load']
        success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0

        if success_rate < 50:
            ready = False
            issues.append("CRITICAL: Most requests are failing")
        elif success_rate < 90:
            ready = False
            issues.append("Success rate below 90%")

        if stats['response_times']:
            mean_time = statistics.mean(stats['response_times'])
            if mean_time > 3.0:
                ready = False
                issues.append("Response times too high")

    if ready:
        report.append("   SUCCESS: SYSTEM IS READY FOR DEMO")
        report.append("   The application can handle expected demo load.")
    else:
        report.append("   WARNING: SYSTEM NEEDS ATTENTION BEFORE DEMO")
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
    print("="*80)

    test_results = {}

    try:
        # Run all tests
        test_results['concurrent_homepage'] = concurrent_homepage_test(CONCURRENT_USERS)
        test_results['sustained_load'] = sustained_load_test(60, CONCURRENT_USERS // 2)
        test_results['endpoint_health'] = endpoint_health_check()
        test_results['database_connection'] = database_connection_test()

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
        # Remove response_times arrays for cleaner JSON
        json_data = {k: {k2: v2 for k2, v2 in v.items() if k2 != 'response_times'}
                    if isinstance(v, dict) else v
                    for k, v in test_results.items()}
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"Raw data saved to: {json_file}")

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nError during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
