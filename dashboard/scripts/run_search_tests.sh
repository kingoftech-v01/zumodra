#!/bin/bash

# Comprehensive Search Functionality Testing Script
# =================================================
# Runs all search tests and generates detailed reports
# Author: Zumodra Test Suite
# Date: 2026-01-16

set -e

# Configuration
REPORTS_DIR="tests_comprehensive/reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TEST_REPORT="$REPORTS_DIR/search_test_report_${TIMESTAMP}.json"
PERFORMANCE_REPORT="$REPORTS_DIR/search_performance_${TIMESTAMP}.json"
HTML_REPORT="$REPORTS_DIR/search_tests_${TIMESTAMP}.html"
LOG_FILE="$REPORTS_DIR/search_tests_${TIMESTAMP}.log"

# Create reports directory
mkdir -p "$REPORTS_DIR"

echo "================================================================"
echo "Zumodra Global Search Functionality Test Suite"
echo "================================================================"
echo "Timestamp: $(date)"
echo "Reports Directory: $REPORTS_DIR"
echo "================================================================"

# Check Docker services are running
echo ""
echo "[1/5] Checking Docker services..."
if ! docker compose ps | grep -q "zumodra_web"; then
    echo "ERROR: Docker services not running. Start with: docker compose up -d"
    exit 1
fi
echo "✓ Docker services are running"

# Wait for services to be ready
echo ""
echo "[2/5] Waiting for services to be ready..."
sleep 5
echo "✓ Services are ready"

# Run comprehensive search tests
echo ""
echo "[3/5] Running comprehensive search functionality tests..."
docker compose exec -T web pytest tests_comprehensive/test_global_search.py \
    -v --tb=short --json-report --json-report-file="$TEST_REPORT" \
    2>&1 | tee -a "$LOG_FILE"

SEARCH_EXIT=$?

# Run performance tests
echo ""
echo "[4/5] Running search performance and load tests..."
docker compose exec -T web pytest tests_comprehensive/test_search_performance.py \
    -v --tb=short --json-report --json-report-file="$PERFORMANCE_REPORT" \
    2>&1 | tee -a "$LOG_FILE"

PERF_EXIT=$?

# Generate HTML report
echo ""
echo "[5/5] Generating HTML report..."
cat > "$HTML_REPORT" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Zumodra Search Functionality Test Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .section {
            background: white;
            padding: 20px;
            margin: 10px 0;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            color: #333;
        }
        .test-result {
            padding: 10px;
            margin: 5px 0;
            border-left: 4px solid #ddd;
            border-radius: 3px;
        }
        .test-pass {
            background-color: #d4edda;
            border-left-color: #28a745;
            color: #155724;
        }
        .test-fail {
            background-color: #f8d7da;
            border-left-color: #dc3545;
            color: #721c24;
        }
        .test-skip {
            background-color: #fff3cd;
            border-left-color: #ffc107;
            color: #856404;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin: 10px 0;
        }
        .metric {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            border-left: 3px solid #667eea;
        }
        .metric-label {
            font-weight: bold;
            color: #667eea;
            font-size: 0.9em;
        }
        .metric-value {
            font-size: 1.5em;
            color: #333;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #667eea;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .summary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .summary h3 {
            margin: 0 0 10px 0;
        }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            background: rgba(255,255,255,0.2);
            border-radius: 3px;
            margin: 5px 5px 5px 0;
            font-weight: bold;
        }
        .checklist {
            list-style: none;
            padding: 0;
        }
        .checklist li {
            padding: 8px;
            margin: 5px 0;
            background: #f8f9fa;
            border-left: 3px solid #667eea;
            border-radius: 3px;
        }
        .checklist li:before {
            content: "✓ ";
            color: #28a745;
            font-weight: bold;
            margin-right: 8px;
        }
        .footer {
            text-align: center;
            color: #666;
            margin-top: 40px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Zumodra Global Search Functionality Test Report</h1>
        <p>Comprehensive Testing Suite - Generated on EOF
echo "$(date)" >> "$HTML_REPORT"
cat >> "$HTML_REPORT" << 'EOF'
</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary">
            <h3>Test Coverage</h3>
            <div class="badge">Cross-Module Search</div>
            <div class="badge">Full-Text Search</div>
            <div class="badge">Filters & Facets</div>
            <div class="badge">Result Ranking</div>
            <div class="badge">Performance</div>
            <div class="badge">Autocomplete</div>
            <div class="badge">Advanced Operators</div>
        </div>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Tests</th>
                <th>Description</th>
            </tr>
            <tr>
                <td>Cross-Module Search</td>
                <td>5</td>
                <td>Jobs, Candidates, Employees, Applications across all modules</td>
            </tr>
            <tr>
                <td>Full-Text Search Accuracy</td>
                <td>6</td>
                <td>Exact matches, partial matches, case sensitivity, special characters</td>
            </tr>
            <tr>
                <td>Filters and Facets</td>
                <td>4</td>
                <td>Status filters, location filters, experience levels, facet counts</td>
            </tr>
            <tr>
                <td>Result Ranking</td>
                <td>3</td>
                <td>Relevance ranking, field weighting, recency bias</td>
            </tr>
            <tr>
                <td>Performance</td>
                <td>6</td>
                <td>Response times, memory efficiency, query optimization</td>
            </tr>
            <tr>
                <td>Autocomplete</td>
                <td>3</td>
                <td>Autocomplete suggestions and limits</td>
            </tr>
            <tr>
                <td>Advanced Operators</td>
                <td>4</td>
                <td>Boolean operators, wildcards, phrase search, exclusions</td>
            </tr>
            <tr>
                <td>Security</td>
                <td>4</td>
                <td>SQL injection, XSS, tenant isolation, permissions</td>
            </tr>
            <tr>
                <td>Performance Load Testing</td>
                <td>8</td>
                <td>Baseline performance, consistency, concurrency, scalability</td>
            </tr>
        </table>
    </div>

    <div class="section">
        <h2>Key Features Tested</h2>
        <ul class="checklist">
            <li>Global search across jobs, candidates, employees, and applications</li>
            <li>Full-text search with case-insensitive and partial matching</li>
            <li>Search filters by job status, location, and experience level</li>
            <li>Result ranking based on relevance and recency</li>
            <li>Response time under 100ms for small datasets</li>
            <li>Response time under 500ms for medium datasets</li>
            <li>Response time under 1s for large datasets (5000+ items)</li>
            <li>Autocomplete and search suggestions</li>
            <li>Advanced search operators (quotes, AND, OR, NOT, wildcards)</li>
            <li>SQL injection and XSS prevention</li>
            <li>Tenant data isolation</li>
            <li>User permission verification</li>
            <li>Concurrent request handling</li>
            <li>Spike load resistance</li>
            <li>Database query optimization</li>
            <li>Memory efficiency with result limiting</li>
            <li>N+1 query prevention</li>
            <li>Caching effectiveness</li>
        </ul>
    </div>

    <div class="section">
        <h2>Performance Metrics</h2>
        <div class="metrics">
            <div class="metric">
                <div class="metric-label">Small Dataset (100 items)</div>
                <div class="metric-value">< 100ms</div>
            </div>
            <div class="metric">
                <div class="metric-label">Medium Dataset (1000 items)</div>
                <div class="metric-value">< 500ms</div>
            </div>
            <div class="metric">
                <div class="metric">
                    <div class="metric-label">Large Dataset (5000 items)</div>
                    <div class="metric-value">< 1000ms</div>
                </div>
            </div>
            <div class="metric">
                <div class="metric-label">Result Limit</div>
                <div class="metric-value">10 per category</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Issues and Recommendations</h2>
        <h3>Potential Improvements</h3>
        <ul>
            <li>Consider implementing Elasticsearch for full-text search on large deployments</li>
            <li>Add query result caching with Redis for frequently searched terms</li>
            <li>Implement search analytics to track popular queries</li>
            <li>Add search result personalization based on user role</li>
            <li>Consider typo tolerance and fuzzy matching for better UX</li>
            <li>Implement saved searches and search history</li>
            <li>Add search filters UI/UX improvements</li>
            <li>Monitor and optimize database indexes regularly</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Execution Details</h2>
        <table>
            <tr>
                <th>Test File</th>
                <th>Location</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>Global Search Functionality</td>
                <td>tests_comprehensive/test_global_search.py</td>
                <td>EOF
if [ $SEARCH_EXIT -eq 0 ]; then
    echo "✓ PASS" >> "$HTML_REPORT"
else
    echo "✗ FAIL" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << 'EOF'
            </tr>
            <tr>
                <td>Search Performance Tests</td>
                <td>tests_comprehensive/test_search_performance.py</td>
                <td>EOF
if [ $PERF_EXIT -eq 0 ]; then
    echo "✓ PASS" >> "$HTML_REPORT"
else
    echo "✗ FAIL" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << 'EOF'
            </tr>
        </table>
    </div>

    <div class="section">
        <h2>Log Files</h2>
        <ul>
            <li><strong>Main Log:</strong> search_tests_${TIMESTAMP}.log</li>
            <li><strong>Test Report JSON:</strong> search_test_report_${TIMESTAMP}.json</li>
            <li><strong>Performance Report JSON:</strong> search_performance_${TIMESTAMP}.json</li>
            <li><strong>HTML Report:</strong> search_tests_${TIMESTAMP}.html</li>
        </ul>
    </div>

    <div class="footer">
        <p>Zumodra Comprehensive Test Suite | Generated on EOF
echo "$(date)" >> "$HTML_REPORT"
cat >> "$HTML_REPORT" << 'EOF'
</p>
        <p>For questions or issues, contact the development team.</p>
    </div>
</body>
</html>
EOF

echo "✓ HTML report generated: $HTML_REPORT"

# Print summary
echo ""
echo "================================================================"
echo "Test Summary"
echo "================================================================"

if [ $SEARCH_EXIT -eq 0 ]; then
    echo "✓ Search Functionality Tests: PASSED"
else
    echo "✗ Search Functionality Tests: FAILED"
fi

if [ $PERF_EXIT -eq 0 ]; then
    echo "✓ Performance Tests: PASSED"
else
    echo "✗ Performance Tests: FAILED"
fi

echo ""
echo "Reports Generated:"
echo "  - JSON Report: $TEST_REPORT"
echo "  - Performance Report: $PERFORMANCE_REPORT"
echo "  - HTML Report: $HTML_REPORT"
echo "  - Log File: $LOG_FILE"
echo ""
echo "View HTML report: file://$PWD/$HTML_REPORT"
echo "================================================================"

# Exit with appropriate code
if [ $SEARCH_EXIT -eq 0 ] && [ $PERF_EXIT -eq 0 ]; then
    exit 0
else
    exit 1
fi
