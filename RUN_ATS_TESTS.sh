#!/bin/bash
# Quick script to run ATS frontend tests

echo "=========================================="
echo "Zumodra ATS Frontend Test Suite"
echo "=========================================="
echo ""

# Check if Playwright is installed
if ! python -c "import playwright" 2>/dev/null; then
    echo "Installing Playwright..."
    pip install playwright pytest-playwright
    playwright install chromium
fi

# Run tests
echo "Running tests..."
python test_ats_frontend.py

# Open results
echo ""
echo "=========================================="
echo "Tests Complete!"
echo "=========================================="
echo ""
echo "Results saved to: ./ats_test_results/"
echo ""
echo "Opening HTML report..."

# Try to open HTML report
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    open ats_test_results/ats_test_report_*.html 2>/dev/null || echo "Open manually: ats_test_results/ats_test_report_*.html"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    # Windows
    start ats_test_results/ats_test_report_*.html 2>/dev/null || echo "Open manually: ats_test_results\ats_test_report_*.html"
else
    # Linux
    xdg-open ats_test_results/ats_test_report_*.html 2>/dev/null || echo "Open manually: ats_test_results/ats_test_report_*.html"
fi

echo ""
echo "Review screenshots in: ./ats_test_results/screenshots/"
echo ""
