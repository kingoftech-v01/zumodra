@echo off
REM Quick script to run ATS frontend tests

echo ==========================================
echo Zumodra ATS Frontend Test Suite
echo ==========================================
echo.

REM Check if Playwright is installed
python -c "import playwright" 2>nul
if errorlevel 1 (
    echo Installing Playwright...
    pip install playwright pytest-playwright
    playwright install chromium
)

REM Run tests
echo Running tests...
python test_ats_frontend.py

REM Open results
echo.
echo ==========================================
echo Tests Complete!
echo ==========================================
echo.
echo Results saved to: .\ats_test_results\
echo.
echo Opening HTML report...

REM Find and open the most recent HTML report
for /f "delims=" %%i in ('dir /b /od ats_test_results\ats_test_report_*.html 2^>nul') do set LATEST=%%i
if defined LATEST (
    start ats_test_results\%LATEST%
) else (
    echo No report found. Check ats_test_results\ directory.
)

echo.
echo Review screenshots in: .\ats_test_results\screenshots\
echo.
pause
