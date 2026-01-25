@echo off
REM ===========================================================================
REM ZUMODRA DEPLOYMENT LAUNCHER (Windows)
REM ===========================================================================
REM
REM This script automatically deploys and tests Zumodra on the server
REM
REM Usage: DEPLOY.bat
REM ===========================================================================

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║           ZUMODRA AUTOMATED DEPLOYMENT LAUNCHER                ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
echo Starting deployment to zumodra.rhematek-solutions.com...
echo.

REM Upload and execute the deployment script via SSH
ssh zumodra "bash -s" < deploy_and_test.sh

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ╔════════════════════════════════════════════════════════════════╗
    echo ║                 DEPLOYMENT SUCCESSFUL                          ║
    echo ╚════════════════════════════════════════════════════════════════╝
    echo.
    echo Server: https://zumodra.rhematek-solutions.com
    echo.
) else (
    echo.
    echo ╔════════════════════════════════════════════════════════════════╗
    echo ║                 DEPLOYMENT FAILED                              ║
    echo ╚════════════════════════════════════════════════════════════════╝
    echo.
    echo Check the error messages above for details.
    echo.
)

pause
