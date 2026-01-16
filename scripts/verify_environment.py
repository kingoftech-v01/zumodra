#!/usr/bin/env python
"""
Environment Verification Script for Zumodra Platform

This script verifies that all dependencies and configurations are correct
before starting development or deployment.

Usage:
    python scripts/verify_environment.py
"""

import os
import sys
from pathlib import Path

# Colors for terminal output
class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def print_header(text):
    """Print a section header."""
    print(f"\n{Colors.BLUE}{'=' * 60}{Colors.NC}")
    print(f"{Colors.BLUE}{text}{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}\n")

def print_success(text):
    """Print a success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.NC}")

def print_warning(text):
    """Print a warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.NC}")

def print_error(text):
    """Print an error message."""
    print(f"{Colors.RED}✗ {text}{Colors.NC}")

def check_python_version():
    """Check if Python version is compatible."""
    print_header("Checking Python Version")

    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    print(f"  Python version: {version_str}")

    if version.major == 3 and version.minor >= 11:
        print_success("Python version is compatible (3.11+)")
        return True
    else:
        print_error("Python 3.11 or higher is required")
        return False

def check_gdal_installation():
    """Check if GDAL is properly installed."""
    print_header("Checking GDAL Installation")

    try:
        from osgeo import gdal
        version = gdal.__version__
        print(f"  GDAL version: {version}")
        print_success("GDAL is installed")
        return True
    except ImportError as e:
        print_error(f"GDAL is not installed: {e}")
        print("  Install GDAL:")
        print("    Windows: Download precompiled wheel from https://github.com/cgohlke/geospatial-wheels")
        print("    Linux: apt-get install gdal-bin libgdal-dev")
        return False

def check_geos_installation():
    """Check if GEOS is properly installed."""
    print_header("Checking GEOS Installation")

    try:
        from django.contrib.gis.geos import Point
        point = Point(0, 0)
        print(f"  GEOS test: {point}")
        print_success("GEOS is working")
        return True
    except Exception as e:
        print_error(f"GEOS is not working: {e}")
        return False

def check_django_installation():
    """Check if Django is properly installed."""
    print_header("Checking Django Installation")

    try:
        import django
        version = django.get_version()
        print(f"  Django version: {version}")

        if version.startswith('5.'):
            print_success("Django 5.x is installed")
            return True
        else:
            print_warning(f"Django {version} detected (5.x recommended)")
            return True
    except ImportError as e:
        print_error(f"Django is not installed: {e}")
        return False

def check_channels_installation():
    """Check if Django Channels is properly installed."""
    print_header("Checking Django Channels")

    try:
        import channels
        from channels.layers import get_channel_layer
        version = channels.__version__
        print(f"  Channels version: {version}")
        print_success("Django Channels is installed")
        return True
    except ImportError as e:
        print_error(f"Django Channels is not installed: {e}")
        return False

def check_env_file():
    """Check if .env file exists."""
    print_header("Checking Environment Configuration")

    env_file = Path('.env')
    if env_file.exists():
        print_success(".env file exists")

        # Check for critical env vars
        critical_vars = [
            'SECRET_KEY',
            'DATABASE_URL',
            'REDIS_URL',
            'RABBITMQ_URL'
        ]

        with open(env_file) as f:
            content = f.read()

        missing_vars = []
        for var in critical_vars:
            if var not in content:
                missing_vars.append(var)

        if missing_vars:
            print_warning(f"Missing environment variables: {', '.join(missing_vars)}")
            return False
        else:
            print_success("All critical environment variables are present")
            return True
    else:
        print_error(".env file not found")
        print("  Copy .env.example to .env and configure it:")
        print("    cp .env.example .env")
        return False

def check_docker_running():
    """Check if Docker is running."""
    print_header("Checking Docker")

    try:
        import subprocess
        result = subprocess.run(
            ['docker', 'ps'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            container_count = len(lines) - 1  # Subtract header
            print(f"  Docker containers running: {container_count}")

            if container_count > 0:
                print_success("Docker is running")
                return True
            else:
                print_warning("Docker is running but no containers are up")
                print("  Start containers: docker compose up -d")
                return False
        else:
            print_error("Docker is not running")
            return False
    except FileNotFoundError:
        print_error("Docker is not installed")
        return False
    except subprocess.TimeoutExpired:
        print_error("Docker command timed out")
        return False

def check_database_connection():
    """Check if database is accessible."""
    print_header("Checking Database Connection")

    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
        import django
        django.setup()

        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT version()")
            version = cursor.fetchone()[0]
            print(f"  PostgreSQL version: {version.split(',')[0]}")

        print_success("Database connection successful")
        return True
    except Exception as e:
        print_error(f"Database connection failed: {e}")
        print("  Make sure Docker containers are running:")
        print("    docker compose up -d")
        return False

def check_redis_connection():
    """Check if Redis is accessible."""
    print_header("Checking Redis Connection")

    try:
        import redis
        from django.conf import settings

        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6380/2')
        client = redis.from_url(redis_url)
        client.ping()

        print_success("Redis connection successful")
        return True
    except Exception as e:
        print_error(f"Redis connection failed: {e}")
        return False

def check_static_files():
    """Check if static files are configured."""
    print_header("Checking Static Files")

    static_dir = Path('staticfiles')
    if static_dir.exists():
        file_count = len(list(static_dir.rglob('*')))
        print(f"  Static files directory exists ({file_count} files)")
        print_success("Static files are collected")
        return True
    else:
        print_warning("Static files directory not found")
        print("  Collect static files: python manage.py collectstatic")
        return False

def main():
    """Run all environment checks."""
    print(f"\n{Colors.BLUE}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     Zumodra Environment Verification Script              ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

    results = {}

    # Run all checks
    results['python'] = check_python_version()
    results['gdal'] = check_gdal_installation()
    results['geos'] = check_geos_installation()
    results['django'] = check_django_installation()
    results['channels'] = check_channels_installation()
    results['env'] = check_env_file()
    results['docker'] = check_docker_running()
    results['database'] = check_database_connection()
    results['redis'] = check_redis_connection()
    results['static'] = check_static_files()

    # Summary
    print_header("Summary")

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    percentage = (passed / total) * 100

    print(f"  Checks passed: {passed}/{total} ({percentage:.0f}%)")
    print()

    if passed == total:
        print_success("All checks passed! Environment is ready.")
        return 0
    elif percentage >= 70:
        print_warning("Most checks passed. Review warnings above.")
        return 1
    else:
        print_error("Many checks failed. Fix errors before proceeding.")
        return 2

if __name__ == '__main__':
    sys.exit(main())
