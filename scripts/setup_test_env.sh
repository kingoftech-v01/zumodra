#!/bin/bash
# Quick setup script for test environment
# Run: bash scripts/setup_test_env.sh

set -e

echo "=== Installing system packages ==="
apt-get update -qq
apt-get install -y -qq gdal-bin libgdal-dev libgeos-dev postgresql-16-postgis-3 postgresql-16-postgis-3-scripts > /dev/null 2>&1

echo "=== Fixing PostgreSQL auth ==="
sed -i 's/local\s*all\s*postgres\s*peer/local   all             postgres                                trust/' /etc/postgresql/16/main/pg_hba.conf
sed -i 's/local\s*all\s*all\s*peer/local   all             all                                     trust/' /etc/postgresql/16/main/pg_hba.conf
chown claude:claude /etc/postgresql/16/main/pg_hba.conf 2>/dev/null || true

echo "=== Starting PostgreSQL ==="
chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key 2>/dev/null || true
service postgresql restart
sleep 2
pg_isready

echo "=== Creating DB role ==="
psql -U postgres -c "CREATE ROLE root WITH LOGIN SUPERUSER CREATEDB;" 2>/dev/null || true

echo "=== Installing Python packages ==="
pip3 install -q \
    djangorestframework djangorestframework-simplejwt drf-spectacular \
    django-filter django-cors-headers django-allauth django-axes \
    django-celery-beat django-celery-results celery \
    channels daphne --no-deps \
    psycopg2-binary psycopg \
    wagtail wagtail-localize wagtailcodeblock \
    django-crispy-forms django-import-export django-simple-history \
    django-auditlog django-storages django-debug-toolbar django-extensions \
    django-phonenumber-field django-anymail django-cleanup django-tinymce \
    sorl-thumbnail django-leaflet django-newsletter django-analytical \
    django-clickify django-csp django-admin-honeypot django-widget-tweaks \
    django-picklefield django-q2 django-cryptography django-formtools \
    django-floppyforms dj-database-url django-secure-mail django-sslserver \
    django-jsonfield \
    ua-parser user-agents \
    Willow whitenoise gunicorn uvicorn \
    Pillow pillow-heif \
    stripe openai geopy geoip2 maxminddb \
    fido2 icalendar requests-mock freezegun python-magic babel \
    pytest-timeout pytest-django pytest-cov factory-boy faker \
    redis channels-redis \
    tablib openpyxl python-docx PyPDF2 pdfplumber \
    qrcode phonenumbers python-dotenv \
    2>&1 | tail -3

echo "=== Fixing cryptography package ==="
pip3 install --force-reinstall --ignore-installed cryptography 2>&1 | tail -1

echo "=== Verifying ==="
python3 -c "
import django, rest_framework, allauth, axes, wagtail, channels, psycopg2, celery, fido2
print('All dependencies OK')
"

timeout 60 python3 -m pytest --co -q --no-header 2>&1 | tail -3

echo "=== Done ==="
