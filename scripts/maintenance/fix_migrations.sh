#!/bin/bash
# =============================================================================
# ZUMODRA MIGRATION FIX SCRIPT
# =============================================================================
# This script fixes "relation already exists" errors by faking migrations
# for apps where tables already exist in the database.
#
# Usage (inside Docker):
#   docker-compose exec web bash /app/scripts/fix_migrations.sh
#
# Or copy commands and run manually inside the web container.
# =============================================================================

set -e

echo "=============================================="
echo "  ZUMODRA MIGRATION FIX"
echo "=============================================="
echo ""

# Check if we're in the right directory
if [ ! -f "manage.py" ]; then
    echo "ERROR: manage.py not found. Run this from /app directory."
    exit 1
fi

echo "Step 1: Faking SHARED_APPS migrations (public schema)..."
echo "----------------------------------------------"

# Django core apps
python manage.py migrate contenttypes --fake 2>/dev/null || echo "  contenttypes: skipped"
python manage.py migrate auth --fake 2>/dev/null || echo "  auth: skipped"
python manage.py migrate sites --fake 2>/dev/null || echo "  sites: skipped"
python manage.py migrate admin --fake 2>/dev/null || echo "  admin: skipped"
python manage.py migrate sessions --fake 2>/dev/null || echo "  sessions: skipped"

# Third-party shared apps
python manage.py migrate django_celery_beat --fake 2>/dev/null || echo "  django_celery_beat: skipped"
python manage.py migrate axes --fake 2>/dev/null || echo "  axes: skipped"
python manage.py migrate admin_honeypot --fake 2>/dev/null || echo "  admin_honeypot: skipped"

# Zumodra shared apps
python manage.py migrate tenants --fake 2>/dev/null || echo "  tenants: skipped"
python manage.py migrate main --fake 2>/dev/null || echo "  main: skipped"
python manage.py migrate custom_account_u --fake 2>/dev/null || echo "  custom_account_u: skipped"

echo ""
echo "Step 2: Faking TENANT_APPS migrations..."
echo "----------------------------------------------"

# Django tenant apps
python manage.py migrate humanize --fake 2>/dev/null || echo "  humanize: skipped (no migrations)"
python manage.py migrate sitemaps --fake 2>/dev/null || echo "  sitemaps: skipped (no migrations)"

# OTP/2FA apps
python manage.py migrate otp_totp --fake 2>/dev/null || echo "  otp_totp: skipped"
python manage.py migrate otp_hotp --fake 2>/dev/null || echo "  otp_hotp: skipped"
python manage.py migrate otp_email --fake 2>/dev/null || echo "  otp_email: skipped"
python manage.py migrate otp_static --fake 2>/dev/null || echo "  otp_static: skipped"

# Allauth apps
python manage.py migrate account --fake 2>/dev/null || echo "  account: skipped"
python manage.py migrate socialaccount --fake 2>/dev/null || echo "  socialaccount: skipped"

# Third-party apps
python manage.py migrate auditlog --fake 2>/dev/null || echo "  auditlog: skipped"
python manage.py migrate taggit --fake 2>/dev/null || echo "  taggit: skipped"
python manage.py migrate newsletter --fake 2>/dev/null || echo "  newsletter: skipped"
python manage.py migrate thumbnail --fake 2>/dev/null || echo "  thumbnail: skipped"
python manage.py migrate django_q --fake 2>/dev/null || echo "  django_q: skipped"

# Wagtail apps
python manage.py migrate wagtailcore --fake 2>/dev/null || echo "  wagtailcore: skipped"
python manage.py migrate wagtailadmin --fake 2>/dev/null || echo "  wagtailadmin: skipped"
python manage.py migrate wagtaildocs --fake 2>/dev/null || echo "  wagtaildocs: skipped"
python manage.py migrate wagtailembeds --fake 2>/dev/null || echo "  wagtailembeds: skipped"
python manage.py migrate wagtailforms --fake 2>/dev/null || echo "  wagtailforms: skipped"
python manage.py migrate wagtailredirects --fake 2>/dev/null || echo "  wagtailredirects: skipped"
python manage.py migrate wagtailsearch --fake 2>/dev/null || echo "  wagtailsearch: skipped"
python manage.py migrate wagtailusers --fake 2>/dev/null || echo "  wagtailusers: skipped"
python manage.py migrate wagtailimages --fake 2>/dev/null || echo "  wagtailimages: skipped"
python manage.py migrate wagtaillocalize --fake 2>/dev/null || echo "  wagtaillocalize: skipped"

# Zumodra apps
python manage.py migrate accounts --fake 2>/dev/null || echo "  accounts: skipped"
python manage.py migrate ats --fake 2>/dev/null || echo "  ats: skipped"
python manage.py migrate hr_core --fake 2>/dev/null || echo "  hr_core: skipped"
python manage.py migrate finance --fake 2>/dev/null || echo "  finance: skipped"
python manage.py migrate services --fake 2>/dev/null || echo "  services: skipped"
python manage.py migrate messages_sys --fake 2>/dev/null || echo "  messages_sys: skipped"
python manage.py migrate notifications --fake 2>/dev/null || echo "  notifications: skipped"
python manage.py migrate careers --fake 2>/dev/null || echo "  careers: skipped"
python manage.py migrate analytics --fake 2>/dev/null || echo "  analytics: skipped"
python manage.py migrate blog --fake 2>/dev/null || echo "  blog: skipped"
python manage.py migrate configurations --fake 2>/dev/null || echo "  configurations: skipped"
python manage.py migrate dashboard --fake 2>/dev/null || echo "  dashboard: skipped"
python manage.py migrate dashboard_service --fake 2>/dev/null || echo "  dashboard_service: skipped"
python manage.py migrate core --fake 2>/dev/null || echo "  core: skipped"
python manage.py migrate security --fake 2>/dev/null || echo "  security: skipped"
python manage.py migrate marketing --fake 2>/dev/null || echo "  marketing: skipped"
python manage.py migrate api --fake 2>/dev/null || echo "  api: skipped"
python manage.py migrate appointment --fake 2>/dev/null || echo "  appointment: skipped"
python manage.py migrate ai_matching --fake 2>/dev/null || echo "  ai_matching: skipped"
python manage.py migrate integrations --fake 2>/dev/null || echo "  integrations: skipped"

echo ""
echo "Step 3: Running migrate_schemas..."
echo "----------------------------------------------"
python manage.py migrate_schemas --shared

echo ""
echo "=============================================="
echo "  MIGRATION FIX COMPLETE!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Exit container: exit"
echo "  2. Restart services: docker-compose restart"
echo ""
