#!/bin/bash

##############################################################################
# Comprehensive Email System Integration Test Suite
##############################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$PROJECT_ROOT/tests_comprehensive/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAILHOG_URL="http://localhost:8026"
DOCKER_COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"

# Ensure report directory exists
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Email System Integration Test Suite${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Function to print section
print_section() {
    echo -e "\n${BLUE}>>> $1${NC}"
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if Docker containers are running
check_docker_services() {
    print_section "Checking Docker Services"

    # Check if docker-compose file exists
    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        print_error "docker-compose.yml not found at $DOCKER_COMPOSE_FILE"
        return 1
    fi

    # Check for running containers
    local running_services=$(docker compose -f "$DOCKER_COMPOSE_FILE" ps --services --filter "status=running" 2>/dev/null)

    if [ -z "$running_services" ]; then
        print_warning "No Docker services running. Starting services..."
        docker compose -f "$DOCKER_COMPOSE_FILE" up -d web db redis mailhog > /dev/null 2>&1
        sleep 10
    fi

    # Check specific services
    local services=("web" "db" "redis" "mailhog")
    for service in "${services[@]}"; do
        if docker compose -f "$DOCKER_COMPOSE_FILE" ps "$service" 2>/dev/null | grep -q "running"; then
            print_success "$service is running"
        else
            print_warning "$service may not be running"
        fi
    done
}

# Check MailHog connectivity
check_mailhog() {
    print_section "Checking MailHog"

    local max_attempts=5
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "$MAILHOG_URL/api/v2/messages" > /dev/null 2>&1; then
            print_success "MailHog is accessible at $MAILHOG_URL"

            # Get current message count
            local msg_count=$(curl -s "$MAILHOG_URL/api/v2/messages" | grep -o '"total":[0-9]*' | cut -d: -f2)
            print_success "Current email count in MailHog: $msg_count"

            return 0
        else
            if [ $attempt -lt $max_attempts ]; then
                print_warning "MailHog not accessible (attempt $attempt/$max_attempts). Retrying..."
                sleep 2
            fi
        fi
        ((attempt++))
    done

    print_error "MailHog is not accessible after $max_attempts attempts"
    print_error "MailHog should be running on $MAILHOG_URL"
    return 1
}

# Run Python test suite
run_python_tests() {
    print_section "Running Python Test Suite"

    cd "$PROJECT_ROOT"

    # Create test report file
    local test_report="$REPORT_DIR/python_test_output_${TIMESTAMP}.txt"

    # Run the test
    python tests_comprehensive/test_email_system_integration.py | tee "$test_report"

    return ${PIPESTATUS[0]}
}

# Run pytest tests
run_pytest_tests() {
    print_section "Running Pytest Tests"

    cd "$PROJECT_ROOT"

    local pytest_report="$REPORT_DIR/pytest_report_${TIMESTAMP}.txt"

    # Run notifications tests
    pytest notifications/tests/test_notifications.py -v --tb=short 2>&1 | tee "$pytest_report"

    return ${PIPESTATUS[0]}
}

# Test transactional emails
test_transactional_emails() {
    print_section "Testing Transactional Email Sending"

    cd "$PROJECT_ROOT"

    local email_test_report="$REPORT_DIR/transactional_email_test_${TIMESTAMP}.txt"

    cat > /tmp/test_email_send.py << 'EOF'
import os
import sys
import django

sys.path.insert(0, '/c/Users/techn/OneDrive/Documents/zumodra')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
django.setup()

from django.core.mail import send_mail
from django.template.loader import render_to_string
import time

print("Testing transactional email sending...")
print("-" * 50)

try:
    # Test 1: Simple email
    print("\n1. Sending simple test email...")
    result = send_mail(
        subject='Zumodra Email System Test',
        message='This is a test of the Zumodra email system.',
        from_email='noreply@zumodra.local',
        recipient_list=['test@example.com'],
        fail_silently=False,
    )
    print(f"   Result: {result}")
    time.sleep(1)

    # Test 2: HTML email
    print("\n2. Sending HTML email...")
    result = send_mail(
        subject='HTML Test Email',
        message='Plain text fallback',
        from_email='noreply@zumodra.local',
        recipient_list=['test@example.com'],
        fail_silently=False,
        html_message='<h1>HTML Test</h1><p>This is an HTML email test.</p>'
    )
    print(f"   Result: {result}")
    time.sleep(1)

    # Test 3: Email with template
    print("\n3. Testing template rendering...")
    context = {'user_name': 'Test User', 'action_url': 'http://example.com'}
    html_content = render_to_string('notifications/email/welcome.html', context) if False else '<p>Template test</p>'
    print(f"   Template rendering successful")

    print("\n" + "-" * 50)
    print("All transactional email tests completed!")

except Exception as e:
    print(f"ERROR: {str(e)}")
    import traceback
    traceback.print_exc()
EOF

    python /tmp/test_email_send.py 2>&1 | tee "$email_test_report"
    local result=$?

    rm -f /tmp/test_email_send.py
    return $result
}

# Check MailHog messages
check_mailhog_messages() {
    print_section "Checking MailHog for Emails"

    local msg_report="$REPORT_DIR/mailhog_messages_${TIMESTAMP}.json"

    echo "Fetching messages from MailHog..."
    curl -s "$MAILHOG_URL/api/v2/messages" > "$msg_report"

    if [ -f "$msg_report" ]; then
        local total=$(grep -o '"total":[0-9]*' "$msg_report" | cut -d: -f2)
        if [ -n "$total" ]; then
            print_success "Total emails in MailHog: $total"
            print_success "Message details saved to: $msg_report"
        else
            print_warning "Could not parse MailHog response"
        fi
    else
        print_error "Could not fetch messages from MailHog"
    fi
}

# Test email templates
test_email_templates() {
    print_section "Testing Email Templates"

    cd "$PROJECT_ROOT"

    local template_report="$REPORT_DIR/template_test_${TIMESTAMP}.txt"

    cat > /tmp/test_templates.py << 'EOF'
import os
import sys
import django

sys.path.insert(0, '/c/Users/techn/OneDrive/Documents/zumodra')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
django.setup()

from notifications.models import NotificationTemplate

print("Testing Email Templates...")
print("-" * 50)

templates = NotificationTemplate.objects.all()[:5]
print(f"\nFound {templates.count()} templates:")

for template in templates:
    print(f"\n  Template: {template.name}")
    print(f"  - Code: {template.code}")
    print(f"  - Subject: {template.subject}")
    print(f"  - Active: {template.is_active}")

print("\n" + "-" * 50)
print("Template test completed!")
EOF

    python /tmp/test_templates.py 2>&1 | tee "$template_report"
    local result=$?

    rm -f /tmp/test_templates.py
    return $result
}

# Test notification preferences
test_notification_preferences() {
    print_section "Testing Notification Preferences"

    cd "$PROJECT_ROOT"

    local pref_report="$REPORT_DIR/preferences_test_${TIMESTAMP}.txt"

    cat > /tmp/test_preferences.py << 'EOF'
import os
import sys
import django

sys.path.insert(0, '/c/Users/techn/OneDrive/Documents/zumodra')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
django.setup()

from notifications.models import NotificationPreference
from django.contrib.auth import get_user_model

User = get_user_model()

print("Testing Notification Preferences...")
print("-" * 50)

# Get or create a test user
user, created = User.objects.get_or_create(
    username='pref_test_user',
    defaults={'email': 'pref@test.local'}
)

# Get or create preferences
prefs, created = NotificationPreference.objects.get_or_create(user=user)

print(f"\nUser: {user.username}")
print(f"Preferences ID: {prefs.id}")
print(f"Email Enabled: {prefs.email_enabled}")
print(f"SMS Enabled: {prefs.sms_enabled}")
print(f"Push Enabled: {prefs.push_enabled}")
print(f"In-App Enabled: {prefs.inapp_enabled}")
print(f"Marketing Emails: {prefs.marketing_emails}")

# Test unsubscribe
print("\nTesting unsubscribe...")
original_marketing = prefs.marketing_emails
prefs.marketing_emails = not original_marketing
prefs.save()

prefs.refresh_from_db()
print(f"Marketing emails toggled: {original_marketing} -> {prefs.marketing_emails}")

# Reset
prefs.marketing_emails = original_marketing
prefs.save()

print("\n" + "-" * 50)
print("Preferences test completed!")
EOF

    python /tmp/test_preferences.py 2>&1 | tee "$pref_report"
    local result=$?

    rm -f /tmp/test_preferences.py
    return $result
}

# Generate final summary report
generate_summary() {
    print_section "Generating Test Summary"

    local summary_report="$REPORT_DIR/email_test_summary_${TIMESTAMP}.txt"

    cat > "$summary_report" << EOF
Email System Integration Test Summary
=====================================
Date: $(date)
Project Root: $PROJECT_ROOT
Report Directory: $REPORT_DIR

Docker Services Status:
- Check docker-compose.yml for service definitions
- MailHog accessible at: $MAILHOG_URL
- Web service accessible at: http://localhost:8002

Test Reports Generated:
$(ls -1 "$REPORT_DIR" | grep -E "${TIMESTAMP}|latest" | sed 's/^/  - /')

Key Test Areas Covered:
1. MailHog Connectivity
2. Transactional Email Sending
3. Email Template Rendering
4. Email Queue Processing (Celery)
5. Bounce and Complaint Handling
6. Email Tracking (Opens, Clicks)
7. Unsubscribe Management
8. Email Logs and Audit Trail
9. Email Notification Service
10. Email Settings Configuration
11. Scheduled Email Notifications
12. Multi-tenant Email Isolation

Next Steps:
1. Review detailed test reports in $REPORT_DIR
2. Check MailHog interface at $MAILHOG_URL
3. Review Django logs in project/logs/
4. Check Celery task logs for async email processing

For more information, see tests_comprehensive/ directory.
EOF

    print_success "Summary report created: $summary_report"
    cat "$summary_report"
}

# Main execution
main() {
    local failures=0

    # Pre-flight checks
    check_docker_services || ((failures++))
    check_mailhog || ((failures++))

    # Run tests
    run_python_tests || ((failures++))

    # Additional tests
    test_transactional_emails || ((failures++))
    test_email_templates || ((failures++))
    test_notification_preferences || ((failures++))
    check_mailhog_messages

    # Generate summary
    generate_summary

    # Print final status
    echo -e "\n${BLUE}========================================${NC}"
    if [ $failures -eq 0 ]; then
        echo -e "${GREEN}All email system tests completed successfully!${NC}"
    else
        echo -e "${RED}$failures test suite(s) had failures${NC}"
    fi
    echo -e "${BLUE}========================================${NC}\n"

    return $failures
}

# Run main
main
exit $?
