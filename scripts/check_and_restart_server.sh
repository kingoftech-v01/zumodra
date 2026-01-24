#!/bin/bash

# Zumodra Server Check and Restart Script
# Run this on the server to diagnose and fix 502 errors

set -e  # Exit on error

echo "========================================="
echo "Zumodra Server Diagnostic & Restart"
echo "Date: $(date)"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print section headers
section() {
    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=========================================${NC}"
}

# Function to print success
success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error
error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to print warning
warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to print info
info() {
    echo -e "ℹ $1"
}

# ========================================
# 1. CHECK DOCKER CONTAINERS
# ========================================
section "1. Checking Docker Containers"

if command -v docker &> /dev/null; then
    success "Docker is installed"

    # Check if docker-compose is available
    if command -v docker-compose &> /dev/null; then
        success "Docker Compose is installed"

        # Check running containers
        info "Checking running containers..."
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

        # Check all containers (including stopped)
        echo ""
        info "Checking all containers (including stopped)..."
        docker ps -a --format "table {{.Names}}\t{{.Status}}"

        # Check for zumodra-related containers
        echo ""
        info "Looking for Zumodra containers..."
        ZUMODRA_CONTAINERS=$(docker ps -a --filter "name=zumodra" --format "{{.Names}}")

        if [ -z "$ZUMODRA_CONTAINERS" ]; then
            warning "No Zumodra containers found"
            info "The application might be running as a systemd service instead"
        else
            success "Found Zumodra containers:"
            echo "$ZUMODRA_CONTAINERS"

            # Check container logs for errors
            echo ""
            info "Checking container logs for errors..."
            for container in $ZUMODRA_CONTAINERS; do
                echo ""
                echo "=== Logs for $container (last 20 lines) ==="
                docker logs --tail 20 "$container" 2>&1 | tail -20
            done
        fi

        # Check if docker-compose.yml exists in current directory
        echo ""
        if [ -f "docker-compose.yml" ]; then
            success "Found docker-compose.yml"
            info "Docker Compose services:"
            docker-compose ps
        else
            warning "No docker-compose.yml in current directory"
        fi

    else
        warning "Docker Compose not found"
    fi
else
    warning "Docker not installed or not in PATH"
    info "Application might be running as systemd services"
fi

# ========================================
# 2. CHECK SYSTEMD SERVICES
# ========================================
section "2. Checking Systemd Services"

SERVICES=("zumodra-web" "zumodra-channels" "zumodra-celery" "nginx" "postgresql" "redis")

for service in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}.service"; then
        STATUS=$(systemctl is-active "$service" 2>/dev/null || echo "not-found")
        if [ "$STATUS" = "active" ]; then
            success "$service is running"
        elif [ "$STATUS" = "not-found" ]; then
            info "$service service not found"
        else
            error "$service is $STATUS"
        fi
    else
        info "$service service not installed"
    fi
done

# ========================================
# 3. CHECK PORTS
# ========================================
section "3. Checking Listening Ports"

info "Checking if critical ports are listening..."
PORTS=("80:nginx" "443:nginx-ssl" "8000:django" "8002:django-docker" "5432:postgresql" "6379:redis")

for port_info in "${PORTS[@]}"; do
    IFS=':' read -r port service <<< "$port_info"
    if sudo netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        success "Port $port ($service) is listening"
    else
        warning "Port $port ($service) is NOT listening"
    fi
done

# ========================================
# 4. CHECK NGINX
# ========================================
section "4. Checking Nginx Configuration"

if command -v nginx &> /dev/null; then
    info "Testing nginx configuration..."
    if sudo nginx -t 2>&1; then
        success "Nginx configuration is valid"
    else
        error "Nginx configuration has errors"
    fi

    # Check nginx error logs
    echo ""
    info "Recent nginx error logs:"
    sudo tail -20 /var/log/nginx/error.log 2>/dev/null || warning "Cannot read nginx error logs"
else
    warning "Nginx not found in PATH"
fi

# ========================================
# 5. CHECK APPLICATION LOGS
# ========================================
section "5. Checking Application Logs"

LOG_PATHS=(
    "/var/log/zumodra/web.log"
    "/var/log/zumodra/error.log"
    "/var/log/gunicorn/error.log"
    "/var/log/django/error.log"
)

for log_path in "${LOG_PATHS[@]}"; do
    if [ -f "$log_path" ]; then
        success "Found log: $log_path"
        echo "Last 20 lines:"
        sudo tail -20 "$log_path"
        echo ""
    fi
done

# Check journalctl for web service
if systemctl list-unit-files | grep -q "zumodra-web.service"; then
    info "Checking journalctl for zumodra-web..."
    sudo journalctl -u zumodra-web -n 20 --no-pager
fi

# ========================================
# 6. CHECK PYTHON/DJANGO
# ========================================
section "6. Checking Python Environment"

# Try to find the project directory
PROJECT_DIRS=(
    "/var/www/zumodra"
    "/home/*/zumodra"
    "/opt/zumodra"
    "$(pwd)"
)

for dir in "${PROJECT_DIRS[@]}"; do
    if [ -f "$dir/manage.py" ]; then
        success "Found Django project at: $dir"
        cd "$dir" || continue

        # Check if virtual environment exists
        if [ -d "venv" ]; then
            success "Found virtual environment"
            source venv/bin/activate

            info "Python version: $(python --version)"
            info "Django version: $(python -c 'import django; print(django.get_version())' 2>/dev/null || echo 'Not found')"

            # Run Django check
            echo ""
            info "Running Django checks..."
            python manage.py check 2>&1 | head -20

        else
            warning "No venv directory found"
        fi
        break
    fi
done

# ========================================
# 7. RESTART DECISION
# ========================================
section "7. Restart Services"

echo ""
warning "Do you want to restart all services? (y/n)"
read -r RESTART_CHOICE

if [ "$RESTART_CHOICE" = "y" ] || [ "$RESTART_CHOICE" = "Y" ]; then

    # Check if using Docker
    if [ -f "docker-compose.yml" ] && command -v docker-compose &> /dev/null; then
        info "Restarting Docker containers..."
        docker-compose down
        docker-compose up -d
        success "Docker containers restarted"
    fi

    # Restart systemd services
    info "Restarting systemd services..."

    for service in "zumodra-web" "zumodra-channels" "zumodra-celery"; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            sudo systemctl restart "$service"
            sleep 2
            if systemctl is-active --quiet "$service"; then
                success "$service restarted successfully"
            else
                error "$service failed to restart"
                sudo journalctl -u "$service" -n 10 --no-pager
            fi
        fi
    done

    # Restart nginx
    if systemctl list-unit-files | grep -q "nginx.service"; then
        sudo systemctl restart nginx
        if systemctl is-active --quiet nginx; then
            success "Nginx restarted successfully"
        else
            error "Nginx failed to restart"
        fi
    fi

    echo ""
    success "All services restarted"

else
    info "Skipping restart"
fi

# ========================================
# 8. FINAL HEALTH CHECK
# ========================================
section "8. Final Health Check"

echo ""
info "Waiting 5 seconds for services to stabilize..."
sleep 5

# Test localhost
echo ""
info "Testing local health endpoint..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health/ 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
    success "Health check passed (HTTP $HTTP_CODE)"
elif [ "$HTTP_CODE" = "000" ]; then
    error "Could not connect to localhost:8000"
else
    error "Health check failed (HTTP $HTTP_CODE)"
fi

# Test through nginx
echo ""
info "Testing through nginx..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/health/ 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
    success "Nginx proxy working (HTTP $HTTP_CODE)"
elif [ "$HTTP_CODE" = "000" ]; then
    error "Could not connect through nginx"
else
    error "Nginx proxy failed (HTTP $HTTP_CODE)"
fi

# ========================================
# 9. SUMMARY
# ========================================
section "9. Summary"

echo ""
echo "Service Status:"
for service in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}.service"; then
        STATUS=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
        if [ "$STATUS" = "active" ]; then
            success "$service: $STATUS"
        else
            error "$service: $STATUS"
        fi
    fi
done

echo ""
if [ "$HTTP_CODE" = "200" ]; then
    success "✓ Server is responding correctly!"
    echo ""
    info "You can now test the public URL:"
    echo "  curl https://zumodra.rhematek-solutions.com/health/"
else
    error "✗ Server is still not responding"
    echo ""
    warning "Troubleshooting steps:"
    echo "  1. Check journalctl logs: sudo journalctl -u zumodra-web -n 50"
    echo "  2. Check application logs in /var/log/zumodra/"
    echo "  3. Verify gunicorn/uwsgi is running: ps aux | grep gunicorn"
    echo "  4. Check if port 8000 is listening: sudo netstat -tlnp | grep 8000"
fi

echo ""
echo "========================================="
echo "Script completed at $(date)"
echo "========================================="
