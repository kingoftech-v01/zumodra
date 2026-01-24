#!/bin/bash
# Run this to check logs and identify what services are needed

echo "========================================="
echo "CHECKING LOGS TO IDENTIFY SERVICES"
echo "========================================="

# 1. Find all systemd services with 'zumodra' in name
echo ""
echo "1. Looking for Zumodra systemd services:"
echo "----------------------------------------"
systemctl list-unit-files | grep zumodra || echo "No zumodra services found in systemd"

# 2. Check common service names
echo ""
echo "2. Checking common service names:"
echo "----------------------------------------"
for service in zumodra zumodra-web zumodra-app zumodra-django gunicorn uwsgi; do
    if systemctl list-unit-files | grep -q "^${service}.service"; then
        echo "  ✓ Found: $service"
        STATUS=$(systemctl is-active $service 2>/dev/null || echo "inactive")
        echo "    Status: $STATUS"
    fi
done

# 3. Check for docker containers
echo ""
echo "3. Checking for Docker containers:"
echo "----------------------------------------"
if command -v docker &> /dev/null; then
    docker ps -a --filter "name=zumodra" --format "table {{.Names}}\t{{.Status}}" || echo "No zumodra containers"
fi

# 4. Check nginx error log
echo ""
echo "4. Nginx Error Log (last 30 lines):"
echo "----------------------------------------"
sudo tail -30 /var/log/nginx/error.log 2>/dev/null || echo "Cannot read nginx error log"

# 5. Check application logs
echo ""
echo "5. Application Logs:"
echo "----------------------------------------"
for log in /var/log/zumodra/*.log /var/log/django/*.log /var/log/gunicorn/*.log; do
    if [ -f "$log" ]; then
        echo "=== $log (last 20 lines) ==="
        sudo tail -20 "$log"
        echo ""
    fi
done

# 6. Check journalctl for recent errors
echo ""
echo "6. System Journal (zumodra-related, last 50 lines):"
echo "----------------------------------------"
sudo journalctl | grep -i zumodra | tail -50 || echo "No zumodra entries in journal"

# 7. Check what's listening on ports
echo ""
echo "7. Listening Ports:"
echo "----------------------------------------"
echo "Port 8000 (Django):"
sudo netstat -tlnp 2>/dev/null | grep :8000 || echo "  Nothing listening on 8000"
echo "Port 80 (HTTP):"
sudo netstat -tlnp 2>/dev/null | grep :80 || echo "  Nothing listening on 80"
echo "Port 443 (HTTPS):"
sudo netstat -tlnp 2>/dev/null | grep :443 || echo "  Nothing listening on 443"

# 8. Check for gunicorn/uwsgi processes
echo ""
echo "8. Python/Django Processes:"
echo "----------------------------------------"
ps aux | grep -E "(gunicorn|uwsgi|python.*manage\.py|daphne)" | grep -v grep || echo "No Django processes running"

# 9. Find the project directory
echo ""
echo "9. Looking for Django project:"
echo "----------------------------------------"
for dir in /var/www/zumodra /opt/zumodra /home/*/zumodra*; do
    if [ -f "$dir/manage.py" ]; then
        echo "  ✓ Found Django project at: $dir"
        echo "    Git status:"
        cd "$dir" && git log --oneline -1
    fi
done

# 10. Check docker-compose
echo ""
echo "10. Docker Compose (if exists):"
echo "----------------------------------------"
for dir in /var/www/zumodra /opt/zumodra /home/*/zumodra*; do
    if [ -f "$dir/docker-compose.yml" ]; then
        echo "  ✓ Found docker-compose.yml at: $dir"
        cd "$dir" && docker-compose ps 2>/dev/null
    fi
done

echo ""
echo "========================================="
echo "SUMMARY"
echo "========================================="
echo "Based on the output above, look for:"
echo "1. Systemd service names (section 1-2)"
echo "2. Error messages in logs (sections 4-6)"
echo "3. Whether Docker is being used (sections 3, 10)"
echo "4. Django project location (section 9)"
echo ""
echo "Then run the appropriate command:"
echo "  For systemd: sudo systemctl start <service-name>"
echo "  For Docker: cd <project-dir> && docker-compose up -d"
echo "========================================="
