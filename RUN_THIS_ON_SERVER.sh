#!/bin/bash
# COPY AND PASTE THIS ENTIRE SCRIPT INTO YOUR SSH TERMINAL

set -x  # Show commands as they run

echo "========================================="
echo "Starting Zumodra Services"
echo "========================================="

# Try to find project directory
if [ -d "/var/www/zumodra" ]; then
    cd /var/www/zumodra
elif [ -d "/opt/zumodra" ]; then
    cd /opt/zumodra
else
    # Find any directory with manage.py
    PROJECT_DIR=$(find /home -name "manage.py" -type f 2>/dev/null | head -1 | xargs dirname)
    if [ -n "$PROJECT_DIR" ]; then
        cd "$PROJECT_DIR"
    fi
fi

echo "Working directory: $(pwd)"

# Pull latest code
git pull origin main || echo "Git pull failed or not needed"

# Start systemd services
sudo systemctl start zumodra-web 2>/dev/null || echo "zumodra-web service not found"
sudo systemctl start zumodra-channels 2>/dev/null || echo "zumodra-channels service not found"
sudo systemctl start zumodra-celery 2>/dev/null || echo "zumodra-celery service not found"
sudo systemctl start nginx 2>/dev/null || echo "nginx service not found"
sudo systemctl start postgresql 2>/dev/null || echo "postgresql service not found"
sudo systemctl start redis 2>/dev/null || echo "redis service not found"

# Enable auto-start
sudo systemctl enable zumodra-web 2>/dev/null
sudo systemctl enable zumodra-channels 2>/dev/null
sudo systemctl enable nginx 2>/dev/null

# OR try Docker if compose file exists
if [ -f "docker-compose.yml" ]; then
    echo "Found docker-compose.yml, starting containers..."
    docker-compose up -d
fi

# Wait for services
echo "Waiting 10 seconds for services to start..."
sleep 10

# Check status
echo ""
echo "========================================="
echo "Service Status:"
echo "========================================="
sudo systemctl status zumodra-web --no-pager --lines=5 2>/dev/null || echo "No systemd service"
docker-compose ps 2>/dev/null || echo "No docker containers"

# Test health
echo ""
echo "========================================="
echo "Testing Health Endpoint:"
echo "========================================="
curl -v http://localhost:8000/health/ 2>&1 | tail -30

echo ""
echo "========================================="
echo "Done! Check the output above."
echo "If you see '200 OK', the server is working!"
echo "========================================="
