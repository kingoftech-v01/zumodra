# Nginx Quick Reference Card

## Quick Status Check

```bash
# One-liner status check
ssh zumodra "docker ps | grep nginx && systemctl is-active nginx"
```

## Common Commands

### System Nginx (Host Level)

```bash
# Status
ssh zumodra "systemctl status nginx"

# Test configuration
ssh zumodra "nginx -t"

# Reload configuration (zero downtime)
ssh zumodra "nginx -t && systemctl reload nginx"

# Restart
ssh zumodra "systemctl restart nginx"

# View logs
ssh zumodra "tail -f /var/log/nginx/access.log"
ssh zumodra "tail -f /var/log/nginx/error.log"

# Check listening ports
ssh zumodra "ss -tlnp | grep nginx"
```

### Docker Nginx (Container Level)

```bash
# Status
ssh zumodra "docker ps | grep zumodra_nginx"

# Restart container
ssh zumodra "cd /root/zumodra && docker compose restart nginx"

# View logs
ssh zumodra "docker logs -f zumodra_nginx"

# Execute command in container
ssh zumodra "docker exec zumodra_nginx nginx -t"

# Access container shell
ssh zumodra "docker exec -it zumodra_nginx sh"
```

## Key Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| System Nginx Config | `/etc/nginx/sites-available/zumodra` | Main production config |
| Docker Nginx Config | `/root/zumodra/docker/nginx-sites/zumodra.rhematek.conf` | Container config |
| Main Nginx Config | `/root/zumodra/docker/nginx.conf` | Global nginx settings |
| Docker Compose | `/root/zumodra/docker-compose.yml` | Service definitions |
| SSL Certificates | `/etc/letsencrypt/live/zumodra.rhematek-solutions.com-0001/` | Let's Encrypt certs |

## Editing Configurations

### Edit System Nginx

```bash
# Edit config
ssh zumodra "nano /etc/nginx/sites-available/zumodra"

# Test and reload
ssh zumodra "nginx -t && systemctl reload nginx"
```

### Edit Docker Nginx

```bash
# Edit locally
notepad "c:\Users\techn\OneDrive\Documents\zumodra\docker\nginx-sites\zumodra.rhematek.conf"

# Copy to server
scp "c:\Users\techn\OneDrive\Documents\zumodra\docker\nginx-sites\zumodra.rhematek.conf" zumodra:/root/zumodra/docker/nginx-sites/

# Restart container
ssh zumodra "cd /root/zumodra && docker compose restart nginx"
```

## Testing Endpoints

```bash
# Health check
curl -I https://zumodra.rhematek-solutions.com/health/

# Tenant subdomain
curl -I https://demo-company.zumodra.rhematek-solutions.com/

# WebSocket endpoint
curl -I https://zumodra.rhematek-solutions.com/ws/

# Static files
curl -I https://zumodra.rhematek-solutions.com/static/img/favicon.ico

# API endpoint
curl -I https://zumodra.rhematek-solutions.com/api/v1/
```

## Troubleshooting

### 404 Errors on Tenant Subdomains

```bash
# Check server_name includes wildcard
ssh zumodra "grep server_name /etc/nginx/sites-available/zumodra"
# Should show: *.zumodra.rhematek-solutions.com

# Check Host header preservation
ssh zumodra "grep 'proxy_set_header Host' /etc/nginx/sites-available/zumodra"
# Should show: proxy_set_header Host $host;

# Check ALLOWED_HOSTS
ssh zumodra "grep ALLOWED_HOSTS /root/zumodra/.env"
# Should include: .zumodra.rhematek-solutions.com
```

### 502 Bad Gateway

```bash
# Check if web container is running
ssh zumodra "docker ps | grep zumodra_web"

# Check web container logs
ssh zumodra "docker logs --tail 50 zumodra_web"

# Check if port 8002 is accessible
ssh zumodra "curl -I http://localhost:8002/health/"

# Restart web container
ssh zumodra "cd /root/zumodra && docker compose restart web"
```

### SSL Certificate Issues

```bash
# Check certificate status
ssh zumodra "certbot certificates"

# Check certificate expiry
ssh zumodra "certbot certificates | grep 'Expiry Date'"

# Renew certificates
ssh zumodra "certbot renew"

# Force renewal (if within 30 days)
ssh zumodra "certbot renew --force-renewal"

# Reload nginx after renewal
ssh zumodra "systemctl reload nginx"
```

### High CPU or Memory

```bash
# Check container resource usage
ssh zumodra "docker stats --no-stream | grep nginx"

# Check nginx worker processes
ssh zumodra "ps aux | grep nginx"

# Check current connections
ssh zumodra "ss -tn | grep :80 | wc -l"
ssh zumodra "ss -tn | grep :443 | wc -l"
```

## Monitoring

### Real-time Logs

```bash
# System nginx access log (all requests)
ssh zumodra "tail -f /var/log/nginx/access.log"

# System nginx error log (errors only)
ssh zumodra "tail -f /var/log/nginx/error.log"

# Docker nginx logs
ssh zumodra "docker logs -f zumodra_nginx"

# Filter logs by domain
ssh zumodra "tail -f /var/log/nginx/access.log | grep 'demo-company'"

# Filter logs by status code
ssh zumodra "tail -f /var/log/nginx/access.log | grep ' 404 '"
ssh zumodra "tail -f /var/log/nginx/access.log | grep ' 502 '"
```

### Log Analysis

```bash
# Count requests by status code
ssh zumodra "awk '{print \$9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn"

# Top 10 requested URLs
ssh zumodra "awk '{print \$7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -10"

# Top 10 IPs by request count
ssh zumodra "awk '{print \$1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -10"

# Average response time
ssh zumodra "awk '{print \$NF}' /var/log/nginx/access.log | grep -E '^[0-9]' | awk '{s+=\$1; c++} END {print s/c}'"
```

## Performance Tuning

### Check Current Settings

```bash
# Worker processes
ssh zumodra "grep worker_processes /root/zumodra/docker/nginx.conf"

# Worker connections
ssh zumodra "grep worker_connections /root/zumodra/docker/nginx.conf"

# Keepalive timeout
ssh zumodra "grep keepalive_timeout /root/zumodra/docker/nginx.conf"
```

### Optimize for High Traffic

Edit `/root/zumodra/docker/nginx.conf`:

```nginx
worker_processes auto;  # Use all CPU cores

events {
    worker_connections 8192;  # Increase if you have many connections
    use epoll;
    multi_accept on;
}

http {
    keepalive_timeout 65;
    keepalive_requests 100;
}
```

## Security

### Check Security Headers

```bash
# Test security headers
curl -I https://zumodra.rhematek-solutions.com/ | grep -E 'Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options'
```

### Rate Limiting Status

```bash
# Check rate limit hits in logs
ssh zumodra "grep 'limiting requests' /var/log/nginx/error.log | tail -20"

# Count rate limit events
ssh zumodra "grep 'limiting requests' /var/log/nginx/error.log | wc -l"
```

### Block an IP Address

Add to nginx config:
```nginx
deny 203.0.113.42;
```

Then reload:
```bash
ssh zumodra "nginx -t && systemctl reload nginx"
```

## SSL Certificate Management

### Check Certificate Details

```bash
# List all certificates
ssh zumodra "certbot certificates"

# Check specific certificate
ssh zumodra "openssl x509 -in /etc/letsencrypt/live/zumodra.rhematek-solutions.com-0001/fullchain.pem -text -noout | grep -E 'Subject:|DNS:|Not After'"
```

### Renew Certificates

```bash
# Dry run (test renewal)
ssh zumodra "certbot renew --dry-run"

# Actual renewal
ssh zumodra "certbot renew"

# Reload nginx after renewal
ssh zumodra "systemctl reload nginx"
```

### Setup Auto-renewal (Cron)

```bash
# Check if certbot timer is enabled
ssh zumodra "systemctl status certbot.timer"

# Manual cron (if timer not available)
ssh zumodra "crontab -l | grep certbot || echo '0 0,12 * * * certbot renew --quiet'"
```

## Backup & Restore

### Backup Configuration

```bash
# Backup system nginx config
ssh zumodra "tar -czf /root/backups/nginx-$(date +%Y%m%d).tar.gz /etc/nginx/sites-available/zumodra"

# Backup docker nginx config
ssh zumodra "cd /root/zumodra && tar -czf /root/backups/docker-nginx-$(date +%Y%m%d).tar.gz docker/nginx*"

# Backup SSL certificates
ssh zumodra "tar -czf /root/backups/letsencrypt-$(date +%Y%m%d).tar.gz /etc/letsencrypt/"
```

### Restore Configuration

```bash
# Restore system nginx
ssh zumodra "tar -xzf /root/backups/nginx-YYYYMMDD.tar.gz -C /"

# Test and reload
ssh zumodra "nginx -t && systemctl reload nginx"
```

## Emergency Procedures

### Complete Restart

```bash
# Restart everything in order
ssh zumodra "cd /root/zumodra && docker compose restart db redis rabbitmq && sleep 10 && docker compose restart web channels && sleep 5 && docker compose restart nginx && systemctl reload nginx"
```

### Rollback Configuration

```bash
# Restore previous config
ssh zumodra "cp /etc/nginx/sites-available/zumodra.backup /etc/nginx/sites-available/zumodra"

# Test and reload
ssh zumodra "nginx -t && systemctl reload nginx"
```

### Emergency Maintenance Mode

Add to system nginx config before other locations:

```nginx
location / {
    return 503;
}

error_page 503 @maintenance;
location @maintenance {
    root /var/www/html;
    rewrite ^(.*)$ /maintenance.html break;
}
```

## Useful One-liners

```bash
# Quick health check
ssh zumodra "docker ps | grep -c 'healthy' && curl -s -o /dev/null -w '%{http_code}' https://zumodra.rhematek-solutions.com/health/"

# Check all service ports
ssh zumodra "ss -tlnp | grep -E ':80 |:443 |:8002|:8003|:8084'"

# Count active connections
ssh zumodra "ss -tn | grep -E ':80 |:443' | wc -l"

# Find slow requests (response time > 1s)
ssh zumodra "awk '\$NF > 1.0' /var/log/nginx/access.log | tail -20"

# Check if nginx is proxying correctly
ssh zumodra "curl -H 'Host: demo-company.zumodra.rhematek-solutions.com' http://localhost:8002/ -I"
```

## Documentation Links

- Full Setup: `/root/zumodra/docs/NGINX_SETUP_DAY2.md`
- Architecture: `/root/zumodra/docs/NGINX_ARCHITECTURE.md`
- System Config: `/etc/nginx/sites-available/zumodra`
- Docker Config: `/root/zumodra/docker/nginx-sites/zumodra.rhematek.conf`

## Support Contacts

- System Administrator: root@zumodra
- Server: ssh zumodra (147.93.47.35)
- Domain: zumodra.rhematek-solutions.com
- Wildcard SSL: *.zumodra.rhematek-solutions.com

---

**Last Updated:** 2026-01-16
**Version:** 1.0
**Status:** Production Ready
