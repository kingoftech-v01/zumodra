# Quick Restart Guide - Copy & Paste Commands

## 🚀 Fast Restart (30 seconds)

### 1. SSH into server
```bash
ssh zumodra
```

### 2. Navigate to project
```bash
cd /var/www/zumodra  # Adjust path if needed
```

### 3. Pull latest code
```bash
git pull origin main
```

### 4. Restart everything
```bash
sudo systemctl restart zumodra-web zumodra-channels zumodra-celery nginx
```

### 5. Wait and check
```bash
sleep 5
sudo systemctl status zumodra-web
```

### 6. Test
```bash
curl http://localhost:8000/health/
```

**Expected**: Should return `200 OK` with JSON

---

## 🔍 If That Doesn't Work

### Check what's failing
```bash
# Check all services
sudo systemctl status zumodra-web zumodra-channels nginx

# Check logs
sudo journalctl -u zumodra-web -n 20 --no-pager
sudo tail -20 /var/log/zumodra/web.log
```

### Common fixes

#### Django won't start:
```bash
# Check for syntax errors
cd /var/www/zumodra
source venv/bin/activate
python manage.py check
```

#### Port already in use:
```bash
# Find process
sudo lsof -i :8000

# Kill it
sudo kill -9 <PID>

# Restart
sudo systemctl restart zumodra-web
```

#### Database connection:
```bash
# Restart PostgreSQL
sudo systemctl restart postgresql

# Test connection
psql -h localhost -U zumodra_user -d zumodra_db
```

---

## 🐳 Docker Version

### If using Docker Compose:
```bash
cd /var/www/zumodra
docker-compose down
docker-compose up -d
docker-compose logs -f web
```

---

## ✅ Final Verification

```bash
# From server
curl http://localhost:8000/health/  # Should return 200

# From your computer
curl https://zumodra.rhematek-solutions.com/health/  # Should return 200
```

If both return 200, you're done! ✅

---

## 🆘 Emergency Commands

### View real-time logs:
```bash
sudo journalctl -u zumodra-web -f
```

### Restart everything (nuclear option):
```bash
sudo systemctl restart zumodra-web zumodra-channels zumodra-celery nginx postgresql redis
```

### Rollback to previous version:
```bash
cd /var/www/zumodra
git reset --hard 0c67aa2  # Previous working commit
sudo systemctl restart zumodra-web zumodra-channels
```

---

**Need Help?** See [DEPLOYMENT_README.md](DEPLOYMENT_README.md) for full instructions.
