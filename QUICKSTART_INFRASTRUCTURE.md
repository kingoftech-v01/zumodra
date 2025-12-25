# 🚀 Quick Start: Infrastructure Setup

**Follow these steps to get the new infrastructure running**

---

## Step 1: Install Dependencies

```bash
# Install new packages
pip install djangorestframework djangorestframework-simplejwt django-filter django-cors-headers django-ratelimit

# Or use the additions file
pip install -r requirements_additions.txt
```

---

## Step 2: Run Migrations

```bash
# Create migrations for new apps
python manage.py makemigrations api notifications analytics

# Apply migrations
python manage.py migrate
```

---

## Step 3: Create Superuser (if not exists)

```bash
python manage.py createsuperuser
```

---

## Step 4: Start Development Server

```bash
python manage.py runserver
```

---

## Step 5: Test the API

### Visit Browsable API:
```
http://localhost:8000/api/
```

### Get JWT Token:

**Using curl:**
```bash
curl -X POST http://localhost:8000/api/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "your-email@example.com", "password": "yourpassword"}'
```

**Using Python:**
```python
import requests

response = requests.post('http://localhost:8000/api/auth/token/', json={
    'username': 'your-email@example.com',
    'password': 'yourpassword'
})

print(response.json())
# {'access': 'eyJ0eXAiOiJ...', 'refresh': 'eyJ0eXAiOiJ...'}
```

**Using Postman:**
- URL: `POST http://localhost:8000/api/auth/token/`
- Body (JSON):
  ```json
  {
    "username": "your-email@example.com",
    "password": "yourpassword"
  }
  ```

### Use Token to Access API:

```bash
# Get services
curl -X GET http://localhost:8000/api/services/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Create service (requires provider profile)
curl -X POST http://localhost:8000/api/services/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Web Development",
    "description": "Professional web dev",
    "price": 5000
  }'
```

---

## Step 6: Test Notifications

### Create Provider Profile First:
```
Visit: http://localhost:8000/services/provider/create/
Fill in the form and create a provider profile
```

### Create a Service:
```
Visit: http://localhost:8000/services/service/create/
Create a service
```

### Test Notifications:
```
Visit: http://localhost:8000/notifications/
You should see notifications from various actions
```

---

## Step 7: Test Analytics

### Provider Analytics:
```
Visit: http://localhost:8000/analytics/provider/
```

### Client Analytics:
```
Visit: http://localhost:8000/analytics/client/
```

### Admin Analytics:
```
Visit: http://localhost:8000/analytics/dashboard/
```

---

## 🎯 Available Endpoints

### API Root
- `http://localhost:8000/api/` - Browsable API

### Authentication
- `POST /api/auth/token/` - Get JWT tokens
- `POST /api/auth/token/refresh/` - Refresh token
- `POST /api/auth/token/verify/` - Verify token

### Services
- `GET /api/services/` - List all services
- `POST /api/services/` - Create service
- `GET /api/services/{uuid}/` - Service details
- `PUT /api/services/{uuid}/` - Update service
- `DELETE /api/services/{uuid}/` - Delete service

### Providers
- `GET /api/providers/` - List providers
- `POST /api/providers/` - Create provider
- `GET /api/providers/{uuid}/` - Provider details

### Notifications
- `GET /notifications/` - List notifications
- `POST /notifications/{id}/read/` - Mark as read
- `GET /notifications/api/count/` - Unread count

### Analytics
- `GET /analytics/dashboard/` - Main dashboard
- `GET /analytics/provider/` - Provider analytics
- `GET /analytics/client/` - Client analytics

---

## 🐛 Common Issues

### Issue: "ModuleNotFoundError: No module named 'rest_framework'"
**Solution:** Install dependencies
```bash
pip install djangorestframework
```

### Issue: "Table doesn't exist"
**Solution:** Run migrations
```bash
python manage.py migrate
```

### Issue: "401 Unauthorized" on API
**Solution:** Get a valid JWT token first
```bash
curl -X POST http://localhost:8000/api/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "your-email", "password": "yourpassword"}'
```

### Issue: "CORS error" from frontend
**Solution:** Add your frontend URL to `CORS_ALLOWED_ORIGINS` in settings.py

### Issue: "Rate limit exceeded"
**Solution:** Wait or increase rate limit in settings.py

---

## 📝 Next Steps

1. **Create Provider Profile**
   - Visit: `/services/provider/create/`

2. **Create Services**
   - Visit: `/services/service/create/`

3. **Test API with Postman**
   - Import endpoints
   - Test CRUD operations

4. **Integrate Frontend**
   - Use JWT tokens
   - Make API calls
   - Handle responses

5. **Monitor Analytics**
   - Check `/analytics/dashboard/`
   - View user actions
   - Track metrics

6. **Test Notifications**
   - Perform actions (create services, proposals, etc.)
   - Check `/notifications/`
   - See auto-notifications

---

## 🔒 Production Deployment

### 1. Update .env
```bash
DEBUG=False
ALLOWED_HOSTS=zumodra.com,www.zumodra.com
DOMAIN=zumodra.com
```

### 2. Setup SSL (Linux Server)
```bash
chmod +x scripts/setup_ssl.sh
sudo ./scripts/setup_ssl.sh
```

### 3. Collect Static Files
```bash
python manage.py collectstatic --noinput
```

### 4. Run with Gunicorn
```bash
gunicorn zumodra.wsgi:application --bind 0.0.0.0:8000
```

### 5. Start Nginx
```bash
sudo systemctl start nginx
sudo systemctl enable nginx
```

---

## ✅ Success Checklist

- [ ] Dependencies installed
- [ ] Migrations run
- [ ] Superuser created
- [ ] Server running
- [ ] API accessible at /api/
- [ ] JWT tokens working
- [ ] Can create services via API
- [ ] Notifications appearing
- [ ] Analytics dashboard accessible
- [ ] No errors in console

---

**You're all set! The infrastructure is ready to use! 🎉**

For detailed documentation, see [INFRASTRUCTURE_IMPLEMENTATION.md](INFRASTRUCTURE_IMPLEMENTATION.md)
