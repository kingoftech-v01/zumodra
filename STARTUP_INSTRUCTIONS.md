# 🚀 Zumodra - Quick Startup Instructions

**Last Updated:** December 25, 2025

---

## ✅ What Was Completed

### 1. Critical Bugs Fixed
- ✅ Removed hardcoded secrets from settings.py
- ✅ Fixed SSL settings (conditional on DEBUG mode)
- ✅ Created `.env.example` file
- ✅ Blog app fixed to use Wagtail properly (removed old Django model references)
- ✅ Wagtail URLs added to main `urls.py`

### 2. Infrastructure Setup
- ✅ Celery configuration created ([zumodra/celery.py](zumodra/celery.py))
- ✅ Nginx configuration created ([docker/nginx/](docker/nginx/))
- ✅ Docker Compose updated with all services

### 3. Apps Cleaned Up
- ✅ Deleted 5 empty apps (jobs, projects, dashboard_alert, dashboard_job, dashboard_project)
- ✅ Removed deleted apps from `INSTALLED_APPS`

### 4. Public Website Ready
- ✅ Created simplified public header ([templates/header_public.html](templates/header_public.html))
- ✅ Updated homepage to use public header
- ✅ Hidden internal features from public navigation (dashboard, appointments, messages moved to `/app/` prefix)

---

## 🏃 Quick Start

### Step 1: Install Dependencies

```bash
# Activate your virtual environment first
# For Windows:
.venv\Scripts\activate

# For Linux/Mac:
source .venv/bin/activate

# Install all requirements
pip install -r requirements.txt
```

**Note:** The requirements.txt includes celery==5.5.3, so this will install it.

### Step 2: Set Up Database

```bash
# Make sure PostgreSQL is running on port 5433
# Check your .env file for correct database credentials

# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

### Step 3: Create Superuser

```bash
python manage.py createsuperuser
```

### Step 4: Create Wagtail Homepage

```bash
# Run Django shell
python manage.py shell
```

Then run these commands in the shell:

```python
from wagtail.models import Page, Site
from blog.models import BlogIndexPage

# Get the root page
root = Page.objects.get(id=1)

# Create a homepage (you'll need to create a HomePage model first, or use BlogIndexPage as homepage)
# For now, let's create a Blog Index as the homepage
blog_index = BlogIndexPage(
    title="Zumodra Blog",
    slug="blog",
    intro="Welcome to our blog"
)
root.add_child(instance=blog_index)
blog_index.save_revision().publish()

# Set up the site to use this page
site = Site.objects.first()
# Note: You may want to create a proper HomePage model later

print("Blog page created!")
exit()
```

### Step 5: Collect Static Files

```bash
python manage.py collectstatic --noinput
```

### Step 6: Run Development Server

```bash
python manage.py runserver
```

Visit: http://localhost:8000

---

## 🎯 Access Points

### Public Access (No Authentication Required)
- **Homepage:** http://localhost:8000/
- **About:** http://localhost:8000/about/
- **Privacy:** http://localhost:8000/privacy/
- **Terms:** http://localhost:8000/terms/
- **Sign Up:** http://localhost:8000/accounts/signup/
- **Sign In:** http://localhost:8000/accounts/login/

### Admin Access (Requires Authentication)
- **Django Admin:** http://localhost:8000/admin-panel/
- **Wagtail CMS:** http://localhost:8000/cms/
- **Fake Admin (Honeypot):** http://localhost:8000/admin/

### Internal Features (Hidden from Public, Authentication Required)
- **Dashboard:** http://localhost:8000/app/dashboard/
- **Appointments:** http://localhost:8000/app/appointment/
- **Messages:** http://localhost:8000/app/messages/

---

## 🐳 Docker Deployment (Optional)

```bash
# Build and start all services
docker-compose up --build

# Run migrations in container
docker-compose exec web python manage.py migrate

# Create superuser in container
docker-compose exec web python manage.py createsuperuser

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput
```

Access via:
- **Nginx:** http://localhost:80
- **Direct Django:** http://localhost:8000

---

## 📝 Next Steps

### Immediate Tasks

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Migrations**
   ```bash
   python manage.py migrate
   ```

3. **Create Superuser**
   ```bash
   python manage.py createsuperuser
   ```

4. **Access Wagtail CMS**
   - Go to http://localhost:8000/cms/
   - Create pages via the Wagtail admin

5. **Create Your First Blog Post**
   - Login to Wagtail CMS
   - Create a BlogPostPage under the Blog Index
   - Publish it

### Content Creation

#### Creating a Proper Homepage (Recommended)

You should create a dedicated HomePage model:

```python
# In blog/models.py or create a new app 'pages'

from wagtail.models import Page
from wagtail.fields import RichTextField
from wagtail.admin.panels import FieldPanel

class HomePage(Page):
    hero_title = models.CharField(max_length=200, default="Welcome to Zumodra")
    hero_subtitle = models.TextField(blank=True)
    body = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel('hero_title'),
        FieldPanel('hero_subtitle'),
        FieldPanel('body'),
    ]

    template = "pages/home_page.html"
```

Then:
1. Run `python manage.py makemigrations`
2. Run `python manage.py migrate`
3. Create homepage via Wagtail CMS at http://localhost:8000/cms/

#### Creating Blog Content

1. Login to Wagtail CMS: http://localhost:8000/cms/
2. Navigate to Pages
3. Create BlogPostPage instances
4. Add featured images, content, tags
5. Publish

---

## 🔧 Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'celery'`
**Solution:** Install requirements
```bash
pip install -r requirements.txt
```

### Issue: `ModuleNotFoundError: No module named 'django_otp'`
**Solution:** Install requirements
```bash
pip install -r requirements.txt
```

### Issue: Database Connection Error
**Solution:** Check `.env` file:
```env
DB_PASSWORD=your-actual-password
DB_HOST=localhost
DB_PORT=5433
```

Make sure PostgreSQL is running.

### Issue: Static Files Not Loading
**Solution:**
```bash
python manage.py collectstatic --noinput
```

### Issue: Can't Access Wagtail Pages
**Solution:** You need to create pages in Wagtail CMS first:
1. Go to http://localhost:8000/cms/
2. Login with superuser
3. Create pages

---

## 📚 Important Files Modified

| File | Change |
|------|--------|
| [zumodra/settings.py](zumodra/settings.py) | Environment variables, SSL conditional |
| [zumodra/urls.py](zumodra/urls.py) | Wagtail URLs added, internal features hidden |
| [blog/views.py](blog/views.py) | Fixed to use Wagtail models |
| [blog/urls.py](blog/urls.py) | Simplified for Wagtail |
| [templates/header_public.html](templates/header_public.html) | New public header |
| [templates/index.html](templates/index.html) | Uses public header |
| [zumodra/celery.py](zumodra/celery.py) | Celery configuration |
| [zumodra/__init__.py](zumodra/__init__.py) | Conditional Celery import |
| [docker/nginx/nginx.conf](docker/nginx/nginx.conf) | Nginx config |
| [compose.yaml](compose.yaml) | All services configured |

---

## 🎨 Customization

### Changing Homepage Content

Edit [templates/index.html](templates/index.html):
- Line 21-22: Hero title and subtitle
- Search form can be disabled if you want

### Adding More Public Pages

1. Create views in `zumodra/views.py`
2. Add templates in `templates/`
3. Add URLs in `zumodra/urls.py` under "Public pages" section

### Hiding More Features

In `zumodra/urls.py`, move URLs under the "Internal features" section and prefix with `app/`

---

## 🚨 Security Reminders

1. **Never commit `.env` file** - Contains secrets
2. **Change SECRET_KEY in production** - Generate new one
3. **Set DEBUG=False in production** - In `.env` file
4. **Enable SSL in production** - Uncomment nginx HTTPS configuration
5. **Update ALLOWED_HOSTS** - Add your domain

---

## 📖 Documentation Reference

- [PROJECT_PLAN.md](PROJECT_PLAN.md) - Full project plan
- [BUGS_AND_FIXES.md](BUGS_AND_FIXES.md) - Known bugs and fixes
- [SETUP_SUMMARY.md](SETUP_SUMMARY.md) - Detailed setup summary
- [README.md](README.md) - Project README

---

## ✨ You're Ready!

Your Zumodra platform is now configured with:
- ✅ Secure environment variables
- ✅ Wagtail CMS for blog and pages
- ✅ Public-facing website with clean navigation
- ✅ Internal features hidden but accessible to authenticated users
- ✅ Docker deployment ready
- ✅ Celery for background tasks
- ✅ Nginx for production

**Next:** Install dependencies and run migrations to get started!

```bash
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Visit http://localhost:8000 and you're live! 🎉
