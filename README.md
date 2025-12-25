# Zumodra - Multi-Tenant CRM & Freelance Services Marketplace

**A comprehensive Django-based platform combining CRM functionality with a freelance services marketplace, appointment booking, and content management.**

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# 1. Clone and navigate to project
cd zumodra

# 2. Copy environment file and configure
cp .env.example .env
# Edit .env with your credentials

# 3. Build and start all services
docker-compose up --build

# 4. Run migrations (in another terminal)
docker-compose exec web python manage.py migrate

# 5. Create superuser
docker-compose exec web python manage.py createsuperuser

# 6. Access application
# - Application: http://localhost:8000
# - Admin Panel: http://localhost:8000/admin-panel/
# - Nginx Proxy: http://localhost:80
```

### Option 2: Local Development

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up environment
cp .env.example .env
# Edit .env with your credentials

# 3. Run migrations
python manage.py migrate

# 4. Create superuser
python manage.py createsuperuser

# 5. Collect static files
python manage.py collectstatic

# 6. Run development server
python manage.py runserver

# 7. Run Celery (in separate terminals)
celery -A zumodra worker --loglevel=info
celery -A zumodra beat --loglevel=info
```

---

## 📋 Features

### Core Features ✅
- **Appointment Booking System** - Full-featured booking with Stripe payments
- **Finance Management** - Payments, subscriptions, escrow, refunds
- **Real-time Messaging** - Chat system with file uploads and typing indicators
- **Email Marketing** - Newsletter campaigns with analytics
- **Security** - 2FA, audit logging, brute force protection, honeypot
- **Content Management** - Wagtail CMS for blog and landing pages

### In Development ⚠️
- **Service Marketplace** - Freelance services platform (models complete, views needed)
- **Dashboard** - Analytics and metrics (templates ready, logic needed)
- **Multi-language Support** - i18n configured for 9 languages

---

## 🏗️ Technology Stack

**Backend:**
- Django 5.2.7 with Python 3.x
- PostgreSQL 16 with PostGIS
- Django REST Framework
- Celery 5.5.3 + Redis
- Django Channels (WebSockets)

**Authentication:**
- Django Allauth (email + social)
- 2FA with django-allauth-2fa
- django-otp

**Infrastructure:**
- Docker + Docker Compose
- Gunicorn (WSGI)
- Nginx (reverse proxy)
- Redis (cache, Celery, Channels)
- Whitenoise (static files)

**CMS & Content:**
- Wagtail 7.1.2
- TinyMCE editor
- Multilingual via wagtail-localize

**Payments:**
- Stripe integration

---

## 📁 Project Structure

```
zumodra/
├── appointment/          # ✅ Appointment booking system
├── finance/             # ✅ Payment processing
├── messages_sys/        # ✅ Real-time chat
├── newsletter/          # ✅ Email campaigns
├── security/            # ✅ Audit & security logging
├── blog/                # ⚠️ Wagtail CMS blog
├── services/            # ⚠️ Freelance marketplace (needs work)
├── dashboard/           # ⚠️ Analytics dashboard (needs work)
├── custom_account_u/    # ✅ Custom user model
├── configurations/      # Global settings
├── main/                # Core models
├── docker/              # Docker configurations
│   └── nginx/          # Nginx config
├── zumodra/             # Django project settings
│   ├── settings.py     # Main settings
│   ├── celery.py       # Celery configuration
│   └── urls.py         # URL routing
├── templates/           # Global templates
├── staticfiles/         # Static source files
├── media/              # User uploads
└── locale/             # Translations
```

---

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=True

# Database
DB_NAME=zumodra
DB_USER=postgres
DB_PASSWORD=your-password
DB_HOST=localhost
DB_PORT=5433

# Email
EMAIL_HOST_PASSWORD=your-email-password

# Stripe
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLIC_KEY=pk_test_...
```

### Services (Docker)

The project includes the following Docker services:

- **db** - PostgreSQL with PostGIS
- **redis** - Redis for caching and Celery
- **web** - Django application
- **celery_worker** - Background task processor
- **celery_beat** - Scheduled tasks
- **nginx** - Reverse proxy

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [SETUP_SUMMARY.md](SETUP_SUMMARY.md) | Quick setup guide and current status |
| [PROJECT_PLAN.md](PROJECT_PLAN.md) | Comprehensive project plan and roadmap |
| [BUGS_AND_FIXES.md](BUGS_AND_FIXES.md) | Known issues and how to fix them |
| [APPS_TO_DELETE.txt](APPS_TO_DELETE.txt) | Unnecessary apps to remove |
| [CLAUDE.md](CLAUDE.md) | Original planning document (French) |

---

## 🐛 Known Issues

### Critical
1. **Blog app** - Model/View mismatch (Wagtail models, Django views)
2. **Services app** - 99% incomplete (models done, views needed)
3. **Dashboard** - Template-only views (no backend logic)

See [BUGS_AND_FIXES.md](BUGS_AND_FIXES.md) for complete list and fixes.

---

## 🚀 Development Roadmap

### Phase 1: Foundation (Weeks 1-3)
- [x] Fix hardcoded secrets
- [x] Configure Celery
- [x] Set up Nginx
- [x] Update Docker Compose
- [ ] Delete empty apps
- [ ] Fix blog architecture

### Phase 2: Core Features (Weeks 4-7)
- [ ] Implement services marketplace views
- [ ] Add dashboard backend logic
- [ ] Consolidate newsletter apps
- [ ] Create API endpoints

### Phase 3: Enhancement (Weeks 8-12)
- [ ] Configure Wagtail CMS properly
- [ ] Set up multilingual support
- [ ] Payment enhancements
- [ ] Messaging upgrades

### Phase 4: Production (Weeks 13-15)
- [ ] Testing & optimization
- [ ] Security audit
- [ ] Deployment setup
- [ ] Monitoring configuration

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for detailed roadmap.

---

## 🌍 Supported Languages

- English (en)
- Spanish (es)
- French (fr)
- German (de)
- Italian (it)
- Portuguese (pt)
- Russian (ru)
- Simplified Chinese (zh-hans)
- Traditional Chinese (zh-hant)

---

## 🧪 Testing

```bash
# Run tests
python manage.py test

# Check for issues
python manage.py check

# Check deployment readiness
python manage.py check --deploy
```

---

## 📦 Database

The project uses PostgreSQL with PostGIS extension for geospatial features.

```bash
# Backup database
docker-compose exec db pg_dump -U postgres zumodra > backup.sql

# Restore database
docker-compose exec -T db psql -U postgres zumodra < backup.sql
```

---

## 🔐 Security Features

- **2FA Required** - All users must enable two-factor authentication
- **Django Axes** - Brute force protection
- **Admin Honeypot** - Fake admin panel to trap attackers
- **CSP Headers** - Content Security Policy
- **Audit Logging** - Complete audit trail with django-auditlog
- **SSL Ready** - HTTPS configuration for production

---

## 📧 Contact & Support

- **Admin Panel:** `/admin-panel/`
- **Wagtail CMS:** `/cms/`
- **API Docs:** `/api/docs/` (when implemented)

---

## ⚠️ Important Notes

1. **Never commit `.env` file** - Contains sensitive credentials
2. **Backup before major changes** - Especially before deleting apps
3. **Test in development first** - Don't deploy untested code
4. **Services app is critical** - Core marketplace functionality needs completion
5. **Multi-tenancy disabled** - Can be enabled via django-tenants if needed

---

## 🤝 Contributing

1. Create feature branch
2. Make changes
3. Test thoroughly
4. Submit pull request

---

## 📄 License

[Your License Here]

---

## 🎯 Project Goals

**Short-term:**
- Fix critical bugs
- Complete services marketplace
- Deploy to production

**Long-term:**
- Mobile app (React Native/Flutter)
- AI-powered service matching
- Advanced analytics
- Multi-currency support

---

**Status:** In Active Development
**Last Updated:** December 25, 2025

For detailed setup instructions, see [SETUP_SUMMARY.md](SETUP_SUMMARY.md)
