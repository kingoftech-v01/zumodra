# Zumodra Documentation

## 📁 Documentation Structure

### 🚀 Deployment
- [Deployment Summary](deployment/DEPLOYMENT_SUMMARY.md) - Complete deployment guide with all recent fixes
- [Migration Fix Guide](deployment/MIGRATION_FIX_README.md) - Troubleshooting for migration issues
- [Migration Status](deployment/MIGRATION_STATUS.md) - Current migration status report
- [Production Rebuild](deployment/PRODUCTION_CLEAN_REBUILD.md) - Clean rebuild instructions
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - General deployment guide
- [Server Update Guide](SERVER_UPDATE_GUIDE.md) - Server update procedures

### 🏗️ Architecture
- [Multi-Tenancy Logic](architecture/SAAS_MULTI_TENANCY_LOGIC.md) - SaaS multi-tenancy architecture
- [Domain Model](domain_model.md) - Data model and relationships
- [Features](FEATURES.md) - Platform features documentation

### 🔐 Security
- [Security Documentation](SECURITY.md) - Security policies and procedures
- [Security Details](security/) - Additional security documentation

### 🔧 Development
- [API Documentation](API_DOCUMENTATION.md) - REST API reference
- [Components](components.md) - Frontend component library
- [Design System Audit](design_system_audit.md) - Design system documentation
- [Verification](verification.md) - Testing and verification procedures

### 📋 Operations
- [QA Scenarios](QA_SCENARIOS.md) - Quality assurance test scenarios
- [Tenant Onboarding](TENANT_ONBOARDING.md) - Tenant setup and onboarding

## 🎯 Quick Links

### For Developers
- Start here: [README.md](../README.md)
- Project instructions: [CLAUDE.md](../CLAUDE.md)
- Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md)

### For Deployment
1. Read [Deployment Summary](deployment/DEPLOYMENT_SUMMARY.md)
2. If migration issues: [Migration Fix Guide](deployment/MIGRATION_FIX_README.md)
3. For production: [Production Rebuild](deployment/PRODUCTION_CLEAN_REBUILD.md)

### For Operations
1. New tenant: [Tenant Onboarding](TENANT_ONBOARDING.md)
2. Updates: [Server Update Guide](SERVER_UPDATE_GUIDE.md)
3. Testing: [QA Scenarios](QA_SCENARIOS.md)

## 🛠️ Tools & Scripts

### Verification
```bash
# Check migration status
python3 ../verify_all_migrations.py

# Run deployment script
bash ../deploy_migration_fix.sh
```

### Development
```bash
# Start services
docker compose up -d

# Run tests
pytest

# Create migrations
python manage.py makemigrations
```

## 📝 Maintenance

Documentation should be updated when:
- Adding new features
- Changing deployment procedures
- Updating architecture
- Fixing critical issues

---

**Last Updated:** 2026-01-11
