# Contributing to Zumodra

Thank you for considering contributing to Zumodra! This document outlines the process and guidelines for contributing.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Making Changes](#making-changes)
5. [Code Standards](#code-standards)
6. [Testing](#testing)
7. [Submitting Changes](#submitting-changes)
8. [Security Issues](#security-issues)

---

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment
- Report unacceptable behavior to support@zumodra.com

---

## Getting Started

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Git

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR-USERNAME/zumodra.git
cd zumodra
git remote add upstream https://github.com/rhematek/zumodra.git
```

---

## Development Setup

### Using Docker (Recommended)

```bash
# Copy environment template
cp .env.example .env

# Start all services
docker compose up -d

# The entrypoint handles migrations and setup automatically

# Access the application
# Web: http://localhost:8002
# API Docs: http://localhost:8002/api/docs/
```

### Local Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or: .venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your database settings

# Run migrations
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant

# Start development server
python manage.py runserver
```

---

## Making Changes

### Branch Naming

Use descriptive branch names:

```bash
feature/add-user-export       # New features
fix/login-validation-error    # Bug fixes
docs/update-api-reference     # Documentation
refactor/simplify-auth-flow   # Refactoring
test/add-payment-tests        # Test additions
```

### Workflow

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** (see Code Standards below)

4. **Test your changes:**
   ```bash
   pytest
   ```

5. **Commit with clear messages:**
   ```bash
   git commit -m "feat: add user data export endpoint"
   ```

---

## Code Standards

### Python Style

- **Formatter:** Black (120 character line length)
- **Import sorting:** isort
- **Linting:** flake8, pylint

```bash
# Format code
black . --line-length 120

# Sort imports
isort .

# Run linters
flake8 .
pylint zumodra/
```

### Commit Message Format

Follow [Conventional Commits](https://conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(ats): add bulk candidate import
fix(auth): resolve 2FA token expiration
docs(api): update authentication examples
test(finance): add escrow payment tests
```

### Django Conventions

**Models:**
```python
class MyModel(TenantAwareModel):
    """
    Brief description of the model.

    Attributes:
        field_name: Description of field
    """
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'My Models'
```

**Views:**
```python
class MyViewSet(SecureTenantViewSet):
    """ViewSet for MyModel operations."""
    queryset = MyModel.objects.all()
    serializer_class = MyModelSerializer
    permission_classes = [IsAuthenticated, HasTenantAccess]
```

**Serializers:**
```python
class MyModelSerializer(serializers.ModelSerializer):
    """Serializer for MyModel."""

    class Meta:
        model = MyModel
        fields = ['id', 'name', 'created_at']
        read_only_fields = ['id', 'created_at']
```

### Multi-Tenant Safety

**Always scope queries to tenant:**
```python
# Good
queryset = MyModel.objects.filter(tenant=request.tenant)

# Bad - cross-tenant data leak!
queryset = MyModel.objects.all()
```

**Celery tasks must include tenant context:**
```python
@shared_task
def process_data(tenant_schema: str, data_id: int):
    with schema_context(tenant_schema):
        # Process within tenant context
        data = MyModel.objects.get(id=data_id)
```

### No External CDNs

All assets must be served locally. See [docs/SECURITY.md](docs/SECURITY.md) for details.

```html
<!-- Correct -->
<script src="{% static 'assets/js/vendor/alpine.min.js' %}"></script>

<!-- Wrong - Never do this -->
<script src="https://cdn.example.com/library.js"></script>
```

---

## Testing

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov

# Specific file
pytest tests/test_ats_flows.py

# By marker
pytest -m security
pytest -m integration
pytest -m workflow

# Fail fast (stop on first failure)
pytest -x
```

### Writing Tests

```python
import pytest
from django.test import TestCase

@pytest.mark.integration
class TestMyFeature(TestCase):
    """Tests for MyFeature."""

    def setUp(self):
        """Set up test fixtures."""
        self.user = UserFactory()
        self.tenant = TenantFactory()

    def test_feature_works(self):
        """Test that feature works correctly."""
        result = my_feature(self.user)
        assert result.status == 'success'

    def test_feature_handles_error(self):
        """Test error handling."""
        with pytest.raises(ValidationError):
            my_feature(None)
```

### Test Markers

- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.security` - Security tests
- `@pytest.mark.workflow` - End-to-end workflow tests
- `@pytest.mark.slow` - Slow tests (skipped by default)

### Coverage Requirements

- **Development:** 60% minimum
- **Production:** 80% minimum

---

## Submitting Changes

### Pull Request Process

1. **Ensure tests pass:**
   ```bash
   pytest
   ```

2. **Update documentation** if needed

3. **Push your branch:**
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create Pull Request** on GitHub with:
   - Clear title following commit message format
   - Description of changes
   - Related issue numbers (if any)
   - Screenshots (for UI changes)

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No secrets or credentials committed
- [ ] No external CDN dependencies added
- [ ] Multi-tenant isolation maintained
- [ ] Migrations included (if model changes)

### Review Process

1. Automated CI checks run
2. Code review by maintainers
3. Address feedback
4. Approval and merge

---

## Security Issues

**Do NOT open public issues for security vulnerabilities.**

Report security issues privately to: **security@rhematek-solutions.com**

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

See [docs/SECURITY.md](docs/SECURITY.md) for full security policy.

---

## Questions?

- **Documentation:** [docs/](docs/)
- **Issues:** GitHub Issues (for non-security bugs)
- **Email:** support@zumodra.com

---

Thank you for contributing to Zumodra!
