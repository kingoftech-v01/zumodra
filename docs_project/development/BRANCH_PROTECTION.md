# Branch Protection Rules for Main Branch

This document outlines the recommended branch protection rules for the Zumodra project to ensure code quality and prevent accidental pushes to production.

## GitHub Settings > Branches > Branch Protection Rules

### Required Status Checks

Configure these settings to ensure CI/CD passes before merging:

- ✓ **Require status checks to pass before merging**
- ✓ **Require branches to be up to date before merging**

**Required checks that must pass:**
- `lint` - Code quality checks (flake8, black, isort, pylint)
- `security` - Security scanning (bandit, safety, pip-audit)
- `test (3.11)` - Python 3.11 test suite with 60% coverage minimum
- `test (3.12)` - Python 3.12 test suite with 60% coverage minimum
- `build` - Docker image build and vulnerability scanning

### Merge Requirements

Enforce code review and collaboration:

- ✓ **Require pull request reviews before merging**
  - Minimum number of approvals: **1**
  - Dismiss stale pull request approvals when new commits are pushed
  - Require review from Code Owners (if CODEOWNERS file exists)

- ✓ **Require conversation resolution before merging**
  - All review comments must be resolved

- ✓ **Require linear history** (optional but recommended)
  - Enforces rebase workflow
  - Prevents merge commits in history

### Additional Restrictions

- ✓ **Do not allow bypassing the above settings**
  - Includes administrators
  - No one can push directly to main without passing checks

- ✓ **Require signed commits** (recommended for production)
  - Ensures commit authenticity
  - All commits must be GPG signed

- ✓ **Lock branch to read-only** (optional for releases)
  - Prevent any changes after release is cut

### Rules Applied To

- **Branch name pattern:** `main`
- **Additional patterns:** `release/*`, `hotfix/*` (optional)

## Development Workflow

With these protections in place, the development workflow is:

1. **Create feature branch** from `main`
   ```bash
   git checkout main
   git pull --rebase
   git checkout -b feature/my-feature
   ```

2. **Make changes and commit**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

3. **Push to remote**
   ```bash
   git push origin feature/my-feature
   ```

4. **Create Pull Request** on GitHub
   - CI/CD automatically runs (lint, security, test, build)
   - Request review from team member
   - Address any review comments

5. **Merge when approved**
   - All CI checks must pass (green)
   - At least 1 approval required
   - All conversations resolved
   - Branch is up to date with main

6. **Automatic deployment** (if configured)
   - Main branch triggers production deployment
   - Develop branch triggers staging deployment

## CI/CD Quality Gates

The CI/CD pipeline enforces these quality gates:

### Test Coverage
- **Minimum coverage:** 60% (development)
- **Target coverage:** 80% (production)
- **Coverage report:** Uploaded to Codecov on every run

### Code Quality
- **Formatting:** Black (120 char line length)
- **Import sorting:** isort (black-compatible profile)
- **Linting:** Flake8 + Pylint
- **Max complexity:** 15 (McCabe)

### Security
- **Dependency scanning:** safety, pip-audit
- **Code scanning:** bandit (Python security linter)
- **Secret scanning:** TruffleHog (verified secrets only)
- **Container scanning:** Trivy (CRITICAL and HIGH vulnerabilities)

### Database
- **PostgreSQL version:** 15 with PostGIS 3.4
- **Migrations:** Must be reversible and tested
- **Tenant isolation:** Schema-based multi-tenancy validated

## Emergency Procedures

### Hotfix Process

If production has a critical bug:

1. **Create hotfix branch from main**
   ```bash
   git checkout main
   git pull --rebase
   git checkout -b hotfix/critical-bug-fix
   ```

2. **Apply fix and test locally**
   ```bash
   # Make fix
   pytest --cov --cov-fail-under=60
   ```

3. **Create PR with "hotfix" label**
   - Request expedited review
   - CI must still pass
   - Minimum 1 approval still required

4. **Merge and deploy**
   - Merge to main triggers production deployment
   - Monitor logs and health checks

### Bypassing Protections (Emergency Only)

If you absolutely must bypass branch protection (e.g., GitHub Actions is down):

1. **Temporarily disable branch protection**
   - GitHub Settings > Branches > Edit main protection
   - Uncheck "Do not allow bypassing the above settings"

2. **Make critical change**
   ```bash
   git checkout main
   git pull --rebase
   # Make fix
   git commit -m "hotfix: critical production fix (bypassed CI)"
   git push origin main
   ```

3. **Immediately re-enable branch protection**

4. **Document the incident**
   - Create issue explaining why bypass was necessary
   - Add tests to prevent recurrence
   - Review and improve CI/CD reliability

## Monitoring Branch Protection

Check compliance regularly:

```bash
# View branch protection status
gh api repos/:owner/:repo/branches/main/protection

# Check recent pushes to main
git log --oneline --graph main --since="1 week ago"

# Verify all commits have passed CI
gh run list --branch main --limit 20
```

## Related Documentation

- [CI/CD Pipeline](.github/workflows/ci.yml) - Full CI/CD configuration
- [CLAUDE.md](../../CLAUDE.md) - Development commands and workflow
- [MIGRATION_FIX_README.md](../deployment/MIGRATION_FIX_README.md) - Database migration guide

## Questions or Issues?

If you encounter issues with branch protection or CI/CD:

1. Check [GitHub Actions runs](https://github.com/kingoftech-v01/zumodra/actions)
2. Review CI/CD logs for specific failures
3. Ensure local tests pass before pushing
4. Contact team lead for branch protection adjustments

**Last Updated:** January 15, 2026
