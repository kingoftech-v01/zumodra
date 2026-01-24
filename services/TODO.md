# Services TODO List

## Critical (HIGH Priority)

### Code Quality
- [ ] **CODE-001** - Add comprehensive docstrings to all public methods
  - **Why**: Improve code maintainability and IDE autocomplete
  - **Effort**: M
  - **Blocker**: No

### Testing
- [ ] **TEST-001** - Increase test coverage to ≥80%
  - **Why**: Current coverage may be below production threshold
  - **Effort**: L
  - **Blocker**: No

- [ ] **TEST-002** - Add integration tests for API endpoints
  - **Why**: Ensure API contracts are maintained
  - **Effort**: M
  - **Blocker**: No

### Security
- [ ] **SEC-001** - Review permissions for all ViewSets
  - **Why**: Ensure proper role-based access control
  - **Effort**: S
  - **Blocker**: No

---

## Important (MEDIUM Priority)

### Documentation
- [ ] **DOC-001** - Add API endpoint examples to README
  - **Why**: Better developer onboarding
  - **Effort**: S
  - **Blocker**: No

- [ ] **DOC-002** - Document all Celery tasks and schedules
  - **Why**: Clarity on async operations
  - **Effort**: S
  - **Blocker**: No

### Performance
- [ ] **PERF-001** - Add database indexes for frequently queried fields
  - **Why**: Improve query performance
  - **Effort**: M
  - **Blocker**: No

- [ ] **PERF-002** - Implement caching for read-heavy endpoints
  - **Why**: Reduce database load
  - **Effort**: M
  - **Blocker**: No

### Features
- [ ] **FEAT-001** - Implement bulk operations for admin
  - **Why**: Improve admin productivity
  - **Effort**: M
  - **Blocker**: No

---

## Nice to Have (LOW Priority)

### UI/UX
- [ ] **UI-001** - Add export to Excel functionality
  - **Why**: User-requested feature
  - **Effort**: S
  - **Blocker**: No

### Monitoring
- [ ] **MON-001** - Add custom metrics for app-specific operations
  - **Why**: Better observability
  - **Effort**: M
  - **Blocker**: No

---

## Technical Debt

### Refactoring
- [ ] **DEBT-001** - Extract common validation logic to mixins
  - **Why**: Reduce code duplication
  - **Effort**: M
  - **Blocker**: No

---

## Completed

- [x] **PHASE-001** - Create forms.py (Phase 12.3.1)
- [x] **PHASE-002** - Create permissions.py (Phase 12.3.2)
- [x] **PHASE-003** - Create tasks.py (Phase 12.3.3)
- [x] **PHASE-004** - Create signals.py (Phase 12.3.4)
- [x] **PHASE-005** - Create README.md (Phase 12.3.5)

---

**Last Updated**: 2026-01-18
**Total Items**: 14
**Completed**: 5
**In Progress**: 0
**Pending**: 9

---

**Effort Estimates**:
- S (Small): < 4 hours
- M (Medium): 4-16 hours
- L (Large): 16-40 hours
- XL (Extra Large): > 40 hours
