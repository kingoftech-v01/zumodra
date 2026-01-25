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

---

## Provider Marketplace Frontend (NEW - 2026-01-24)

**Context**: The `services_public` app now has a functional public marketplace. The `services` app needs a provider-facing frontend for managing services that appear on the marketplace. This frontend is SEPARATE from the public catalog and focuses on service management.

### Critical - Marketplace Integration (HIGH Priority)

#### Service Management UI
- [ ] **MARKET-001** - Add "Publish to Marketplace" toggle in service form
  - **Why**: Providers need intuitive way to control `is_public` flag
  - **Details**: Visual toggle with confirmation modal, sync status indicator
  - **Effort**: S
  - **Blocker**: No

- [ ] **MARKET-002** - Service creation wizard (multi-step form)
  - **Why**: Simplify complex service creation process
  - **Details**: Steps: Basic Info → Pricing → Media → Settings → Preview
  - **Effort**: L
  - **Blocker**: No

- [ ] **MARKET-003** - Service editor with rich text (WYSIWYG)
  - **Why**: Better content creation experience
  - **Details**: HTML editor with preview, image upload, auto-save
  - **Effort**: M
  - **Blocker**: No

#### Pricing Tier Management
- [ ] **MARKET-004** - Pricing tier CRUD interface
  - **Why**: Required for marketplace display (not yet implemented in frontend)
  - **Details**: Add/edit/delete tiers, drag-drop reorder, duplicate tier
  - **Effort**: M
  - **Blocker**: No

- [ ] **MARKET-005** - Pricing tier validation
  - **Why**: Ensure data quality before marketplace sync
  - **Details**: Min 1 tier, max 5 tiers, price ordering, required fields
  - **Effort**: S
  - **Blocker**: No

#### Portfolio Management
- [ ] **MARKET-006** - Portfolio gallery interface
  - **Why**: Required for marketplace display (not yet implemented in frontend)
  - **Details**: Upload images, drag-drop reorder, alt text, grid layout config
  - **Effort**: M
  - **Blocker**: No

### Important - Analytics & Notifications (MEDIUM Priority)

#### Dashboard & Analytics
- [ ] **MARKET-007** - Provider dashboard with marketplace stats
  - **Why**: Providers need visibility into marketplace performance
  - **Details**: Views, bookings, conversion rate, top services
  - **Effort**: L
  - **Blocker**: No

- [ ] **MARKET-008** - Performance analytics charts
  - **Why**: Help providers optimize services
  - **Details**: Views over time, geographic distribution, conversion funnel
  - **Effort**: M
  - **Blocker**: No

#### Notifications
- [ ] **MARKET-009** - Sync status notifications
  - **Why**: Inform providers about publish/sync success/failure
  - **Details**: "Published to marketplace", "Sync failed", "Updated"
  - **Effort**: S
  - **Blocker**: No

- [ ] **MARKET-010** - Booking notifications from marketplace
  - **Why**: Alert providers about new opportunities
  - **Details**: New booking alert, referrer info, direct link
  - **Effort**: S
  - **Blocker**: No

### Nice to Have - Advanced Features (LOW Priority)

#### Optimization Tools
- [ ] **MARKET-011** - Marketplace preview
  - **Why**: Let providers see how service appears on public catalog
  - **Details**: Live preview, mobile/desktop toggle, real-time updates
  - **Effort**: M
  - **Blocker**: No

- [ ] **MARKET-012** - SEO score for service listings
  - **Why**: Help providers optimize for marketplace visibility
  - **Details**: Title/description analysis, keyword suggestions, readability score
  - **Effort**: M
  - **Blocker**: No

- [ ] **MARKET-013** - A/B testing for service listings
  - **Why**: Data-driven optimization
  - **Details**: Test variations, track performance, declare winner
  - **Effort**: L
  - **Blocker**: No

#### Collaboration
- [ ] **MARKET-014** - Team member management
  - **Why**: Allow teams to collaborate on services
  - **Details**: Invite members, role permissions, activity log
  - **Effort**: M
  - **Blocker**: No

- [ ] **MARKET-015** - Approval workflow for publishing
  - **Why**: Quality control for enterprise tenants
  - **Details**: Draft → Review → Publish, approver roles, comments
  - **Effort**: L
  - **Blocker**: No

#### Advanced Features
- [ ] **MARKET-016** - Service bundles
  - **Why**: Increase average order value
  - **Details**: Bundle multiple services, discounted pricing
  - **Effort**: L
  - **Blocker**: No

- [ ] **MARKET-017** - Availability calendar
  - **Why**: Manage service delivery schedule
  - **Details**: Set available dates, auto-update `is_accepting_work`
  - **Effort**: M
  - **Blocker**: No

- [ ] **MARKET-018** - Service templates
  - **Why**: Speed up service creation
  - **Details**: Save as template, quick-create from template
  - **Effort**: S
  - **Blocker**: No

### Testing & Documentation

#### Testing
- [ ] **MARKET-TEST-001** - Integration tests for publish workflow
  - **Why**: Ensure marketplace sync works end-to-end
  - **Details**: Create → Publish → Verify on public catalog
  - **Effort**: M
  - **Blocker**: No

- [ ] **MARKET-TEST-002** - E2E tests for service wizard
  - **Why**: Ensure user flows work correctly
  - **Details**: Selenium/Cypress tests for complete workflows
  - **Effort**: L
  - **Blocker**: No

#### Documentation
- [ ] **MARKET-DOC-001** - Provider user guide
  - **Why**: Help providers use marketplace features
  - **Details**: How to publish, optimize listings, manage pricing
  - **Effort**: M
  - **Blocker**: No

- [ ] **MARKET-DOC-002** - Video tutorials
  - **Why**: Visual learning for providers
  - **Details**: Service creation, portfolio management, analytics
  - **Effort**: L
  - **Blocker**: No

---

**Important Notes**:

1. **Automatic Sync Already Implemented**: Django signals + Celery tasks in `services/signals.py` and `services/tasks.py` automatically sync services when `is_public=True`. Frontend just needs to expose this functionality via UI.

2. **Separate Frontend Design**: The `services` app frontend should have its own professional, provider-focused design. Do NOT use the same styles as `services_public` (which is customer-facing).

3. **No Changes to services_public Templates**: The public catalog templates in `services_public/templates/` should NOT be modified. That app has its own separate design and functionality.

4. **Backend Already Complete**: The models `ServicePricingTier` and `ProviderPortfolio` exist in `services/models.py`. The sync logic exists in `core/sync/service_sync.py`. Only frontend UI is needed.

---

**Marketplace Integration Status**:

- [x] Backend models (ServicePricingTier, ProviderPortfolio)
- [x] Sync infrastructure (signals, tasks, ServicePublicSyncService)
- [x] Public catalog frontend (services_public app)
- [x] **API Layer (NEW - 2026-01-25)**
  - [x] services/serializers.py: Complete serializers for all models
  - [x] services/views_api.py: Tenant-aware ViewSets with custom actions
  - [x] services/filters.py: Comprehensive filtering for all endpoints
  - [x] services/urls.py: Unified frontend + API routing
  - [x] Renamed template_views.py → views_frontend.py (convention compliance)
- [ ] Provider frontend UI (THIS TODO LIST - focus on templates/forms)

---

**API Endpoints Available** (NEW - 2026-01-25):

All API endpoints are prefixed with `/services/api/`:

**Providers:**

- `GET/PUT/PATCH /api/providers/` - List/Update providers
- `GET /api/providers/me/` - Current user's provider profile
- `GET /api/providers/{uuid}/stats/` - Provider statistics

**Services:**

- `GET/POST /api/services/` - List/Create services
- `GET/PUT/PATCH/DELETE /api/services/{uuid}/` - Service CRUD
- `GET /api/services/my-services/` - Current user's services
- `POST /api/services/{uuid}/publish/` - Publish to marketplace
- `POST /api/services/{uuid}/unpublish/` - Remove from marketplace
- `POST /api/services/{uuid}/duplicate/` - Duplicate service

**Pricing & Portfolio:**

- `GET/POST /api/pricing-tiers/` - Pricing tier CRUD
- `GET/POST /api/portfolio/` - Portfolio item CRUD

**Contracts:**

- `GET/POST /api/contracts/` - Contract list/Create
- `GET /api/contracts/my-contracts/` - User's contracts
- `POST /api/contracts/{uuid}/deliver/` - Provider marks as delivered
- `POST /api/contracts/{uuid}/complete/` - Client marks as complete
- `POST /api/contracts/{uuid}/request-revision/` - Request revision

**Reviews:**

- `GET /api/reviews/` - List reviews
- `POST /api/reviews/{id}/respond/` - Provider responds to review

**Other:**

- `GET /api/categories/`, `GET /api/categories/tree/` - Categories
- `GET /api/tags/` - Tags
- `GET/POST /api/images/` - Service images
- `GET/POST /api/messages/` - Contract messages
- `GET/POST /api/cross-tenant-requests/` - Cross-tenant hiring

See `services/serializers.py`, `services/views_api.py`, and `services/filters.py` for implementation details.

---

**Last Updated**: 2026-01-25 (Added API layer completion status)
