# Core App TODO

**Last Updated:** 2026-01-16
**Total Items:** 1
**Status:** Production

## Overview
The core app provides foundational utilities, middleware, authentication, caching, domain management, validators, and shared components used across all Zumodra apps.

## Low Priority

### [TODO-CORE-001] Sync Service Abstract Methods
- **Priority:** Low
- **Category:** Architecture (By Design)
- **Status:** Not Started (Expected Behavior)
- **Effort:** N/A
- **File:** `core/sync/base.py:77-84`
- **Description:**
  The `BaseSyncService.__init__()` raises `NotImplementedError` if subclasses don't define `public_model`, `tenant_model`, or `field_mapping`. This is intentional abstract base class behavior.
- **Context:**
  `BaseSyncService` is an abstract base class for syncing data between public schema and tenant schemas. Subclasses must implement required attributes. The `NotImplementedError` exceptions enforce this contract.
- **Resolution:**
  - This is working as designed - no action needed
  - The exceptions ensure subclasses provide required configuration
  - Prevents runtime errors from missing configuration
- **Possible Enhancement:**
  - [ ] Inherit from `abc.ABC` for explicit abstract class declaration
  - [ ] Convert `public_model`, `tenant_model`, `field_mapping` to `@abstractmethod` decorated properties
  - [ ] Add type hints: `public_model: Type[Model]`, etc.
  - [ ] Update docstring with examples of concrete implementations
  - [ ] Document sync service pattern in core/sync/README.md
  - [ ] Add validation tests for abstract enforcement
- **Dependencies:**
  - None
- **Notes:**
  - Lines 74-84 in sync/base.py
  - Not a bug - architectural pattern for enforcing subclass contracts
  - Similar pattern used in Django's generic views
  - Low priority since current implementation is correct and functional
  - Explicit ABC would make intent clearer to new developers

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-CORE-XXX]` and update the central [TODO.md](../TODO.md) index.
