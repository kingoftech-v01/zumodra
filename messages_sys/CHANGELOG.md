# Messages System App Changelog

## [2026-01-15] - Fail-Hard Migration Enforcement (Phase 5)

### Added
- `messages_sys/signals.py` (NEW): Signal handlers for auto-creating UserStatus
  - `create_user_status_on_user_creation()`: Automatically creates UserStatus when new user is created
  - `ensure_userstatus_exists()`: Ensures UserStatus exists before any messaging operation
  - Connected to `post_save` signal on CustomUser model

- `messages_sys/management/commands/create_user_statuses.py` (NEW): Backfill command
  - Creates UserStatus for all existing users across all tenants
  - Handles schema context switching for multi-tenant support
  - Idempotent - safe to run multiple times

### Changed
- `messages_sys/views.py` (Lines 28-34): Updated to use get_or_create pattern
  - Changed from `.filter().first()` to `.get_or_create()`
  - Prevents race conditions when multiple requests arrive simultaneously
  - More robust error handling

- `messages_sys/apps.py`: Registered signals in `ready()` method
  - Ensures signal handlers are connected at application startup
  - Follows Django best practices for signal registration

### Fixed
- **CRITICAL**: Fixed "relation 'messages_sys_userstatus' does not exist" error
  - Root cause: Migrations not applied to tenant schemas
  - Now handled automatically through signal handlers and tenant migration enforcement
  - All new users automatically get UserStatus record
  - Backfill command available for existing users

### Testing
Run backfill command to ensure all existing users have UserStatus:
```bash
python manage.py create_user_statuses
```

Check for missing UserStatus records:
```bash
python manage.py shell
from custom_account_u.models import CustomUser
from messages_sys.models import UserStatus
users_without_status = CustomUser.objects.exclude(
    id__in=UserStatus.objects.values_list('user_id', flat=True)
).count()
print(f"Users without UserStatus: {users_without_status}")
```

---

## [Earlier Changes]

### Real-Time Messaging Features
- WebSocket-based real-time chat using Django Channels
- Redis channel layer for message passing
- User online/offline status tracking
- Typing indicators
- Message read receipts
- Message threading and replies
- File attachments support
- Emoji reactions
- Message search and filtering
- User blocking/muting
- Group conversations
- Direct messages (1-on-1)
- Message notifications
- Message history and pagination
