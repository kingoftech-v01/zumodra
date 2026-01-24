"""
Remove FREELANCER Tenant Type from Codebase

This script removes all references to the FREELANCER tenant type after
successful migration of all FREELANCER tenants to FreelancerProfile.

MUST RUN AFTER: migrate_freelancer_tenants_to_profiles.py

PROCESS:
1. Verify no active FREELANCER tenants exist
2. Remove FREELANCER from TenantType choices
3. Update all validators/decorators checking tenant_type
4. Update all views/templates referencing FREELANCER
5. Create migration to update database constraints
6. Update documentation

SAFETY:
- Checks for active FREELANCER tenants before proceeding
- Dry-run mode available
- Generates backup of modified files
- Comprehensive logging

Usage:
    # Dry run (show what would be changed)
    python scripts/remove_freelancer_tenant_type.py --dry-run

    # Actual removal
    python scripts/remove_freelancer_tenant_type.py

    # Force removal (skip safety checks - DANGEROUS)
    python scripts/remove_freelancer_tenant_type.py --force
"""

import sys
import os
import logging
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple
import argparse

# Django setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

import django
django.setup()

from django.utils import timezone
from tenants.models import Tenant

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'remove_freelancer_type_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class FileModification:
    """Track file modifications."""

    def __init__(self, file_path: Path, description: str):
        self.file_path = file_path
        self.description = description
        self.original_content: str = ""
        self.modified_content: str = ""
        self.backup_path: Optional[Path] = None

    def backup(self):
        """Create backup of original file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = Path('backups') / 'freelancer_type_removal' / timestamp
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Preserve directory structure in backup
        relative_path = self.file_path.relative_to(Path('.'))
        self.backup_path = backup_dir / relative_path

        self.backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.file_path, self.backup_path)

        logger.info(f"Backed up {self.file_path} → {self.backup_path}")

    def apply(self):
        """Apply modifications to file."""
        self.file_path.write_text(self.modified_content)
        logger.info(f"✅ Modified {self.file_path}: {self.description}")


def check_active_freelancer_tenants() -> Tuple[bool, int]:
    """
    Check if any active FREELANCER tenants still exist.

    Returns:
        (is_safe, count_active_freelancers)
    """
    active_freelancers = Tenant.objects.filter(
        tenant_type='freelancer',
        status='active'
    )

    count = active_freelancers.count()

    if count > 0:
        logger.error(f"❌ Found {count} active FREELANCER tenants!")
        for tenant in active_freelancers:
            logger.error(f"   - Tenant {tenant.id}: {tenant.name} ({tenant.schema_name})")
        return False, count

    logger.info(f"✅ No active FREELANCER tenants found")
    return True, 0


def modify_tenant_model() -> FileModification:
    """
    Remove FREELANCER from TenantType choices in tenants/models.py
    """
    file_path = Path('tenants/models.py')
    original_content = file_path.read_text()

    # Find and modify TenantType class
    pattern = r'class TenantType\(models\.TextChoices\):.*?FREELANCER\s*=\s*[\'"]freelancer[\'"],\s*_\([\'"]Freelancer[\'"]\).*?\n'

    # Remove the FREELANCER line
    modified_content = re.sub(
        r"^\s*FREELANCER\s*=\s*'freelancer',\s*_\('Freelancer'\).*\n",
        "",
        original_content,
        flags=re.MULTILINE
    )

    # Also update any comments referencing FREELANCER
    modified_content = re.sub(
        r"# FREELANCER tenants.*\n",
        "# Individual freelancers are now FreelancerProfile user profiles (not tenants)\n",
        modified_content
    )

    mod = FileModification(file_path, "Removed FREELANCER from TenantType choices")
    mod.original_content = original_content
    mod.modified_content = modified_content

    return mod


def find_tenant_type_checks() -> List[Path]:
    """
    Find all files that check for tenant_type == 'freelancer'
    """
    patterns_to_search = [
        "tenant_type == 'freelancer'",
        'tenant_type == "freelancer"',
        "tenant.tenant_type == 'freelancer'",
        'tenant.tenant_type == "freelancer"',
        'TenantType.FREELANCER',
        '@require_tenant_type.*freelancer',
    ]

    files_to_check = []

    # Search Python files
    for py_file in Path('.').rglob('*.py'):
        if '.git' in str(py_file) or 'venv' in str(py_file) or '__pycache__' in str(py_file):
            continue

        content = py_file.read_text()

        for pattern in patterns_to_search:
            if pattern.lower() in content.lower():
                files_to_check.append(py_file)
                break

    return files_to_check


def modify_tenant_type_checks(file_path: Path) -> FileModification:
    """
    Remove or comment out checks for FREELANCER tenant type.
    """
    original_content = file_path.read_text()
    modified_content = original_content

    # Comment out checks for FREELANCER
    modified_content = re.sub(
        r"(\s*)(if\s+.*tenant_type\s*==\s*['\"]freelancer['\"].*:)",
        r"\1# REMOVED: FREELANCER tenant type deprecated\n\1# \2",
        modified_content,
        flags=re.IGNORECASE
    )

    # Comment out TenantType.FREELANCER references
    modified_content = re.sub(
        r"(\s*)(.*TenantType\.FREELANCER.*)",
        r"\1# REMOVED: FREELANCER tenant type deprecated\n\1# \2",
        modified_content
    )

    # Update @require_tenant_type decorators
    modified_content = re.sub(
        r"@require_tenant_type\(\['company',\s*'freelancer'\]\)",
        "@require_tenant_type(['company'])  # FREELANCER removed",
        modified_content
    )

    mod = FileModification(file_path, "Removed/commented FREELANCER type checks")
    mod.original_content = original_content
    mod.modified_content = modified_content

    return mod


def create_database_migration() -> str:
    """
    Generate Django migration to remove FREELANCER from database constraints.

    Returns:
        Path to migration file
    """
    migration_content = """# Generated by remove_freelancer_tenant_type.py

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0006_auto_previous_migration'),  # Update with actual latest migration
    ]

    operations = [
        # Remove FREELANCER choice from tenant_type field
        # Note: This doesn't affect data, only the constraint
        migrations.AlterField(
            model_name='tenant',
            name='tenant_type',
            field=models.CharField(
                max_length=20,
                choices=[('company', 'Company')],  # FREELANCER removed
                default='company',
                help_text='Type of organization. Individual freelancers use FreelancerProfile instead.'
            ),
        ),
    ]
"""

    migration_file = Path('tenants/migrations/0007_remove_freelancer_tenant_type.py')

    logger.info(f"Generated migration: {migration_file}")
    logger.info("⚠️ You must manually adjust the dependency to the latest migration")

    return migration_content


def generate_modification_report(modifications: List[FileModification]) -> str:
    """Generate report of all modifications."""
    report = f"""
================================================================================
FREELANCER TENANT TYPE REMOVAL REPORT
================================================================================
Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
--------
Total Files Modified: {len(modifications)}

FILES MODIFIED:
---------------
"""
    for mod in modifications:
        report += f"  ✅ {mod.file_path}\n"
        report += f"     {mod.description}\n"
        if mod.backup_path:
            report += f"     Backup: {mod.backup_path}\n"
        report += "\n"

    report += """
NEXT STEPS:
-----------
1. Review all modified files
2. Run tests: pytest -v
3. Create database migration:
   python manage.py makemigrations tenants
4. Apply migration:
   python manage.py migrate_schemas
5. Update documentation:
   - Remove FREELANCER from all docs
   - Update architecture diagrams
6. Git commit:
   git add .
   git commit -m "refactor: remove FREELANCER tenant type (migrated to FreelancerProfile)"

================================================================================
"""
    return report


def main():
    """Main removal script."""
    parser = argparse.ArgumentParser(
        description='Remove FREELANCER tenant type from codebase'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be changed without making changes'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force removal even if active FREELANCER tenants exist (DANGEROUS)'
    )

    args = parser.parse_args()

    logger.info("="*80)
    logger.info("REMOVE FREELANCER TENANT TYPE SCRIPT")
    logger.info("="*80)
    logger.info(f"Started: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Dry Run: {args.dry_run}")
    logger.info(f"Force: {args.force}")
    logger.info("="*80 + "\n")

    # Safety check
    is_safe, active_count = check_active_freelancer_tenants()

    if not is_safe and not args.force:
        logger.error("\n❌ SAFETY CHECK FAILED!")
        logger.error(f"Found {active_count} active FREELANCER tenants.")
        logger.error("You must migrate all FREELANCER tenants before removing the type.")
        logger.error("\nRun migration script first:")
        logger.error("  python scripts/migrate_freelancer_tenants_to_profiles.py")
        logger.error("\nOr use --force to skip this check (NOT RECOMMENDED)")
        sys.exit(1)

    modifications: List[FileModification] = []

    # 1. Modify tenant model
    logger.info("\n1. Modifying tenants/models.py...")
    model_mod = modify_tenant_model()
    modifications.append(model_mod)

    # 2. Find and modify tenant_type checks
    logger.info("\n2. Finding files with FREELANCER type checks...")
    files_with_checks = find_tenant_type_checks()
    logger.info(f"Found {len(files_with_checks)} files to modify")

    for file_path in files_with_checks:
        logger.info(f"   Processing {file_path}...")
        mod = modify_tenant_type_checks(file_path)
        modifications.append(mod)

    # 3. Generate migration
    logger.info("\n3. Generating database migration...")
    migration_content = create_database_migration()

    # Apply modifications (if not dry run)
    if not args.dry_run:
        logger.info("\n4. Applying modifications...")

        for mod in modifications:
            mod.backup()
            mod.apply()

        # Write migration file
        migration_file = Path('tenants/migrations/0007_remove_freelancer_tenant_type.py')
        migration_file.write_text(migration_content)
        logger.info(f"✅ Created migration: {migration_file}")

    else:
        logger.info("\n[DRY RUN] Would modify the following files:")
        for mod in modifications:
            logger.info(f"   - {mod.file_path}: {mod.description}")

    # Generate report
    report = generate_modification_report(modifications)
    print(report)

    # Save report
    report_filename = f'freelancer_type_removal_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    with open(report_filename, 'w') as f:
        f.write(report)

    logger.info(f"Report saved to: {report_filename}")

    if args.dry_run:
        logger.info("\n[DRY RUN COMPLETE] No changes were made.")
        logger.info("Run without --dry-run to apply changes.")
    else:
        logger.info("\n✅ FREELANCER tenant type removal complete!")
        logger.info("Next steps:")
        logger.info("  1. Review modified files")
        logger.info("  2. Run tests: pytest -v")
        logger.info("  3. Apply migration: python manage.py migrate_schemas")
        logger.info("  4. Update documentation")

    sys.exit(0)


if __name__ == '__main__':
    main()
