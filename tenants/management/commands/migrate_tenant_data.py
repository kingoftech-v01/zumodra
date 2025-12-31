"""
Management command to migrate data between tenants.
Useful for tenant mergers, data consolidation, or backup restoration.
"""

import json
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.apps import apps
from django.core.serializers import serialize, deserialize
from tenants.models import Tenant


class Command(BaseCommand):
    help = 'Migrate data between tenants (copy or move)'

    def add_arguments(self, parser):
        parser.add_argument(
            'source_tenant',
            type=str,
            help='Source tenant slug or schema name'
        )
        parser.add_argument(
            'target_tenant',
            type=str,
            help='Target tenant slug or schema name'
        )
        parser.add_argument(
            '--models',
            type=str,
            nargs='+',
            help='Specific models to migrate (e.g., ats.JobPosting hr_core.Employee)'
        )
        parser.add_argument(
            '--all-models',
            action='store_true',
            help='Migrate all tenant-specific models'
        )
        parser.add_argument(
            '--move',
            action='store_true',
            help='Move data (delete from source after copy). Default is copy only.'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be migrated without making changes'
        )
        parser.add_argument(
            '--export-file',
            type=str,
            help='Export source data to JSON file instead of migrating'
        )
        parser.add_argument(
            '--import-file',
            type=str,
            help='Import data from JSON file into target tenant'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=1000,
            help='Number of records to process at a time (default: 1000)'
        )

    def handle(self, *args, **options):
        source_slug = options['source_tenant']
        target_slug = options['target_tenant']
        model_names = options.get('models') or []
        all_models = options.get('all_models', False)
        is_move = options.get('move', False)
        dry_run = options.get('dry_run', False)
        export_file = options.get('export_file')
        import_file = options.get('import_file')
        batch_size = options.get('batch_size', 1000)

        # Validate tenants
        try:
            source_tenant = Tenant.objects.get(slug=source_slug)
        except Tenant.DoesNotExist:
            try:
                source_tenant = Tenant.objects.get(schema_name=source_slug)
            except Tenant.DoesNotExist:
                raise CommandError(f"Source tenant not found: {source_slug}")

        try:
            target_tenant = Tenant.objects.get(slug=target_slug)
        except Tenant.DoesNotExist:
            try:
                target_tenant = Tenant.objects.get(schema_name=target_slug)
            except Tenant.DoesNotExist:
                raise CommandError(f"Target tenant not found: {target_slug}")

        if source_tenant == target_tenant:
            raise CommandError("Source and target tenants must be different")

        # Get models to migrate
        tenant_models = self._get_tenant_models(model_names, all_models)

        if not tenant_models:
            raise CommandError("No models specified. Use --models or --all-models")

        self.stdout.write(f"\nSource tenant: {source_tenant.name} ({source_tenant.schema_name})")
        self.stdout.write(f"Target tenant: {target_tenant.name} ({target_tenant.schema_name})")
        self.stdout.write(f"Mode: {'MOVE' if is_move else 'COPY'}")
        self.stdout.write(f"Models: {', '.join([m.__name__ for m in tenant_models])}")

        if dry_run:
            self.stdout.write(self.style.WARNING("\n=== DRY RUN MODE ===\n"))

        # Handle export to file
        if export_file:
            self._export_to_file(source_tenant, tenant_models, export_file, dry_run)
            return

        # Handle import from file
        if import_file:
            self._import_from_file(target_tenant, import_file, dry_run)
            return

        # Perform migration
        total_records = 0
        for model in tenant_models:
            count = self._migrate_model(
                source_tenant, target_tenant, model,
                is_move, dry_run, batch_size
            )
            total_records += count

        if dry_run:
            self.stdout.write(self.style.WARNING(
                f"\n[DRY RUN] Would migrate {total_records} total records"
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"\nSuccessfully migrated {total_records} total records"
            ))

    def _get_tenant_models(self, model_names, all_models):
        """Get list of Django models to migrate."""
        tenant_models = []

        if all_models:
            # Get all models from tenant-specific apps
            tenant_apps = ['ats', 'hr_core', 'careers', 'accounts']
            for app_label in tenant_apps:
                try:
                    app_config = apps.get_app_config(app_label)
                    for model in app_config.get_models():
                        tenant_models.append(model)
                except LookupError:
                    pass
        else:
            for model_name in model_names:
                try:
                    if '.' in model_name:
                        app_label, model_class = model_name.rsplit('.', 1)
                        model = apps.get_model(app_label, model_class)
                    else:
                        model = apps.get_model(model_name)
                    tenant_models.append(model)
                except LookupError:
                    self.stdout.write(self.style.WARNING(
                        f"Model not found: {model_name}"
                    ))

        return tenant_models

    def _migrate_model(self, source_tenant, target_tenant, model, is_move, dry_run, batch_size):
        """Migrate a single model's data between tenants."""
        model_name = f"{model._meta.app_label}.{model.__name__}"
        self.stdout.write(f"\nProcessing {model_name}...")

        # Switch to source tenant schema
        connection.set_schema(source_tenant.schema_name)

        # Count records
        count = model.objects.count()
        if count == 0:
            self.stdout.write(f"  No records to migrate")
            return 0

        self.stdout.write(f"  Found {count} records")

        if dry_run:
            self.stdout.write(f"  [DRY RUN] Would migrate {count} records")
            return count

        # Serialize data from source
        try:
            data = serialize('json', model.objects.all())
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  Error serializing: {e}"))
            return 0

        # Switch to target tenant and import
        connection.set_schema(target_tenant.schema_name)

        created = 0
        try:
            with transaction.atomic():
                for obj in deserialize('json', data):
                    # Reset PK to allow creation
                    obj.object.pk = None
                    obj.object.save()
                    created += 1

                    if created % batch_size == 0:
                        self.stdout.write(f"  Migrated {created}/{count} records...")

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  Error importing: {e}"))
            return 0

        self.stdout.write(self.style.SUCCESS(f"  Migrated {created} records"))

        # Delete from source if move mode
        if is_move and created > 0:
            connection.set_schema(source_tenant.schema_name)
            deleted, _ = model.objects.all().delete()
            self.stdout.write(f"  Deleted {deleted} records from source")

        return created

    def _export_to_file(self, tenant, models, filepath, dry_run):
        """Export tenant data to JSON file."""
        connection.set_schema(tenant.schema_name)

        export_data = {}
        total = 0

        for model in models:
            model_name = f"{model._meta.app_label}.{model.__name__}"
            count = model.objects.count()
            total += count

            if count > 0:
                export_data[model_name] = serialize('json', model.objects.all())
                self.stdout.write(f"  {model_name}: {count} records")

        if dry_run:
            self.stdout.write(self.style.WARNING(
                f"\n[DRY RUN] Would export {total} records to {filepath}"
            ))
            return

        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

        self.stdout.write(self.style.SUCCESS(
            f"\nExported {total} records to {filepath}"
        ))

    def _import_from_file(self, tenant, filepath, dry_run):
        """Import data from JSON file into tenant."""
        connection.set_schema(tenant.schema_name)

        try:
            with open(filepath, 'r') as f:
                import_data = json.load(f)
        except FileNotFoundError:
            raise CommandError(f"Import file not found: {filepath}")
        except json.JSONDecodeError as e:
            raise CommandError(f"Invalid JSON in import file: {e}")

        total = 0
        for model_name, data in import_data.items():
            objects = list(deserialize('json', data))
            count = len(objects)
            total += count

            self.stdout.write(f"  {model_name}: {count} records")

            if not dry_run:
                with transaction.atomic():
                    for obj in objects:
                        obj.object.pk = None
                        obj.object.save()

        if dry_run:
            self.stdout.write(self.style.WARNING(
                f"\n[DRY RUN] Would import {total} records from {filepath}"
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"\nImported {total} records from {filepath}"
            ))
