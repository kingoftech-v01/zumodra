# Migration Instructions

## Issue Resolution

The `services_service` table was missing because migrations hadn't been run for the services app in tenant schemas.

## Required Steps

### 1. Start Docker (if not running)

```bash
docker compose up -d
```

### 2. Run Migrations

Run migrations for both shared (public) and tenant schemas:

```bash
# Shared schema (public) migrations
docker compose exec web python manage.py migrate_schemas --shared

# Tenant schema migrations (THIS IS THE KEY STEP)
docker compose exec web python manage.py migrate_schemas --tenant
```

### 3. Verify Services Table

Check that the services_service table now exists:

```bash
docker compose exec db psql -U zumodra -d zumodra -c "\dt services_*"
```

Expected output should include:
- services_service
- services_servicecategory
- services_serviceprovider
- etc.

### 4. Optional: Run Geocoding

If you have demo data and want to geocode locations:

```bash
docker compose exec web python manage.py geocode_locations --all
```

## Alternative: Run Migrations on Startup

Set environment variable in `.env`:

```bash
RUN_GEOCODING=true
```

Then restart:

```bash
docker compose down
docker compose up -d
```

The entrypoint will automatically:
1. Run migrations
2. Geocode existing data (if RUN_GEOCODING=true)
3. Start the application

## Troubleshooting

If migrations fail:

1. Check database connection:
   ```bash
   docker compose exec web python manage.py dbshell
   ```

2. Check migration status:
   ```bash
   docker compose exec web python manage.py showmigrations services
   ```

3. View container logs:
   ```bash
   docker compose logs web
   docker compose logs channels
   ```

---

**Note**: The Service model now includes geolocation fields (`location_coordinates`, `geocode_attempted`, `geocode_error`) that match the migration `0002_add_location_coordinates.py`.
