#!/usr/bin/env python
"""
Temporary script to check if new migrations are needed
Bypasses GDAL import issues
"""
import os
import sys
import django

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

# Mock GDAL before Django loads
from unittest.mock import MagicMock
sys.modules['django.contrib.gis.gdal'] = MagicMock()
sys.modules['django.contrib.gis.gdal.libgdal'] = MagicMock()
sys.modules['django.contrib.gis.geos'] = MagicMock()

# Now setup Django
django.setup()

# Run makemigrations
from django.core.management import call_command

print("Checking for migrations...")
try:
    call_command('makemigrations', 'accounts', '--dry-run', verbosity=2)
    print("\n" + "="*60)
    print("Creating migration files...")
    call_command('makemigrations', 'accounts', verbosity=2)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
