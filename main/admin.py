from django.contrib import admin
from django_tenants.admin import TenantAdminMixin
from .models import *

# Register your models here.
@admin.register(Tenant)
class TenantAdmin(TenantAdminMixin, admin.ModelAdmin):
    pass
