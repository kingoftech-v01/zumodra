"""
Tax Admin - Tax Calculation and Compliance Management
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import (
    AvalaraConfig,
    TaxRate,
    TaxCalculation,
    TaxExemption,
    TaxRemittance,
    TaxReport,
)


@admin.register(AvalaraConfig)
class AvalaraConfigAdmin(admin.ModelAdmin):
    list_display = [
        "company_name",
        "company_code",
        "environment_display",
        "is_active",
        "last_sync",
    ]
    list_filter = ["is_active", "is_sandbox"]
    search_fields = ["company_name", "company_code", "account_id"]
    readonly_fields = ["created_at", "updated_at", "last_sync"]

    fieldsets = (
        (
            "Avalara Credentials",
            {
                "fields": (
                    "account_id",
                    "license_key",
                    "company_code",
                    "is_sandbox",
                )
            },
        ),
        (
            "Company Information",
            {"fields": ("company_name", "tax_id")},
        ),
        (
            "Settings",
            {
                "fields": (
                    "default_tax_code",
                    "commit_transactions",
                )
            },
        ),
        (
            "Status",
            {"fields": ("is_active", "last_sync")},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def environment_display(self, obj):
        if obj.is_sandbox:
            return format_html('<span style="color: blue;">Sandbox</span>')
        return format_html('<span style="color: green;">Production</span>')

    environment_display.short_description = "Environment"


@admin.register(TaxRate)
class TaxRateAdmin(admin.ModelAdmin):
    list_display = [
        "location_display",
        "tax_type",
        "rate_display",
        "effective_period",
        "is_active",
    ]
    list_filter = ["tax_type", "country", "is_active"]
    search_fields = [
        "state_province",
        "city",
        "postal_code",
        "avalara_jurisdiction_id",
    ]
    readonly_fields = ["created_at", "updated_at"]
    date_hierarchy = "effective_start"

    fieldsets = (
        (
            "Jurisdiction",
            {
                "fields": (
                    "country",
                    "state_province",
                    "county",
                    "city",
                    "postal_code",
                )
            },
        ),
        (
            "Tax Details",
            {"fields": ("tax_type", "rate")},
        ),
        (
            "Effective Period",
            {"fields": ("effective_start", "effective_end")},
        ),
        (
            "Avalara",
            {
                "fields": ("avalara_jurisdiction_id",),
                "classes": ("collapse",),
            },
        ),
        (
            "Status",
            {"fields": ("is_active",)},
        ),
        (
            "Notes",
            {"fields": ("notes",)},
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def location_display(self, obj):
        parts = [obj.city, obj.state_province, obj.country]
        return ", ".join([p for p in parts if p])

    location_display.short_description = "Location"

    def rate_display(self, obj):
        return f"{obj.rate_percentage:.3f}%"

    rate_display.short_description = "Rate"

    def effective_period(self, obj):
        if obj.effective_end:
            return f"{obj.effective_start} → {obj.effective_end}"
        return f"{obj.effective_start} → Ongoing"

    effective_period.short_description = "Effective Period"


@admin.register(TaxCalculation)
class TaxCalculationAdmin(admin.ModelAdmin):
    list_display = [
        "calculated_at",
        "source",
        "subtotal_display",
        "tax_amount_display",
        "total_display",
        "effective_rate_display",
    ]
    list_filter = ["source", "calculated_at"]
    search_fields = [
        "avalara_transaction_code",
        "payment_transaction__transaction_id",
    ]
    readonly_fields = ["calculated_at"]
    date_hierarchy = "calculated_at"

    fieldsets = (
        (
            "Related Transaction",
            {
                "fields": (
                    "payment_transaction",
                    "subscription_invoice",
                )
            },
        ),
        (
            "Calculation",
            {
                "fields": (
                    "source",
                    "subtotal",
                    "tax_amount",
                    "total",
                    "currency",
                )
            },
        ),
        (
            "Breakdown",
            {"fields": ("tax_breakdown",)},
        ),
        (
            "Address",
            {"fields": ("tax_address",)},
        ),
        (
            "Avalara",
            {
                "fields": ("avalara_transaction_code", "avalara_response"),
                "classes": ("collapse",),
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamp",
            {"fields": ("calculated_at",)},
        ),
    )

    def subtotal_display(self, obj):
        return f"{obj.currency} {obj.subtotal:,.2f}"

    subtotal_display.short_description = "Subtotal"

    def tax_amount_display(self, obj):
        return format_html(
            '<span style="color: orange; font-weight: bold;">{} {:,.2f}</span>',
            obj.currency,
            obj.tax_amount
        )

    tax_amount_display.short_description = "Tax"

    def total_display(self, obj):
        return f"{obj.currency} {obj.total:,.2f}"

    total_display.short_description = "Total"

    def effective_rate_display(self, obj):
        return f"{obj.effective_tax_rate:.2f}%"

    effective_rate_display.short_description = "Effective Rate"


@admin.register(TaxExemption)
class TaxExemptionAdmin(admin.ModelAdmin):
    list_display = [
        "customer",
        "exemption_type",
        "exemption_number",
        "jurisdiction_display",
        "status_display",
        "expiration_date",
        "is_valid_display",
    ]
    list_filter = ["status", "exemption_type", "country"]
    search_fields = [
        "customer__email",
        "customer__first_name",
        "customer__last_name",
        "exemption_number",
    ]
    readonly_fields = ["created_at", "updated_at", "verified_at"]
    date_hierarchy = "issue_date"

    fieldsets = (
        (
            "Customer",
            {"fields": ("customer",)},
        ),
        (
            "Exemption Details",
            {
                "fields": (
                    "exemption_type",
                    "exemption_number",
                    "status",
                )
            },
        ),
        (
            "Jurisdiction",
            {"fields": ("country", "state_province")},
        ),
        (
            "Dates",
            {
                "fields": (
                    "issue_date",
                    "expiration_date",
                    "verified_at",
                )
            },
        ),
        (
            "Certificate",
            {"fields": ("certificate_file",)},
        ),
        (
            "Notes",
            {"fields": ("notes",)},
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def jurisdiction_display(self, obj):
        return f"{obj.state_province}, {obj.country}" if obj.state_province else obj.country

    jurisdiction_display.short_description = "Jurisdiction"

    def status_display(self, obj):
        colors = {
            "active": "green",
            "expired": "orange",
            "revoked": "red",
            "pending": "blue",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def is_valid_display(self, obj):
        if obj.is_valid:
            return format_html('<span style="color: green;">✓ Valid</span>')
        return format_html('<span style="color: red;">✗ Invalid</span>')

    is_valid_display.short_description = "Valid"


@admin.register(TaxRemittance)
class TaxRemittanceAdmin(admin.ModelAdmin):
    list_display = [
        "remittance_id",
        "authority_name",
        "jurisdiction_display",
        "period_display",
        "tax_owed_display",
        "status_display",
        "due_date",
    ]
    list_filter = ["status", "filing_frequency", "country"]
    search_fields = [
        "remittance_id",
        "authority_name",
        "filing_reference",
    ]
    readonly_fields = [
        "remittance_id",
        "created_at",
        "updated_at",
        "paid_at",
    ]
    date_hierarchy = "due_date"

    fieldsets = (
        (
            "Remittance Details",
            {
                "fields": (
                    "remittance_id",
                    "status",
                )
            },
        ),
        (
            "Jurisdiction",
            {
                "fields": (
                    "country",
                    "state_province",
                    "authority_name",
                )
            },
        ),
        (
            "Period",
            {"fields": ("period_start", "period_end", "filing_frequency")},
        ),
        (
            "Amounts",
            {
                "fields": (
                    "tax_collected",
                    "tax_owed",
                    "amount_paid",
                    "currency",
                )
            },
        ),
        (
            "Payment",
            {
                "fields": (
                    "due_date",
                    "paid_at",
                    "payment_transaction",
                )
            },
        ),
        (
            "Filing",
            {"fields": ("filing_reference",)},
        ),
        (
            "Notes",
            {"fields": ("notes",)},
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def jurisdiction_display(self, obj):
        return f"{obj.state_province}, {obj.country}" if obj.state_province else obj.country

    jurisdiction_display.short_description = "Jurisdiction"

    def period_display(self, obj):
        return f"{obj.period_start} → {obj.period_end}"

    period_display.short_description = "Period"

    def tax_owed_display(self, obj):
        return format_html(
            '<span style="color: red; font-weight: bold;">{} {:,.2f}</span>',
            obj.currency,
            obj.tax_owed
        )

    tax_owed_display.short_description = "Tax Owed"

    def status_display(self, obj):
        colors = {
            "scheduled": "blue",
            "paid": "green",
            "failed": "red",
            "overdue": "darkred",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"


@admin.register(TaxReport)
class TaxReportAdmin(admin.ModelAdmin):
    list_display = [
        "report_number",
        "report_type",
        "period_display",
        "total_tax_collected_display",
        "total_tax_remitted_display",
        "generated_by",
        "generated_at",
    ]
    list_filter = ["report_type", "generated_at"]
    search_fields = ["report_number"]
    readonly_fields = ["report_number", "generated_at"]
    date_hierarchy = "period_end"

    fieldsets = (
        (
            "Report Details",
            {
                "fields": (
                    "report_number",
                    "report_type",
                )
            },
        ),
        (
            "Period",
            {"fields": ("period_start", "period_end")},
        ),
        (
            "Totals",
            {
                "fields": (
                    "total_taxable_sales",
                    "total_exempt_sales",
                    "total_tax_collected",
                    "total_tax_remitted",
                    "currency",
                )
            },
        ),
        (
            "Breakdown",
            {"fields": ("jurisdiction_breakdown",)},
        ),
        (
            "Generation",
            {"fields": ("generated_by", "generated_at")},
        ),
        (
            "PDF",
            {"fields": ("pdf_file",)},
        ),
        (
            "Notes",
            {"fields": ("notes",)},
        ),
    )

    def period_display(self, obj):
        return f"{obj.period_start} → {obj.period_end}"

    period_display.short_description = "Period"

    def total_tax_collected_display(self, obj):
        return f"{obj.currency} {obj.total_tax_collected:,.2f}"

    total_tax_collected_display.short_description = "Tax Collected"

    def total_tax_remitted_display(self, obj):
        return f"{obj.currency} {obj.total_tax_remitted:,.2f}"

    total_tax_remitted_display.short_description = "Tax Remitted"
