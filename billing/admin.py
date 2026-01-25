"""
Billing Admin - Platform Subscription Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    SubscriptionPlan,
    TenantSubscription,
    PlatformInvoice,
    BillingHistory,
)


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "tier",
        "price_monthly_display",
        "price_yearly_display",
        "discount_display",
        "max_users",
        "max_jobs",
        "is_active",
        "is_public",
        "sort_order",
    ]
    list_filter = ["tier", "is_active", "is_public"]
    search_fields = ["name", "description"]
    prepopulated_fields = {"slug": ("name",)}
    ordering = ["sort_order", "price_monthly"]
    readonly_fields = ["created_at", "updated_at", "discount_display"]

    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "slug", "tier", "description")},
        ),
        (
            "Pricing",
            {
                "fields": (
                    "price_monthly",
                    "price_yearly",
                    "currency",
                    "discount_display",
                )
            },
        ),
        (
            "Limits",
            {
                "fields": (
                    "max_users",
                    "max_jobs",
                    "max_storage_gb",
                    "max_api_calls_per_month",
                )
            },
        ),
        ("Features", {"fields": ("features",)}),
        ("Trial", {"fields": ("trial_days",)}),
        (
            "Stripe Integration",
            {
                "fields": (
                    "stripe_product_id",
                    "stripe_price_id_monthly",
                    "stripe_price_id_yearly",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Display Settings",
            {"fields": ("is_active", "is_public", "sort_order")},
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def price_monthly_display(self, obj):
        return f"${obj.price_monthly}/{obj.currency}"

    price_monthly_display.short_description = "Monthly Price"

    def price_yearly_display(self, obj):
        return f"${obj.price_yearly}/{obj.currency}"

    price_yearly_display.short_description = "Yearly Price"

    def discount_display(self, obj):
        discount = obj.get_yearly_discount_percentage()
        if discount > 0:
            return format_html(
                '<span style="color: green; font-weight: bold;">{}% off</span>',
                discount,
            )
        return "-"

    discount_display.short_description = "Yearly Discount"


@admin.register(TenantSubscription)
class TenantSubscriptionAdmin(admin.ModelAdmin):
    list_display = [
        "tenant",
        "plan",
        "status_display",
        "billing_cycle",
        "current_period_display",
        "trial_status",
        "days_until_renewal",
    ]
    list_filter = ["status", "billing_cycle", "plan__tier"]
    search_fields = [
        "tenant__name",
        "tenant__schema_name",
        "stripe_subscription_id",
        "stripe_customer_id",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
        "is_trialing",
        "is_active",
        "days_until_renewal",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Subscription Details",
            {"fields": ("tenant", "plan", "status", "billing_cycle", "quantity")},
        ),
        (
            "Billing Periods",
            {
                "fields": (
                    "current_period_start",
                    "current_period_end",
                    "trial_start",
                    "trial_end",
                    "canceled_at",
                    "ended_at",
                )
            },
        ),
        (
            "Stripe Integration",
            {
                "fields": ("stripe_subscription_id", "stripe_customer_id"),
                "classes": ("collapse",),
            },
        ),
        (
            "Cancellation",
            {
                "fields": ("cancel_at_period_end", "cancellation_reason"),
                "classes": ("collapse",),
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Computed Fields",
            {
                "fields": ("is_trialing", "is_active", "days_until_renewal"),
                "classes": ("collapse",),
            },
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def status_display(self, obj):
        colors = {
            "active": "green",
            "trialing": "blue",
            "past_due": "orange",
            "canceled": "red",
            "unpaid": "darkred",
            "paused": "gray",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def current_period_display(self, obj):
        if obj.current_period_start and obj.current_period_end:
            return f"{obj.current_period_start.date()} → {obj.current_period_end.date()}"
        return "-"

    current_period_display.short_description = "Current Period"

    def trial_status(self, obj):
        if obj.is_trialing:
            if obj.trial_end:
                return format_html(
                    '<span style="color: blue;">Trial until {}</span>',
                    obj.trial_end.date(),
                )
        return "-"

    trial_status.short_description = "Trial"


@admin.register(PlatformInvoice)
class PlatformInvoiceAdmin(admin.ModelAdmin):
    list_display = [
        "invoice_number",
        "tenant",
        "status_display",
        "total_display",
        "invoice_date",
        "due_date",
        "overdue_status",
        "paid_at",
    ]
    list_filter = ["status", "invoice_date", "due_date"]
    search_fields = [
        "invoice_number",
        "tenant__name",
        "stripe_invoice_id",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
        "is_overdue",
        "stripe_invoice_link",
    ]
    date_hierarchy = "invoice_date"

    fieldsets = (
        (
            "Invoice Details",
            {"fields": ("tenant", "subscription", "invoice_number", "status")},
        ),
        (
            "Amounts",
            {
                "fields": (
                    "subtotal",
                    "tax",
                    "total",
                    "amount_paid",
                    "amount_due",
                    "currency",
                )
            },
        ),
        ("Line Items", {"fields": ("line_items",)}),
        (
            "Dates",
            {
                "fields": (
                    "invoice_date",
                    "due_date",
                    "paid_at",
                    "is_overdue",
                )
            },
        ),
        (
            "Stripe Integration",
            {
                "fields": (
                    "stripe_invoice_id",
                    "stripe_payment_intent_id",
                    "stripe_invoice_link",
                ),
                "classes": ("collapse",),
            },
        ),
        ("PDF", {"fields": ("pdf_url",), "classes": ("collapse",)}),
        (
            "Notes",
            {"fields": ("notes", "customer_notes"), "classes": ("collapse",)},
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def status_display(self, obj):
        colors = {
            "draft": "gray",
            "open": "blue",
            "paid": "green",
            "void": "red",
            "uncollectible": "darkred",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def total_display(self, obj):
        return f"${obj.total} {obj.currency}"

    total_display.short_description = "Total"

    def overdue_status(self, obj):
        if obj.is_overdue:
            return format_html(
                '<span style="color: red; font-weight: bold;">OVERDUE</span>'
            )
        return "-"

    overdue_status.short_description = "Overdue"

    def stripe_invoice_link(self, obj):
        if obj.stripe_invoice_id:
            stripe_url = f"https://dashboard.stripe.com/invoices/{obj.stripe_invoice_id}"
            return format_html(
                '<a href="{}" target="_blank">View in Stripe</a>', stripe_url
            )
        return "-"

    stripe_invoice_link.short_description = "Stripe Link"


@admin.register(BillingHistory)
class BillingHistoryAdmin(admin.ModelAdmin):
    list_display = [
        "tenant",
        "change_type_display",
        "plan_change",
        "status_change",
        "created_at",
        "changed_by",
    ]
    list_filter = ["change_type", "created_at"]
    search_fields = ["tenant__name", "description"]
    readonly_fields = ["created_at", "tenant", "subscription"]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Change Details",
            {
                "fields": (
                    "tenant",
                    "subscription",
                    "change_type",
                    "description",
                    "changed_by",
                )
            },
        ),
        (
            "Before/After State",
            {
                "fields": (
                    "old_plan",
                    "new_plan",
                    "old_status",
                    "new_status",
                )
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        ("Timestamp", {"fields": ("created_at",)}),
    )

    def change_type_display(self, obj):
        colors = {
            "created": "blue",
            "upgraded": "green",
            "downgraded": "orange",
            "canceled": "red",
            "reactivated": "green",
            "renewed": "blue",
            "trial_started": "purple",
            "trial_ended": "gray",
            "payment_failed": "red",
            "payment_succeeded": "green",
        }
        color = colors.get(obj.change_type, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_change_type_display(),
        )

    change_type_display.short_description = "Change Type"

    def plan_change(self, obj):
        if obj.old_plan and obj.new_plan:
            return f"{obj.old_plan.name} → {obj.new_plan.name}"
        elif obj.new_plan:
            return f"→ {obj.new_plan.name}"
        return "-"

    plan_change.short_description = "Plan Change"

    def status_change(self, obj):
        if obj.old_status and obj.new_status:
            return f"{obj.old_status} → {obj.new_status}"
        elif obj.new_status:
            return f"→ {obj.new_status}"
        return "-"

    status_change.short_description = "Status Change"

    def has_add_permission(self, request):
        """Billing history is created automatically, no manual adds"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Billing history should never be deleted"""
        return False
