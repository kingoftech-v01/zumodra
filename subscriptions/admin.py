"""
Subscriptions Admin - Tenant Subscription Product Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    SubscriptionProduct,
    SubscriptionTier,
    CustomerSubscription,
    SubscriptionInvoice,
    UsageRecord,
)


class SubscriptionTierInline(admin.TabularInline):
    model = SubscriptionTier
    extra = 1
    fields = [
        'name',
        'min_quantity',
        'max_quantity',
        'price_per_unit_monthly',
        'price_per_unit_yearly',
    ]


@admin.register(SubscriptionProduct)
class SubscriptionProductAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "product_type",
        "price_monthly_display",
        "price_yearly_display",
        "discount_display",
        "trial_period_days",
        "is_active",
        "is_public",
        "sort_order",
    ]
    list_filter = ["product_type", "is_active", "is_public"]
    search_fields = ["name", "description"]
    prepopulated_fields = {"slug": ("name",)}
    ordering = ["sort_order", "name"]
    readonly_fields = ["created_at", "updated_at", "discount_display"]
    inlines = [SubscriptionTierInline]

    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "slug", "product_type", "description")},
        ),
        (
            "Pricing",
            {
                "fields": (
                    "base_price_monthly",
                    "base_price_yearly",
                    "currency",
                    "discount_display",
                )
            },
        ),
        (
            "Trial",
            {"fields": ("trial_period_days",)},
        ),
        (
            "Limits",
            {
                "fields": (
                    "max_users",
                    "max_storage_gb",
                    "max_api_calls_per_month",
                )
            },
        ),
        ("Features", {"fields": ("features",)}),
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
        return f"{obj.currency} {obj.base_price_monthly}"

    price_monthly_display.short_description = "Monthly Price"

    def price_yearly_display(self, obj):
        return f"{obj.currency} {obj.base_price_yearly}"

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


@admin.register(SubscriptionTier)
class SubscriptionTierAdmin(admin.ModelAdmin):
    list_display = [
        "product",
        "name",
        "quantity_range",
        "price_monthly_display",
        "price_yearly_display",
    ]
    list_filter = ["product"]
    search_fields = ["name", "product__name"]
    ordering = ["product", "min_quantity"]

    fieldsets = (
        (
            "Tier Information",
            {"fields": ("product", "name", "min_quantity", "max_quantity")},
        ),
        (
            "Pricing",
            {
                "fields": ("price_per_unit_monthly", "price_per_unit_yearly")
            },
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    readonly_fields = ["created_at", "updated_at"]

    def quantity_range(self, obj):
        max_qty = obj.max_quantity or '∞'
        return f"{obj.min_quantity} - {max_qty}"

    quantity_range.short_description = "Quantity Range"

    def price_monthly_display(self, obj):
        return f"{obj.price_per_unit_monthly} / unit"

    price_monthly_display.short_description = "Monthly Price"

    def price_yearly_display(self, obj):
        return f"{obj.price_per_unit_yearly} / unit"

    price_yearly_display.short_description = "Yearly Price"


@admin.register(CustomerSubscription)
class CustomerSubscriptionAdmin(admin.ModelAdmin):
    list_display = [
        "customer",
        "product",
        "status_display",
        "billing_cycle",
        "quantity",
        "total_price_display",
        "current_period_display",
        "trial_status",
        "days_until_renewal",
    ]
    list_filter = ["status", "billing_cycle", "product"]
    search_fields = [
        "customer__email",
        "customer__first_name",
        "customer__last_name",
        "product__name",
        "stripe_subscription_id",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
        "is_trialing",
        "is_active",
        "days_until_renewal",
        "total_price",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Subscription Details",
            {
                "fields": (
                    "customer",
                    "product",
                    "tier",
                    "status",
                    "billing_cycle",
                    "quantity",
                )
            },
        ),
        (
            "Pricing",
            {
                "fields": (
                    "price_per_unit",
                    "total_price",
                    "currency",
                )
            },
        ),
        (
            "Billing Periods",
            {
                "fields": (
                    "current_period_start",
                    "current_period_end",
                    "trial_start",
                    "trial_end",
                )
            },
        ),
        (
            "Cancellation",
            {
                "fields": (
                    "cancel_at_period_end",
                    "canceled_at",
                    "cancellation_reason",
                    "ended_at",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Stripe Integration",
            {
                "fields": ("stripe_subscription_id", "stripe_customer_id"),
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

    def total_price_display(self, obj):
        return f"{obj.currency} {obj.total_price} / {obj.billing_cycle}"

    total_price_display.short_description = "Total Price"

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


@admin.register(SubscriptionInvoice)
class SubscriptionInvoiceAdmin(admin.ModelAdmin):
    list_display = [
        "invoice_number",
        "customer",
        "subscription_link",
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
        "customer__email",
        "customer__first_name",
        "customer__last_name",
        "stripe_invoice_id",
    ]
    readonly_fields = [
        "invoice_number",
        "total",
        "amount_due",
        "created_at",
        "updated_at",
        "is_overdue",
        "stripe_invoice_link",
    ]
    date_hierarchy = "invoice_date"

    fieldsets = (
        (
            "Invoice Details",
            {
                "fields": (
                    "invoice_number",
                    "subscription",
                    "customer",
                    "status",
                )
            },
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
            "Billing Period",
            {"fields": ("period_start", "period_end")},
        ),
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
        return f"{obj.currency} {obj.total}"

    total_display.short_description = "Total"

    def overdue_status(self, obj):
        if obj.is_overdue:
            return format_html(
                '<span style="color: red; font-weight: bold;">OVERDUE</span>'
            )
        return "-"

    overdue_status.short_description = "Overdue"

    def subscription_link(self, obj):
        url = reverse(
            "admin:subscriptions_customersubscription_change",
            args=[obj.subscription.pk],
        )
        return format_html(
            '<a href="{}">{} - {}</a>',
            url,
            obj.subscription.customer.get_full_name(),
            obj.subscription.product.name,
        )

    subscription_link.short_description = "Subscription"

    def stripe_invoice_link(self, obj):
        if obj.stripe_invoice_id:
            stripe_url = f"https://dashboard.stripe.com/invoices/{obj.stripe_invoice_id}"
            return format_html(
                '<a href="{}" target="_blank">View in Stripe</a>', stripe_url
            )
        return "-"

    stripe_invoice_link.short_description = "Stripe Link"


@admin.register(UsageRecord)
class UsageRecordAdmin(admin.ModelAdmin):
    list_display = [
        "subscription_link",
        "usage_type",
        "quantity",
        "unit_price",
        "total_amount_display",
        "usage_date",
        "period_display",
    ]
    list_filter = ["usage_type", "usage_date"]
    search_fields = [
        "subscription__customer__email",
        "subscription__customer__first_name",
        "subscription__customer__last_name",
    ]
    readonly_fields = ["total_amount", "created_at", "updated_at"]
    date_hierarchy = "usage_date"

    fieldsets = (
        (
            "Usage Details",
            {
                "fields": (
                    "subscription",
                    "usage_type",
                    "quantity",
                    "unit_price",
                    "total_amount",
                )
            },
        ),
        (
            "Time Period",
            {
                "fields": (
                    "usage_date",
                    "period_start",
                    "period_end",
                )
            },
        ),
        (
            "Stripe Integration",
            {
                "fields": ("stripe_usage_record_id",),
                "classes": ("collapse",),
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def subscription_link(self, obj):
        url = reverse(
            "admin:subscriptions_customersubscription_change",
            args=[obj.subscription.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.subscription.customer.get_full_name(),
        )

    subscription_link.short_description = "Subscription"

    def total_amount_display(self, obj):
        return f"{obj.subscription.currency} {obj.total_amount}"

    total_amount_display.short_description = "Total Amount"

    def period_display(self, obj):
        return f"{obj.period_start} → {obj.period_end}"

    period_display.short_description = "Period"
