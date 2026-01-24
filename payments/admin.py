"""
Payments Admin - Multi-Currency Payment Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    Currency,
    ExchangeRate,
    PaymentMethod,
    PaymentTransaction,
    RefundRequest,
    PaymentIntent,
)


@admin.register(Currency)
class CurrencyAdmin(admin.ModelAdmin):
    list_display = [
        "code",
        "name",
        "symbol",
        "decimal_places",
        "is_active",
        "created_at",
    ]
    list_filter = ["is_active"]
    search_fields = ["code", "name"]
    readonly_fields = ["created_at", "updated_at"]
    ordering = ["code"]

    fieldsets = (
        (
            "Currency Information",
            {"fields": ("code", "name", "symbol", "decimal_places")},
        ),
        ("Status", {"fields": ("is_active",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(ExchangeRate)
class ExchangeRateAdmin(admin.ModelAdmin):
    list_display = [
        "from_currency",
        "to_currency",
        "rate_display",
        "date",
        "source",
        "created_at",
    ]
    list_filter = ["date", "source", "from_currency", "to_currency"]
    search_fields = ["from_currency__code", "to_currency__code"]
    readonly_fields = ["created_at"]
    date_hierarchy = "date"
    ordering = ["-date", "from_currency"]

    fieldsets = (
        (
            "Exchange Rate Details",
            {"fields": ("from_currency", "to_currency", "rate", "date")},
        ),
        ("Source", {"fields": ("source",)}),
        (
            "Timestamps",
            {"fields": ("created_at",), "classes": ("collapse",)},
        ),
    )

    def rate_display(self, obj):
        return f"{obj.rate:.8f}"

    rate_display.short_description = "Rate"


@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "method_type",
        "method_display",
        "is_default",
        "is_active",
        "created_at",
    ]
    list_filter = ["method_type", "is_default", "is_active"]
    search_fields = [
        "user__email",
        "user__first_name",
        "user__last_name",
        "stripe_payment_method_id",
        "card_last4",
        "account_last4",
    ]
    readonly_fields = ["created_at", "updated_at"]
    date_hierarchy = "created_at"

    fieldsets = (
        ("User", {"fields": ("user",)}),
        (
            "Payment Method",
            {"fields": ("method_type", "is_default", "is_active")},
        ),
        (
            "Card Details",
            {
                "fields": (
                    "card_brand",
                    "card_last4",
                    "card_exp_month",
                    "card_exp_year",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Bank Account Details",
            {
                "fields": ("bank_name", "account_last4"),
                "classes": ("collapse",),
            },
        ),
        (
            "Stripe Integration",
            {
                "fields": ("stripe_payment_method_id",),
                "classes": ("collapse",),
            },
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def method_display(self, obj):
        if obj.method_type == PaymentMethod.PaymentMethodType.CARD:
            default_badge = (
                '<span style="color: green;"> (Default)</span>'
                if obj.is_default
                else ""
            )
            return format_html(
                "{} ****{}{}", obj.card_brand or "Card", obj.card_last4, default_badge
            )
        elif obj.method_type == PaymentMethod.PaymentMethodType.BANK_ACCOUNT:
            return format_html(
                "{} ****{}", obj.bank_name or "Bank", obj.account_last4
            )
        return obj.get_method_type_display()

    method_display.short_description = "Payment Method"


@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(admin.ModelAdmin):
    list_display = [
        "transaction_id",
        "payer",
        "payee",
        "amount_display",
        "status_display",
        "payment_method",
        "created_at",
    ]
    list_filter = ["status", "currency", "created_at"]
    search_fields = [
        "transaction_id",
        "payer__email",
        "payer__first_name",
        "payer__last_name",
        "payee__email",
        "payee__first_name",
        "payee__last_name",
        "stripe_payment_intent_id",
        "stripe_charge_id",
    ]
    readonly_fields = [
        "transaction_id",
        "amount_usd",
        "created_at",
        "updated_at",
        "succeeded_at",
        "failed_at",
        "refunded_at",
        "stripe_link",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Transaction Details",
            {"fields": ("transaction_id", "status", "description")},
        ),
        (
            "Amount",
            {
                "fields": (
                    "amount",
                    "currency",
                    "exchange_rate",
                    "amount_usd",
                )
            },
        ),
        ("Parties", {"fields": ("payer", "payee")}),
        (
            "Payment Method",
            {"fields": ("payment_method",)},
        ),
        (
            "Related Object",
            {
                "fields": ("content_type", "object_id"),
                "classes": ("collapse",),
            },
        ),
        (
            "Stripe Integration",
            {
                "fields": (
                    "stripe_payment_intent_id",
                    "stripe_charge_id",
                    "stripe_transfer_id",
                    "stripe_link",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Dates",
            {
                "fields": (
                    "succeeded_at",
                    "failed_at",
                    "refunded_at",
                )
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def status_display(self, obj):
        colors = {
            "pending": "orange",
            "processing": "blue",
            "succeeded": "green",
            "failed": "red",
            "canceled": "gray",
            "refunded": "purple",
            "partially_refunded": "purple",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def amount_display(self, obj):
        usd_display = ""
        if obj.currency.code != "USD":
            usd_display = f" (${obj.amount_usd} USD)"
        return format_html(
            "{} {}{}", obj.amount, obj.currency.symbol, usd_display
        )

    amount_display.short_description = "Amount"

    def stripe_link(self, obj):
        if obj.stripe_payment_intent_id:
            stripe_url = (
                f"https://dashboard.stripe.com/payments/{obj.stripe_payment_intent_id}"
            )
            return format_html(
                '<a href="{}" target="_blank">View in Stripe</a>', stripe_url
            )
        return "-"

    stripe_link.short_description = "Stripe Link"


@admin.register(RefundRequest)
class RefundRequestAdmin(admin.ModelAdmin):
    list_display = [
        "refund_id",
        "transaction_link",
        "amount_display",
        "status_display",
        "reason",
        "requested_by",
        "requested_at",
    ]
    list_filter = ["status", "reason", "requested_at"]
    search_fields = [
        "refund_id",
        "transaction__transaction_id",
        "stripe_refund_id",
    ]
    readonly_fields = [
        "refund_id",
        "requested_at",
        "processed_at",
        "created_at",
        "updated_at",
        "stripe_refund_link",
    ]
    date_hierarchy = "requested_at"

    fieldsets = (
        (
            "Refund Details",
            {"fields": ("refund_id", "transaction", "amount", "status")},
        ),
        (
            "Reason",
            {"fields": ("reason", "reason_details", "requested_by")},
        ),
        (
            "Stripe Integration",
            {
                "fields": ("stripe_refund_id", "stripe_refund_link"),
                "classes": ("collapse",),
            },
        ),
        (
            "Dates",
            {"fields": ("requested_at", "processed_at")},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def status_display(self, obj):
        colors = {
            "pending": "orange",
            "processing": "blue",
            "succeeded": "green",
            "failed": "red",
            "canceled": "gray",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def amount_display(self, obj):
        return f"{obj.amount} {obj.transaction.currency.symbol}"

    amount_display.short_description = "Refund Amount"

    def transaction_link(self, obj):
        url = reverse(
            "admin:payments_paymenttransaction_change", args=[obj.transaction.pk]
        )
        return format_html('<a href="{}">{}</a>', url, obj.transaction.transaction_id)

    transaction_link.short_description = "Transaction"

    def stripe_refund_link(self, obj):
        if obj.stripe_refund_id:
            stripe_url = (
                f"https://dashboard.stripe.com/refunds/{obj.stripe_refund_id}"
            )
            return format_html(
                '<a href="{}" target="_blank">View in Stripe</a>', stripe_url
            )
        return "-"

    stripe_refund_link.short_description = "Stripe Link"


@admin.register(PaymentIntent)
class PaymentIntentAdmin(admin.ModelAdmin):
    list_display = [
        "stripe_payment_intent_id",
        "customer",
        "amount_display",
        "status_display",
        "payment_method",
        "created_at",
    ]
    list_filter = ["status", "currency", "created_at"]
    search_fields = [
        "stripe_payment_intent_id",
        "customer__email",
        "customer__first_name",
        "customer__last_name",
    ]
    readonly_fields = [
        "client_secret",
        "created_at",
        "updated_at",
        "stripe_intent_link",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Payment Intent",
            {"fields": ("stripe_payment_intent_id", "status")},
        ),
        (
            "Amount",
            {"fields": ("amount", "currency")},
        ),
        (
            "Customer & Payment Method",
            {"fields": ("customer", "payment_method")},
        ),
        (
            "Related Transaction",
            {"fields": ("transaction",)},
        ),
        (
            "Stripe Details",
            {
                "fields": ("client_secret", "stripe_intent_link"),
                "classes": ("collapse",),
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def status_display(self, obj):
        colors = {
            "requires_payment_method": "orange",
            "requires_confirmation": "orange",
            "requires_action": "blue",
            "processing": "blue",
            "requires_capture": "blue",
            "canceled": "gray",
            "succeeded": "green",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def amount_display(self, obj):
        return f"{obj.amount} {obj.currency.symbol}"

    amount_display.short_description = "Amount"

    def stripe_intent_link(self, obj):
        if obj.stripe_payment_intent_id:
            stripe_url = f"https://dashboard.stripe.com/payments/{obj.stripe_payment_intent_id}"
            return format_html(
                '<a href="{}" target="_blank">View in Stripe</a>', stripe_url
            )
        return "-"

    stripe_intent_link.short_description = "Stripe Link"
