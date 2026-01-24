"""
Stripe Connect Admin - Marketplace Payment Infrastructure Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    ConnectedAccount,
    StripeConnectOnboarding,
    PlatformFee,
    PayoutSchedule,
    Transfer,
    BalanceTransaction,
)


@admin.register(ConnectedAccount)
class ConnectedAccountAdmin(admin.ModelAdmin):
    list_display = [
        "provider",
        "stripe_account_id",
        "account_type",
        "status_display",
        "capabilities_display",
        "requirements_pending",
        "created_at",
    ]
    list_filter = ["status", "account_type", "requirements_pending", "country"]
    search_fields = [
        "stripe_account_id",
        "provider__email",
        "provider__first_name",
        "provider__last_name",
    ]
    readonly_fields = [
        "stripe_account_id",
        "created_at",
        "updated_at",
        "dashboard_link_expires",
        "stripe_dashboard_link",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Account Details",
            {
                "fields": (
                    "provider",
                    "stripe_account_id",
                    "account_type",
                    "status",
                )
            },
        ),
        (
            "Capabilities",
            {
                "fields": (
                    "charges_enabled",
                    "payouts_enabled",
                    "transfers_enabled",
                )
            },
        ),
        (
            "Requirements",
            {
                "fields": (
                    "requirements_pending",
                    "requirements",
                )
            },
        ),
        (
            "Verification",
            {
                "fields": (
                    "verification_status",
                    "verification_disabled_reason",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Business Details",
            {
                "fields": (
                    "business_type",
                    "country",
                    "default_currency",
                    "email",
                )
            },
        ),
        (
            "Stripe Dashboard",
            {
                "fields": (
                    "dashboard_link_expires",
                    "stripe_dashboard_link",
                ),
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
            "incomplete": "orange",
            "pending": "blue",
            "enabled": "green",
            "disabled": "red",
            "rejected": "darkred",
        }
        color = colors.get(obj.status, "black")
        status_text = obj.get_status_display()

        # Add warning icon if requirements pending
        if obj.requirements_pending:
            status_text += " ⚠️"

        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            status_text,
        )

    status_display.short_description = "Status"

    def capabilities_display(self, obj):
        capabilities = []
        if obj.charges_enabled:
            capabilities.append('<span style="color: green;">✓ Charges</span>')
        if obj.payouts_enabled:
            capabilities.append('<span style="color: green;">✓ Payouts</span>')
        if obj.transfers_enabled:
            capabilities.append('<span style="color: green;">✓ Transfers</span>')

        if not capabilities:
            return format_html('<span style="color: gray;">None</span>')

        return format_html(' | '.join(capabilities))

    capabilities_display.short_description = "Capabilities"

    def stripe_dashboard_link(self, obj):
        if obj.stripe_account_id:
            stripe_url = f"https://dashboard.stripe.com/connect/accounts/{obj.stripe_account_id}"
            return format_html(
                '<a href="{}" target="_blank">View in Stripe Dashboard</a>',
                stripe_url
            )
        return "-"

    stripe_dashboard_link.short_description = "Stripe Dashboard"


@admin.register(StripeConnectOnboarding)
class StripeConnectOnboardingAdmin(admin.ModelAdmin):
    list_display = [
        "connected_account_link",
        "status_display",
        "onboarding_url_valid",
        "completed_at",
        "created_at",
    ]
    list_filter = ["status", "created_at"]
    search_fields = [
        "connected_account__provider__email",
        "connected_account__provider__first_name",
        "connected_account__provider__last_name",
    ]
    readonly_fields = [
        "onboarding_url_expires",
        "completed_at",
        "created_at",
        "updated_at",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Onboarding Details",
            {"fields": ("connected_account", "status")},
        ),
        (
            "Onboarding Link",
            {
                "fields": (
                    "onboarding_url",
                    "onboarding_url_expires",
                )
            },
        ),
        (
            "Completion",
            {"fields": ("completed_at",)},
        ),
        (
            "URLs",
            {
                "fields": ("return_url", "refresh_url"),
                "classes": ("collapse",),
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def connected_account_link(self, obj):
        url = reverse(
            "admin:stripe_connect_connectedaccount_change",
            args=[obj.connected_account.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.connected_account.provider.get_full_name(),
        )

    connected_account_link.short_description = "Connected Account"

    def status_display(self, obj):
        colors = {
            "not_started": "gray",
            "in_progress": "blue",
            "completed": "green",
            "failed": "red",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def onboarding_url_valid(self, obj):
        if obj.is_onboarding_url_valid:
            return format_html('<span style="color: green;">✓ Valid</span>')
        return format_html('<span style="color: red;">✗ Expired</span>')

    onboarding_url_valid.short_description = "URL Valid"


@admin.register(PlatformFee)
class PlatformFeeAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "fee_structure_display",
        "applies_to",
        "is_active",
        "created_at",
    ]
    list_filter = ["is_active", "applies_to"]
    search_fields = ["name", "description"]
    readonly_fields = ["created_at", "updated_at"]

    fieldsets = (
        (
            "Fee Information",
            {"fields": ("name", "description", "applies_to")},
        ),
        (
            "Fee Structure",
            {
                "fields": (
                    "percentage",
                    "fixed_amount",
                    "currency",
                )
            },
        ),
        (
            "Limits",
            {
                "fields": ("min_fee", "max_fee"),
            },
        ),
        (
            "Status",
            {"fields": ("is_active",)},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def fee_structure_display(self, obj):
        parts = []
        if obj.percentage > 0:
            parts.append(f"{obj.percentage}%")
        if obj.fixed_amount > 0:
            parts.append(f"{obj.currency} {obj.fixed_amount}")

        fee_display = " + ".join(parts) if parts else "Free"

        # Add limits if any
        limits = []
        if obj.min_fee:
            limits.append(f"min: {obj.currency} {obj.min_fee}")
        if obj.max_fee:
            limits.append(f"max: {obj.currency} {obj.max_fee}")

        if limits:
            fee_display += f" ({', '.join(limits)})"

        return fee_display

    fee_structure_display.short_description = "Fee Structure"


@admin.register(PayoutSchedule)
class PayoutScheduleAdmin(admin.ModelAdmin):
    list_display = [
        "connected_account_link",
        "schedule_display",
        "minimum_payout_display",
        "delay_days",
        "is_active",
    ]
    list_filter = ["interval", "is_active"]
    search_fields = [
        "connected_account__provider__email",
        "connected_account__provider__first_name",
        "connected_account__provider__last_name",
    ]
    readonly_fields = ["created_at", "updated_at"]

    fieldsets = (
        (
            "Payout Schedule",
            {
                "fields": (
                    "connected_account",
                    "interval",
                    "weekly_anchor",
                    "monthly_anchor",
                    "delay_days",
                )
            },
        ),
        (
            "Minimum Payout",
            {
                "fields": ("minimum_payout", "currency")
            },
        ),
        (
            "Status",
            {"fields": ("is_active",)},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def connected_account_link(self, obj):
        url = reverse(
            "admin:stripe_connect_connectedaccount_change",
            args=[obj.connected_account.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.connected_account.provider.get_full_name(),
        )

    connected_account_link.short_description = "Connected Account"

    def schedule_display(self, obj):
        schedule = obj.get_interval_display()
        if obj.interval == PayoutSchedule.Interval.WEEKLY:
            schedule += f" ({obj.get_weekly_anchor_display()})"
        elif obj.interval == PayoutSchedule.Interval.MONTHLY:
            schedule += f" (Day {obj.monthly_anchor})"
        return schedule

    schedule_display.short_description = "Schedule"

    def minimum_payout_display(self, obj):
        return f"{obj.currency} {obj.minimum_payout}"

    minimum_payout_display.short_description = "Minimum Payout"


@admin.register(Transfer)
class TransferAdmin(admin.ModelAdmin):
    list_display = [
        "transfer_id",
        "connected_account_link",
        "amount_display",
        "status_display",
        "arrival_date",
        "reversed",
        "created_at",
    ]
    list_filter = ["status", "reversed", "created_at"]
    search_fields = [
        "transfer_id",
        "stripe_transfer_id",
        "connected_account__provider__email",
    ]
    readonly_fields = [
        "transfer_id",
        "stripe_transfer_id",
        "created_at_stripe",
        "created_at",
        "updated_at",
        "reversed_at",
        "stripe_transfer_link",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Transfer Details",
            {
                "fields": (
                    "transfer_id",
                    "stripe_transfer_id",
                    "connected_account",
                    "status",
                )
            },
        ),
        (
            "Amount",
            {"fields": ("amount", "currency")},
        ),
        (
            "Source",
            {"fields": ("source_transaction", "description")},
        ),
        (
            "Dates",
            {
                "fields": (
                    "created_at_stripe",
                    "arrival_date",
                )
            },
        ),
        (
            "Failure Details",
            {
                "fields": ("failure_code", "failure_message"),
                "classes": ("collapse",),
            },
        ),
        (
            "Reversal",
            {
                "fields": ("reversed", "reversed_at"),
            },
        ),
        (
            "Stripe",
            {
                "fields": ("stripe_transfer_link",),
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
            "pending": "orange",
            "in_transit": "blue",
            "paid": "green",
            "failed": "red",
            "canceled": "gray",
        }
        color = colors.get(obj.status, "black")
        status_text = obj.get_status_display()

        if obj.reversed:
            status_text += " (Reversed)"
            color = "purple"

        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            status_text,
        )

    status_display.short_description = "Status"

    def amount_display(self, obj):
        return f"{obj.currency} {obj.amount}"

    amount_display.short_description = "Amount"

    def connected_account_link(self, obj):
        url = reverse(
            "admin:stripe_connect_connectedaccount_change",
            args=[obj.connected_account.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.connected_account.provider.get_full_name(),
        )

    connected_account_link.short_description = "Connected Account"

    def stripe_transfer_link(self, obj):
        if obj.stripe_transfer_id:
            stripe_url = f"https://dashboard.stripe.com/transfers/{obj.stripe_transfer_id}"
            return format_html(
                '<a href="{}" target="_blank">View in Stripe</a>',
                stripe_url
            )
        return "-"

    stripe_transfer_link.short_description = "Stripe Link"


@admin.register(BalanceTransaction)
class BalanceTransactionAdmin(admin.ModelAdmin):
    list_display = [
        "stripe_balance_transaction_id",
        "connected_account_link",
        "transaction_type",
        "amount_display",
        "fee_display",
        "net_display",
        "available_on",
    ]
    list_filter = ["transaction_type", "created_at_stripe"]
    search_fields = [
        "stripe_balance_transaction_id",
        "connected_account__provider__email",
        "source_id",
    ]
    readonly_fields = [
        "stripe_balance_transaction_id",
        "net",
        "created_at_stripe",
        "available_on",
        "created_at",
        "updated_at",
    ]
    date_hierarchy = "created_at_stripe"

    fieldsets = (
        (
            "Transaction Details",
            {
                "fields": (
                    "stripe_balance_transaction_id",
                    "connected_account",
                    "transaction_type",
                )
            },
        ),
        (
            "Amounts",
            {
                "fields": (
                    "amount",
                    "fee",
                    "net",
                    "currency",
                )
            },
        ),
        (
            "Source",
            {
                "fields": (
                    "source_id",
                    "transfer",
                    "description",
                )
            },
        ),
        (
            "Dates",
            {
                "fields": (
                    "created_at_stripe",
                    "available_on",
                )
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def amount_display(self, obj):
        sign = "+" if obj.amount >= 0 else ""
        return f"{sign}{obj.amount} {obj.currency}"

    amount_display.short_description = "Amount"

    def fee_display(self, obj):
        return f"-{obj.fee} {obj.currency}"

    fee_display.short_description = "Fee"

    def net_display(self, obj):
        sign = "+" if obj.net >= 0 else ""
        color = "green" if obj.net >= 0 else "red"
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}{} {}</span>',
            color,
            sign,
            obj.net,
            obj.currency,
        )

    net_display.short_description = "Net"

    def connected_account_link(self, obj):
        url = reverse(
            "admin:stripe_connect_connectedaccount_change",
            args=[obj.connected_account.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.connected_account.provider.get_full_name(),
        )

    connected_account_link.short_description = "Connected Account"
