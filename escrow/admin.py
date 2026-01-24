"""
Escrow Admin - Marketplace Escrow Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    EscrowTransaction,
    MilestonePayment,
    EscrowRelease,
    Dispute,
    EscrowPayout,
    EscrowAudit,
)


class EscrowAuditInline(admin.TabularInline):
    model = EscrowAudit
    extra = 0
    readonly_fields = ['action', 'description', 'actor', 'created_at']
    can_delete = False
    max_num = 0  # Read-only

    fields = ['created_at', 'action', 'actor', 'description']

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(EscrowTransaction)
class EscrowTransactionAdmin(admin.ModelAdmin):
    list_display = [
        "escrow_id",
        "client",
        "provider",
        "amount_display",
        "status_display",
        "platform_fee_display",
        "payout_amount_display",
        "work_completed_display",
        "created_at",
    ]
    list_filter = ["status", "created_at"]
    search_fields = [
        "escrow_id",
        "client__email",
        "client__first_name",
        "client__last_name",
        "provider__email",
        "provider__first_name",
        "provider__last_name",
    ]
    readonly_fields = [
        "escrow_id",
        "platform_fee_amount",
        "payout_amount",
        "auto_release_at",
        "created_at",
        "updated_at",
        "funded_at",
        "released_at",
        "refunded_at",
    ]
    date_hierarchy = "created_at"
    inlines = [EscrowAuditInline]

    fieldsets = (
        (
            "Escrow Details",
            {"fields": ("escrow_id", "status", "description")},
        ),
        (
            "Amount",
            {
                "fields": (
                    "amount",
                    "currency",
                    "platform_fee_percentage",
                    "platform_fee_amount",
                    "payout_amount",
                )
            },
        ),
        (
            "Parties",
            {"fields": ("client", "provider")},
        ),
        (
            "Related Object",
            {
                "fields": ("content_type", "object_id"),
                "classes": ("collapse",),
            },
        ),
        (
            "Release Conditions",
            {
                "fields": (
                    "auto_release_days",
                    "work_completed_at",
                    "auto_release_at",
                )
            },
        ),
        (
            "Payment Integration",
            {"fields": ("payment_transaction",)},
        ),
        (
            "Dates",
            {
                "fields": (
                    "funded_at",
                    "released_at",
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
            "funded": "blue",
            "released": "green",
            "refunded": "purple",
            "disputed": "red",
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
        return f"{obj.currency} {obj.amount}"

    amount_display.short_description = "Amount"

    def platform_fee_display(self, obj):
        return f"{obj.platform_fee_percentage}% ({obj.currency} {obj.platform_fee_amount})"

    platform_fee_display.short_description = "Platform Fee"

    def payout_amount_display(self, obj):
        return f"{obj.currency} {obj.payout_amount}"

    payout_amount_display.short_description = "Payout Amount"

    def work_completed_display(self, obj):
        if obj.work_completed_at:
            return format_html(
                '<span style="color: green;">✓ {}</span>',
                obj.work_completed_at.strftime('%Y-%m-%d %H:%M'),
            )
        return format_html('<span style="color: gray;">Not completed</span>')

    work_completed_display.short_description = "Work Completed"


@admin.register(MilestonePayment)
class MilestonePaymentAdmin(admin.ModelAdmin):
    list_display = [
        "milestone_number",
        "title",
        "amount_display",
        "status_display",
        "due_date",
        "escrow_link",
        "created_at",
    ]
    list_filter = ["status", "due_date"]
    search_fields = ["title", "description"]
    readonly_fields = [
        "created_at",
        "updated_at",
        "started_at",
        "completed_at",
        "approved_at",
        "paid_at",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Milestone Details",
            {
                "fields": (
                    "milestone_number",
                    "title",
                    "description",
                    "status",
                )
            },
        ),
        (
            "Amount",
            {"fields": ("amount", "currency")},
        ),
        (
            "Escrow",
            {"fields": ("escrow_transaction",)},
        ),
        (
            "Deliverables",
            {"fields": ("deliverables", "delivered_files")},
        ),
        (
            "Dates",
            {
                "fields": (
                    "due_date",
                    "started_at",
                    "completed_at",
                    "approved_at",
                    "paid_at",
                )
            },
        ),
        (
            "Related Object",
            {
                "fields": ("content_type", "object_id"),
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
            "pending": "gray",
            "funded": "blue",
            "in_progress": "orange",
            "completed": "purple",
            "approved": "lightgreen",
            "paid": "green",
            "disputed": "red",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def amount_display(self, obj):
        return f"{obj.currency} {obj.amount}"

    amount_display.short_description = "Amount"

    def escrow_link(self, obj):
        if obj.escrow_transaction:
            url = reverse(
                "admin:escrow_escrowtransaction_change",
                args=[obj.escrow_transaction.pk],
            )
            return format_html(
                '<a href="{}">{}</a>',
                url,
                obj.escrow_transaction.escrow_id,
            )
        return "-"

    escrow_link.short_description = "Escrow"


@admin.register(EscrowRelease)
class EscrowReleaseAdmin(admin.ModelAdmin):
    list_display = [
        "escrow_link",
        "release_type",
        "amount_display",
        "approved_by",
        "is_automatic",
        "released_at",
    ]
    list_filter = ["release_type", "is_automatic", "released_at"]
    search_fields = [
        "escrow_transaction__escrow_id",
        "approved_by__email",
    ]
    readonly_fields = ["released_at"]
    date_hierarchy = "released_at"

    fieldsets = (
        (
            "Release Details",
            {
                "fields": (
                    "escrow_transaction",
                    "release_type",
                    "amount",
                )
            },
        ),
        (
            "Approval",
            {
                "fields": (
                    "approved_by",
                    "approval_reason",
                    "is_automatic",
                )
            },
        ),
        (
            "Payout",
            {"fields": ("payout_transaction",)},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamp",
            {"fields": ("released_at",)},
        ),
    )

    def escrow_link(self, obj):
        url = reverse(
            "admin:escrow_escrowtransaction_change",
            args=[obj.escrow_transaction.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.escrow_transaction.escrow_id,
        )

    escrow_link.short_description = "Escrow"

    def amount_display(self, obj):
        return f"{obj.escrow_transaction.currency} {obj.amount}"

    amount_display.short_description = "Amount"


@admin.register(Dispute)
class DisputeAdmin(admin.ModelAdmin):
    list_display = [
        "dispute_id",
        "escrow_link",
        "initiated_by",
        "status_display",
        "resolution_display",
        "opened_at",
        "resolved_at",
    ]
    list_filter = ["status", "resolution", "opened_at"]
    search_fields = [
        "dispute_id",
        "escrow_transaction__escrow_id",
        "initiated_by__email",
    ]
    readonly_fields = [
        "dispute_id",
        "opened_at",
        "closed_at",
        "created_at",
        "updated_at",
    ]
    date_hierarchy = "opened_at"

    fieldsets = (
        (
            "Dispute Details",
            {
                "fields": (
                    "dispute_id",
                    "escrow_transaction",
                    "initiated_by",
                    "status",
                )
            },
        ),
        (
            "Dispute Information",
            {"fields": ("reason", "evidence")},
        ),
        (
            "Resolution",
            {
                "fields": (
                    "resolution",
                    "resolution_notes",
                    "resolved_by",
                    "resolved_at",
                )
            },
        ),
        (
            "Amounts",
            {
                "fields": (
                    "provider_amount",
                    "client_refund_amount",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Dates",
            {"fields": ("opened_at", "closed_at")},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def status_display(self, obj):
        colors = {
            "open": "orange",
            "under_review": "blue",
            "resolved": "green",
            "escalated": "red",
            "closed": "gray",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def resolution_display(self, obj):
        if obj.resolution:
            return obj.get_resolution_display()
        return "-"

    resolution_display.short_description = "Resolution"

    def escrow_link(self, obj):
        url = reverse(
            "admin:escrow_escrowtransaction_change",
            args=[obj.escrow_transaction.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.escrow_transaction.escrow_id,
        )

    escrow_link.short_description = "Escrow"


@admin.register(EscrowPayout)
class EscrowPayoutAdmin(admin.ModelAdmin):
    list_display = [
        "payout_id",
        "escrow_link",
        "provider",
        "gross_amount_display",
        "platform_fee_display",
        "net_amount_display",
        "status_display",
        "initiated_at",
        "paid_at",
    ]
    list_filter = ["status", "initiated_at"]
    search_fields = [
        "payout_id",
        "escrow_transaction__escrow_id",
        "provider__email",
        "stripe_transfer_id",
    ]
    readonly_fields = [
        "payout_id",
        "created_at",
        "updated_at",
        "initiated_at",
        "paid_at",
        "failed_at",
    ]
    date_hierarchy = "initiated_at"

    fieldsets = (
        (
            "Payout Details",
            {
                "fields": (
                    "payout_id",
                    "escrow_transaction",
                    "provider",
                    "status",
                )
            },
        ),
        (
            "Amounts",
            {
                "fields": (
                    "gross_amount",
                    "platform_fee",
                    "net_amount",
                    "currency",
                )
            },
        ),
        (
            "Payment",
            {
                "fields": (
                    "payment_transaction",
                    "stripe_transfer_id",
                )
            },
        ),
        (
            "Dates",
            {
                "fields": (
                    "initiated_at",
                    "paid_at",
                    "failed_at",
                )
            },
        ),
        (
            "Failure Details",
            {
                "fields": ("failure_reason",),
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
            "processing": "blue",
            "paid": "green",
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

    def gross_amount_display(self, obj):
        return f"{obj.currency} {obj.gross_amount}"

    gross_amount_display.short_description = "Gross Amount"

    def platform_fee_display(self, obj):
        return f"{obj.currency} {obj.platform_fee}"

    platform_fee_display.short_description = "Platform Fee"

    def net_amount_display(self, obj):
        return f"{obj.currency} {obj.net_amount}"

    net_amount_display.short_description = "Net Amount"

    def escrow_link(self, obj):
        url = reverse(
            "admin:escrow_escrowtransaction_change",
            args=[obj.escrow_transaction.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.escrow_transaction.escrow_id,
        )

    escrow_link.short_description = "Escrow"


@admin.register(EscrowAudit)
class EscrowAuditAdmin(admin.ModelAdmin):
    list_display = [
        "escrow_link",
        "action",
        "actor",
        "description_short",
        "created_at",
    ]
    list_filter = ["action", "created_at"]
    search_fields = [
        "escrow_transaction__escrow_id",
        "actor__email",
        "description",
    ]
    readonly_fields = [
        "escrow_transaction",
        "action",
        "description",
        "actor",
        "previous_state",
        "new_state",
        "ip_address",
        "user_agent",
        "created_at",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Audit Details",
            {
                "fields": (
                    "escrow_transaction",
                    "action",
                    "description",
                    "actor",
                )
            },
        ),
        (
            "State Changes",
            {
                "fields": ("previous_state", "new_state"),
                "classes": ("collapse",),
            },
        ),
        (
            "Security",
            {
                "fields": ("ip_address", "user_agent"),
                "classes": ("collapse",),
            },
        ),
        (
            "Timestamp",
            {"fields": ("created_at",)},
        ),
    )

    def has_add_permission(self, request):
        """Audit logs are created automatically, no manual adds"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Audit logs should never be deleted"""
        return False

    def escrow_link(self, obj):
        url = reverse(
            "admin:escrow_escrowtransaction_change",
            args=[obj.escrow_transaction.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.escrow_transaction.escrow_id,
        )

    escrow_link.short_description = "Escrow"

    def description_short(self, obj):
        if len(obj.description) > 80:
            return obj.description[:77] + "..."
        return obj.description

    description_short.short_description = "Description"
