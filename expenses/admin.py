"""
Expenses Admin - Business Expense Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    ExpenseCategory,
    ExpenseReport,
    ExpenseLineItem,
    ExpenseApproval,
    Reimbursement,
    MileageRate,
)


@admin.register(ExpenseCategory)
class ExpenseCategoryAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "parent",
        "requires_receipt",
        "limits_display",
        "gl_code",
        "is_active",
    ]
    list_filter = ["is_active", "requires_receipt", "is_taxable"]
    search_fields = ["name", "description", "gl_code"]
    prepopulated_fields = {"slug": ("name",)}
    readonly_fields = ["created_at", "updated_at"]

    fieldsets = (
        (
            "Category Information",
            {"fields": ("name", "slug", "description", "parent")},
        ),
        (
            "Requirements",
            {"fields": ("requires_receipt", "requires_justification")},
        ),
        (
            "Limits",
            {"fields": ("daily_limit", "monthly_limit")},
        ),
        (
            "Tax Treatment",
            {"fields": ("is_taxable",)},
        ),
        (
            "Accounting",
            {"fields": ("gl_code",)},
        ),
        (
            "Status",
            {"fields": ("is_active",)},
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def limits_display(self, obj):
        limits = []
        if obj.daily_limit:
            limits.append(f"Daily: ${obj.daily_limit}")
        if obj.monthly_limit:
            limits.append(f"Monthly: ${obj.monthly_limit}")
        return " | ".join(limits) if limits else "-"

    limits_display.short_description = "Limits"


class ExpenseLineItemInline(admin.TabularInline):
    model = ExpenseLineItem
    extra = 0
    fields = [
        'expense_date',
        'category',
        'description',
        'amount',
        'merchant',
        'receipt_file',
        'is_reimbursable',
    ]
    readonly_fields = []


class ExpenseApprovalInline(admin.TabularInline):
    model = ExpenseApproval
    extra = 0
    readonly_fields = ['approval_level', 'approver_role', 'requested_at', 'responded_at']
    fields = [
        'approval_level',
        'approver',
        'approver_role',
        'action',
        'comments',
        'responded_at',
    ]


@admin.register(ExpenseReport)
class ExpenseReportAdmin(admin.ModelAdmin):
    list_display = [
        "report_number",
        "employee",
        "title",
        "status_display",
        "period_display",
        "total_amount_display",
        "reimbursable_amount_display",
        "submitted_at",
    ]
    list_filter = ["status", "submitted_at", "period_start"]
    search_fields = [
        "report_number",
        "employee__user__email",
        "employee__user__first_name",
        "employee__user__last_name",
        "title",
    ]
    readonly_fields = [
        "report_number",
        "total_amount",
        "reimbursable_amount",
        "non_reimbursable_amount",
        "submitted_at",
        "approved_at",
        "rejected_at",
        "paid_at",
        "created_at",
        "updated_at",
    ]
    date_hierarchy = "submitted_at"
    inlines = [ExpenseLineItemInline, ExpenseApprovalInline]

    fieldsets = (
        (
            "Report Details",
            {
                "fields": (
                    "report_number",
                    "employee",
                    "title",
                    "description",
                    "purpose",
                    "status",
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
                    "total_amount",
                    "reimbursable_amount",
                    "non_reimbursable_amount",
                )
            },
        ),
        (
            "Dates",
            {
                "fields": (
                    "submitted_at",
                    "approved_at",
                    "rejected_at",
                    "paid_at",
                )
            },
        ),
        (
            "Notes",
            {"fields": ("employee_notes", "approver_notes")},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def status_display(self, obj):
        colors = {
            "draft": "gray",
            "submitted": "blue",
            "pending_approval": "orange",
            "approved": "green",
            "rejected": "red",
            "paid": "darkgreen",
            "partially_paid": "lightgreen",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def period_display(self, obj):
        return f"{obj.period_start} → {obj.period_end}"

    period_display.short_description = "Period"

    def total_amount_display(self, obj):
        return f"${obj.total_amount:,.2f}"

    total_amount_display.short_description = "Total"

    def reimbursable_amount_display(self, obj):
        return format_html(
            '<span style="color: green; font-weight: bold;">${:,.2f}</span>',
            obj.reimbursable_amount
        )

    reimbursable_amount_display.short_description = "Reimbursable"


@admin.register(ExpenseLineItem)
class ExpenseLineItemAdmin(admin.ModelAdmin):
    list_display = [
        "expense_report_link",
        "expense_date",
        "category",
        "description_short",
        "merchant",
        "amount_display",
        "receipt_status",
        "is_reimbursable",
    ]
    list_filter = ["expense_type", "category", "is_reimbursable", "is_billable"]
    search_fields = [
        "expense_report__report_number",
        "description",
        "merchant",
    ]
    readonly_fields = ["created_at", "updated_at"]
    date_hierarchy = "expense_date"

    fieldsets = (
        (
            "Expense Details",
            {
                "fields": (
                    "expense_report",
                    "expense_type",
                    "category",
                    "description",
                    "expense_date",
                )
            },
        ),
        (
            "Amount",
            {"fields": ("amount", "currency")},
        ),
        (
            "Merchant/Vendor",
            {"fields": ("merchant", "location")},
        ),
        (
            "Mileage",
            {
                "fields": (
                    "mileage_distance",
                    "mileage_rate",
                    "mileage_start_location",
                    "mileage_end_location",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Receipt",
            {"fields": ("receipt_file", "receipt_url")},
        ),
        (
            "Classification",
            {"fields": ("is_reimbursable", "is_billable", "client_name")},
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

    def expense_report_link(self, obj):
        url = reverse(
            "admin:expenses_expensereport_change",
            args=[obj.expense_report.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.expense_report.report_number,
        )

    expense_report_link.short_description = "Expense Report"

    def description_short(self, obj):
        if len(obj.description) > 50:
            return obj.description[:47] + "..."
        return obj.description

    description_short.short_description = "Description"

    def amount_display(self, obj):
        return f"{obj.currency} {obj.amount:,.2f}"

    amount_display.short_description = "Amount"

    def receipt_status(self, obj):
        if obj.receipt_file or obj.receipt_url:
            return format_html('<span style="color: green;">✓ Attached</span>')
        return format_html('<span style="color: orange;">No receipt</span>')

    receipt_status.short_description = "Receipt"


@admin.register(ExpenseApproval)
class ExpenseApprovalAdmin(admin.ModelAdmin):
    list_display = [
        "expense_report_link",
        "approval_level",
        "approver",
        "approver_role",
        "action_display",
        "requested_at",
        "responded_at",
    ]
    list_filter = ["action", "approval_level", "requested_at"]
    search_fields = [
        "expense_report__report_number",
        "approver__email",
        "approver__first_name",
        "approver__last_name",
    ]
    readonly_fields = ["requested_at", "responded_at"]

    fieldsets = (
        (
            "Approval Details",
            {
                "fields": (
                    "expense_report",
                    "approval_level",
                    "approver",
                    "approver_role",
                )
            },
        ),
        (
            "Action",
            {"fields": ("action", "comments")},
        ),
        (
            "Dates",
            {"fields": ("requested_at", "responded_at")},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
    )

    def expense_report_link(self, obj):
        url = reverse(
            "admin:expenses_expensereport_change",
            args=[obj.expense_report.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.expense_report.report_number,
        )

    expense_report_link.short_description = "Expense Report"

    def action_display(self, obj):
        colors = {
            "pending": "orange",
            "approved": "green",
            "rejected": "red",
            "returned": "blue",
        }
        color = colors.get(obj.action, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_action_display(),
        )

    action_display.short_description = "Action"


@admin.register(Reimbursement)
class ReimbursementAdmin(admin.ModelAdmin):
    list_display = [
        "reimbursement_id",
        "employee",
        "expense_report_link",
        "amount_display",
        "status_display",
        "payment_method",
        "paid_at",
    ]
    list_filter = ["status", "payment_method", "created_at"]
    search_fields = [
        "reimbursement_id",
        "employee__user__email",
        "employee__user__first_name",
        "employee__user__last_name",
        "expense_report__report_number",
    ]
    readonly_fields = [
        "reimbursement_id",
        "approved_at",
        "paid_at",
        "created_at",
        "updated_at",
    ]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Reimbursement Details",
            {
                "fields": (
                    "reimbursement_id",
                    "expense_report",
                    "employee",
                    "status",
                )
            },
        ),
        (
            "Amount",
            {"fields": ("amount", "currency")},
        ),
        (
            "Payment",
            {
                "fields": (
                    "payment_method",
                    "payment_transaction",
                    "payroll_run",
                )
            },
        ),
        (
            "Dates",
            {"fields": ("approved_at", "paid_at")},
        ),
        (
            "Notes",
            {"fields": ("notes",)},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def expense_report_link(self, obj):
        url = reverse(
            "admin:expenses_expensereport_change",
            args=[obj.expense_report.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.expense_report.report_number,
        )

    expense_report_link.short_description = "Expense Report"

    def amount_display(self, obj):
        return format_html(
            '<span style="color: green; font-weight: bold;">{} {:,.2f}</span>',
            obj.currency,
            obj.amount
        )

    amount_display.short_description = "Amount"

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


@admin.register(MileageRate)
class MileageRateAdmin(admin.ModelAdmin):
    list_display = [
        "country",
        "region",
        "rate_display",
        "unit",
        "purpose",
        "effective_period",
        "is_active",
    ]
    list_filter = ["country", "purpose", "is_active"]
    search_fields = ["country", "region"]
    readonly_fields = ["created_at", "updated_at"]

    fieldsets = (
        (
            "Location",
            {"fields": ("country", "region")},
        ),
        (
            "Rate",
            {"fields": ("rate", "unit", "purpose")},
        ),
        (
            "Effective Period",
            {"fields": ("effective_start", "effective_end")},
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

    def rate_display(self, obj):
        return f"${obj.rate}/{obj.unit}"

    rate_display.short_description = "Rate"

    def effective_period(self, obj):
        if obj.effective_end:
            return f"{obj.effective_start} → {obj.effective_end}"
        return f"{obj.effective_start} → Ongoing"

    effective_period.short_description = "Effective Period"
