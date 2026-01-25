"""
Payroll Admin - Employee Payroll Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    PayrollRun,
    DirectDeposit,
    EmployeePayment,
    PayrollDeduction,
    PayStub,
    PayrollTax,
)


class EmployeePaymentInline(admin.TabularInline):
    model = EmployeePayment
    extra = 0
    readonly_fields = ['net_amount', 'total_taxes', 'total_deductions']
    fields = [
        'employee',
        'gross_amount',
        'total_taxes',
        'total_deductions',
        'net_amount',
        'paid',
    ]
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(PayrollRun)
class PayrollRunAdmin(admin.ModelAdmin):
    list_display = [
        "run_number",
        "frequency",
        "pay_period_display",
        "pay_date",
        "status_display",
        "employee_count",
        "total_gross_display",
        "total_net_display",
        "created_by",
    ]
    list_filter = ["status", "frequency", "pay_date"]
    search_fields = ["run_number"]
    readonly_fields = [
        "run_number",
        "employee_count",
        "total_gross",
        "total_net",
        "total_taxes",
        "total_deductions",
        "created_at",
        "updated_at",
        "approved_at",
        "paid_at",
    ]
    date_hierarchy = "pay_date"
    inlines = [EmployeePaymentInline]

    fieldsets = (
        (
            "Payroll Run Details",
            {
                "fields": (
                    "run_number",
                    "frequency",
                    "status",
                )
            },
        ),
        (
            "Pay Period",
            {
                "fields": (
                    "pay_period_start",
                    "pay_period_end",
                    "pay_date",
                )
            },
        ),
        (
            "Totals",
            {
                "fields": (
                    "employee_count",
                    "total_gross",
                    "total_taxes",
                    "total_deductions",
                    "total_net",
                )
            },
        ),
        (
            "Approval",
            {
                "fields": (
                    "created_by",
                    "approved_by",
                    "approved_at",
                )
            },
        ),
        (
            "Payment",
            {"fields": ("paid_at",)},
        ),
        (
            "Notes",
            {"fields": ("notes",), "classes": ("collapse",)},
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
            "processing": "blue",
            "approved": "lightblue",
            "paid": "green",
            "failed": "red",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = "Status"

    def pay_period_display(self, obj):
        return f"{obj.pay_period_start} → {obj.pay_period_end}"

    pay_period_display.short_description = "Pay Period"

    def total_gross_display(self, obj):
        return f"${obj.total_gross:,.2f}"

    total_gross_display.short_description = "Total Gross"

    def total_net_display(self, obj):
        return f"${obj.total_net:,.2f}"

    total_net_display.short_description = "Total Net"


@admin.register(DirectDeposit)
class DirectDepositAdmin(admin.ModelAdmin):
    list_display = [
        "employee",
        "bank_name",
        "account_display",
        "account_type",
        "allocation_display",
        "is_primary",
        "verified",
    ]
    list_filter = ["account_type", "is_active", "is_primary", "verified"]
    search_fields = [
        "employee__user__email",
        "employee__user__first_name",
        "employee__user__last_name",
        "bank_name",
    ]
    readonly_fields = ["account_number_last4", "verified_at", "created_at", "updated_at"]

    fieldsets = (
        (
            "Employee",
            {"fields": ("employee",)},
        ),
        (
            "Bank Account",
            {
                "fields": (
                    "account_type",
                    "routing_number",
                    "account_number",
                    "account_number_last4",
                    "bank_name",
                )
            },
        ),
        (
            "Allocation",
            {
                "fields": (
                    "allocation_type",
                    "allocation_value",
                )
            },
        ),
        (
            "Status",
            {
                "fields": (
                    "is_active",
                    "is_primary",
                    "verified",
                    "verified_at",
                )
            },
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def account_display(self, obj):
        return f"****{obj.account_number_last4}"

    account_display.short_description = "Account"

    def allocation_display(self, obj):
        if obj.allocation_type == 'remainder':
            return "Remainder"
        elif obj.allocation_type == 'percentage':
            return f"{obj.allocation_value}%"
        elif obj.allocation_type == 'fixed':
            return f"${obj.allocation_value}"
        return "-"

    allocation_display.short_description = "Allocation"


class PayrollDeductionInline(admin.TabularInline):
    model = PayrollDeduction
    extra = 0
    fields = ['deduction_type', 'description', 'amount', 'pre_tax']


class PayrollTaxInline(admin.TabularInline):
    model = PayrollTax
    extra = 0
    readonly_fields = ['tax_type', 'taxable_amount', 'tax_rate', 'tax_amount']
    fields = ['tax_type', 'taxable_amount', 'tax_rate', 'tax_amount', 'jurisdiction']
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(EmployeePayment)
class EmployeePaymentAdmin(admin.ModelAdmin):
    list_display = [
        "employee",
        "payroll_run_link",
        "gross_amount_display",
        "total_taxes_display",
        "net_amount_display",
        "payment_method",
        "paid_display",
    ]
    list_filter = ["payroll_run__status", "payment_method", "paid"]
    search_fields = [
        "employee__user__email",
        "employee__user__first_name",
        "employee__user__last_name",
        "payroll_run__run_number",
    ]
    readonly_fields = [
        "total_taxes",
        "net_amount",
        "created_at",
        "updated_at",
        "paid_at",
    ]
    inlines = [PayrollDeductionInline, PayrollTaxInline]

    fieldsets = (
        (
            "Payment Details",
            {
                "fields": (
                    "payroll_run",
                    "employee",
                )
            },
        ),
        (
            "Earnings",
            {
                "fields": (
                    "gross_amount",
                    "regular_hours",
                    "overtime_hours",
                    "hourly_rate",
                    "bonus_amount",
                    "adjustment_amount",
                )
            },
        ),
        (
            "Taxes",
            {
                "fields": (
                    "federal_tax",
                    "state_tax",
                    "local_tax",
                    "social_security",
                    "medicare",
                    "total_taxes",
                )
            },
        ),
        (
            "Deductions",
            {"fields": ("total_deductions",)},
        ),
        (
            "Net Pay",
            {"fields": ("net_amount",)},
        ),
        (
            "Payment",
            {
                "fields": (
                    "payment_method",
                    "direct_deposit",
                    "payment_transaction",
                    "paid",
                    "paid_at",
                )
            },
        ),
        (
            "Year-to-Date",
            {
                "fields": ("ytd_gross", "ytd_taxes"),
                "classes": ("collapse",),
            },
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def payroll_run_link(self, obj):
        url = reverse("admin:payroll_payrollrun_change", args=[obj.payroll_run.pk])
        return format_html('<a href="{}">{}</a>', url, obj.payroll_run.run_number)

    payroll_run_link.short_description = "Payroll Run"

    def gross_amount_display(self, obj):
        return f"${obj.gross_amount:,.2f}"

    gross_amount_display.short_description = "Gross"

    def total_taxes_display(self, obj):
        return f"${obj.total_taxes:,.2f}"

    total_taxes_display.short_description = "Taxes"

    def net_amount_display(self, obj):
        return format_html(
            '<span style="color: green; font-weight: bold;">${:,.2f}</span>',
            obj.net_amount
        )

    net_amount_display.short_description = "Net Pay"

    def paid_display(self, obj):
        if obj.paid:
            return format_html('<span style="color: green;">✓ Paid</span>')
        return format_html('<span style="color: orange;">Pending</span>')

    paid_display.short_description = "Paid"


@admin.register(PayrollDeduction)
class PayrollDeductionAdmin(admin.ModelAdmin):
    list_display = [
        "employee_payment_link",
        "deduction_type",
        "description",
        "amount_display",
        "pre_tax",
    ]
    list_filter = ["deduction_type", "pre_tax"]
    search_fields = [
        "employee_payment__employee__user__email",
        "description",
    ]
    readonly_fields = ["created_at"]

    fieldsets = (
        (
            "Deduction Details",
            {
                "fields": (
                    "employee_payment",
                    "deduction_type",
                    "description",
                )
            },
        ),
        (
            "Amount",
            {"fields": ("amount", "pre_tax")},
        ),
        (
            "Timestamp",
            {"fields": ("created_at",)},
        ),
    )

    def employee_payment_link(self, obj):
        url = reverse(
            "admin:payroll_employeepayment_change",
            args=[obj.employee_payment.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.employee_payment.employee.user.get_full_name(),
        )

    employee_payment_link.short_description = "Employee Payment"

    def amount_display(self, obj):
        return f"${obj.amount:,.2f}"

    amount_display.short_description = "Amount"


@admin.register(PayStub)
class PayStubAdmin(admin.ModelAdmin):
    list_display = [
        "stub_number",
        "employee_payment_link",
        "employee_viewed_display",
        "pdf_available",
        "generated_at",
    ]
    list_filter = ["employee_viewed", "generated_at"]
    search_fields = [
        "stub_number",
        "employee_payment__employee__user__email",
    ]
    readonly_fields = [
        "stub_number",
        "generated_at",
        "employee_viewed_at",
    ]

    fieldsets = (
        (
            "Pay Stub Details",
            {"fields": ("stub_number", "employee_payment")},
        ),
        (
            "PDF",
            {"fields": ("pdf_file", "pdf_url")},
        ),
        (
            "Employee Access",
            {"fields": ("employee_viewed", "employee_viewed_at")},
        ),
        ("Metadata", {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            "Timestamp",
            {"fields": ("generated_at",)},
        ),
    )

    def employee_payment_link(self, obj):
        url = reverse(
            "admin:payroll_employeepayment_change",
            args=[obj.employee_payment.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.employee_payment.employee.user.get_full_name(),
        )

    employee_payment_link.short_description = "Employee"

    def employee_viewed_display(self, obj):
        if obj.employee_viewed:
            return format_html(
                '<span style="color: green;">✓ Viewed ({})</span>',
                obj.employee_viewed_at.strftime('%Y-%m-%d %H:%M') if obj.employee_viewed_at else 'N/A'
            )
        return format_html('<span style="color: gray;">Not viewed</span>')

    employee_viewed_display.short_description = "Viewed"

    def pdf_available(self, obj):
        if obj.pdf_file or obj.pdf_url:
            return format_html('<span style="color: green;">✓ Available</span>')
        return format_html('<span style="color: orange;">Not generated</span>')

    pdf_available.short_description = "PDF"


@admin.register(PayrollTax)
class PayrollTaxAdmin(admin.ModelAdmin):
    list_display = [
        "employee_payment_link",
        "tax_type",
        "jurisdiction",
        "taxable_amount_display",
        "tax_rate_display",
        "tax_amount_display",
    ]
    list_filter = ["tax_type", "jurisdiction"]
    search_fields = [
        "employee_payment__employee__user__email",
        "jurisdiction",
    ]
    readonly_fields = ["created_at"]

    fieldsets = (
        (
            "Tax Details",
            {
                "fields": (
                    "employee_payment",
                    "tax_type",
                    "jurisdiction",
                )
            },
        ),
        (
            "Calculation",
            {
                "fields": (
                    "taxable_amount",
                    "tax_rate",
                    "tax_amount",
                )
            },
        ),
        (
            "Calculation Data",
            {
                "fields": ("calculation_data",),
                "classes": ("collapse",),
            },
        ),
        (
            "Timestamp",
            {"fields": ("created_at",)},
        ),
    )

    def employee_payment_link(self, obj):
        url = reverse(
            "admin:payroll_employeepayment_change",
            args=[obj.employee_payment.pk],
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.employee_payment.employee.user.get_full_name(),
        )

    employee_payment_link.short_description = "Employee Payment"

    def taxable_amount_display(self, obj):
        return f"${obj.taxable_amount:,.2f}"

    taxable_amount_display.short_description = "Taxable Amount"

    def tax_rate_display(self, obj):
        return f"{obj.tax_rate * 100:.2f}%"

    tax_rate_display.short_description = "Tax Rate"

    def tax_amount_display(self, obj):
        return f"${obj.tax_amount:,.2f}"

    tax_amount_display.short_description = "Tax Amount"
