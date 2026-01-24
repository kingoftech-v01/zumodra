"""
Accounting Admin - QuickBooks/Xero Integration Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    AccountingProvider,
    ChartOfAccounts,
    JournalEntry,
    JournalEntryLine,
    AccountingSyncLog,
    FinancialReport,
    ReconciliationRecord,
)


class JournalEntryLineInline(admin.TabularInline):
    model = JournalEntryLine
    extra = 2
    fields = ['account', 'description', 'debit', 'credit']

    def has_add_permission(self, request, obj=None):
        # Can add lines to draft entries only
        if obj and obj.status != 'draft':
            return False
        return super().has_add_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        # Can delete lines from draft entries only
        if obj and obj.status != 'draft':
            return False
        return super().has_delete_permission(request, obj)


@admin.register(AccountingProvider)
class AccountingProviderAdmin(admin.ModelAdmin):
    list_display = [
        'provider_display',
        'status',
        'oauth_status',
        'last_sync_display',
        'sync_status',
    ]
    list_filter = ['provider', 'status']
    search_fields = ['realm_id', 'xero_tenant_id']
    readonly_fields = [
        'created_at',
        'updated_at',
        'last_sync',
        'token_expires_at',
        'oauth_link',
    ]

    fieldsets = (
        (
            'Provider Configuration',
            {
                'fields': (
                    'provider',
                )
            },
        ),
        (
            'OAuth Credentials',
            {
                'fields': (
                    'access_token',
                    'refresh_token',
                    'token_expires_at',
                    'realm_id',
                    'xero_tenant_id',
                ),
                'classes': ('collapse',),
            },
        ),
        (
            'Sync Status',
            {
                'fields': (
                    'last_sync',
                    'status',
                    'last_error',
                )
            },
        ),
        (
            'OAuth Link',
            {
                'fields': ('oauth_link',),
                'classes': ('collapse',),
            },
        ),
        ('Metadata', {'fields': ('metadata',), 'classes': ('collapse',)}),
        (
            'Timestamps',
            {'fields': ('created_at', 'updated_at'), 'classes': ('collapse',)},
        ),
    )

    def provider_display(self, obj):
        provider_names = {
            'quickbooks': 'QuickBooks Online',
            'xero': 'Xero',
            'manual': 'Manual Entry',
        }
        return provider_names.get(obj.provider, obj.provider)

    provider_display.short_description = 'Provider'

    def oauth_status(self, obj):
        if obj.is_token_expired:
            return format_html(
                '<span style="color: red; font-weight: bold;">⚠️ Expired</span>'
            )
        if obj.access_token:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ Connected</span>'
            )
        return format_html('<span style="color: gray;">Not Connected</span>')

    oauth_status.short_description = 'OAuth Status'

    def last_sync_display(self, obj):
        if obj.last_sync:
            return obj.last_sync.strftime('%Y-%m-%d %H:%M')
        return '-'

    last_sync_display.short_description = 'Last Sync'

    def sync_status(self, obj):
        colors = {
            'connected': 'green',
            'disconnected': 'gray',
            'error': 'red',
            'syncing': 'blue',
        }
        color = colors.get(obj.status, 'gray')

        if obj.status:
            status_text = obj.get_status_display()
            return format_html(
                '<span style="color: {}; font-weight: bold;">{}</span>',
                color,
                status_text,
            )
        return '-'

    sync_status.short_description = 'Sync Status'

    def oauth_link(self, obj):
        if obj.provider == 'quickbooks' and obj.realm_id:
            qbo_url = f"https://app.qbo.intuit.com/app/homepage?realmId={obj.realm_id}"
            return format_html(
                '<a href="{}" target="_blank">Open QuickBooks</a>',
                qbo_url
            )
        elif obj.provider == 'xero' and obj.xero_tenant_id:
            xero_url = f"https://go.xero.com/organisationlogin/default.aspx?shortcode={obj.xero_tenant_id}"
            return format_html(
                '<a href="{}" target="_blank">Open Xero</a>',
                xero_url
            )
        return '-'

    oauth_link.short_description = 'Accounting Software'


@admin.register(ChartOfAccounts)
class ChartOfAccountsAdmin(admin.ModelAdmin):
    list_display = [
        'account_number',
        'account_name',
        'account_type',
        'parent_account',
        'balance_display',
        'is_active',
    ]
    list_filter = ['account_type', 'is_active']
    search_fields = ['account_number', 'account_name', 'external_id']
    readonly_fields = ['created_at', 'updated_at', 'last_synced']

    fieldsets = (
        (
            'Account Details',
            {
                'fields': (
                    'account_number',
                    'account_name',
                    'account_type',
                    'parent_account',
                )
            },
        ),
        (
            'Balance',
            {
                'fields': (
                    'current_balance',
                    'currency',
                )
            },
        ),
        (
            'External Reference',
            {
                'fields': (
                    'external_id',
                    'last_synced',
                ),
                'classes': ('collapse',),
            },
        ),
        (
            'Status',
            {'fields': ('is_active',)},
        ),
        (
            'Description',
            {'fields': ('description',)},
        ),
        ('Metadata', {'fields': ('metadata',), 'classes': ('collapse',)}),
        (
            'Timestamps',
            {'fields': ('created_at', 'updated_at'), 'classes': ('collapse',)},
        ),
    )

    def balance_display(self, obj):
        if obj.current_balance >= 0:
            color = 'green'
            sign = '+'
        else:
            color = 'red'
            sign = ''

        return format_html(
            '<span style="color: {}; font-weight: bold;">{}{:,.2f} {}</span>',
            color,
            sign,
            obj.current_balance,
            obj.currency,
        )

    balance_display.short_description = 'Balance'


@admin.register(JournalEntry)
class JournalEntryAdmin(admin.ModelAdmin):
    list_display = [
        'entry_number',
        'entry_date',
        'status_display',
        'balance_status',
        'created_by',
        'created_at',
    ]
    list_filter = ['status', 'entry_date']
    search_fields = ['entry_number', 'description', 'reference']
    readonly_fields = [
        'entry_number',
        'created_at',
        'updated_at',
        'balance_check',
    ]
    date_hierarchy = 'entry_date'
    inlines = [JournalEntryLineInline]

    fieldsets = (
        (
            'Entry Details',
            {
                'fields': (
                    'entry_number',
                    'entry_date',
                    'status',
                )
            },
        ),
        (
            'Description',
            {
                'fields': (
                    'description',
                    'reference',
                )
            },
        ),
        (
            'Related Transaction',
            {
                'fields': (
                    'payment_transaction',
                ),
                'classes': ('collapse',),
            },
        ),
        (
            'Balance Check',
            {'fields': ('balance_check',)},
        ),
        ('Metadata', {'fields': ('metadata',), 'classes': ('collapse',)}),
        (
            'Timestamps',
            {
                'fields': ('created_by', 'created_at', 'updated_at', 'posted_at'),
                'classes': ('collapse',),
            },
        ),
    )

    def status_display(self, obj):
        colors = {
            'draft': 'gray',
            'posted': 'green',
            'voided': 'red',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = 'Status'

    def balance_status(self, obj):
        if obj.is_balanced:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ Balanced</span>'
            )
        return format_html(
            '<span style="color: red; font-weight: bold;">⚠️ Unbalanced</span>'
        )

    balance_status.short_description = 'Balance'

    def balance_check(self, obj):
        total_debits = sum(line.debit for line in obj.lines.all())
        total_credits = sum(line.credit for line in obj.lines.all())
        difference = total_debits - total_credits

        if difference == 0:
            return format_html(
                '<div style="padding: 10px; background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px;">'
                '<strong style="color: #155724;">✓ Entry is Balanced</strong><br>'
                'Debits: {:,.2f}<br>'
                'Credits: {:,.2f}<br>'
                'Difference: 0.00'
                '</div>',
                total_debits,
                total_credits,
            )
        else:
            return format_html(
                '<div style="padding: 10px; background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px;">'
                '<strong style="color: #721c24;">⚠️ Entry is Unbalanced</strong><br>'
                'Debits: {:,.2f}<br>'
                'Credits: {:,.2f}<br>'
                'Difference: {:,.2f}'
                '</div>',
                total_debits,
                total_credits,
                abs(difference),
            )

    balance_check.short_description = 'Balance Check'


@admin.register(AccountingSyncLog)
class AccountingSyncLogAdmin(admin.ModelAdmin):
    list_display = [
        'sync_id',
        'provider_display',
        'sync_type',
        'status_display',
        'records_synced',
        'started_at',
        'duration_display',
    ]
    list_filter = ['status', 'sync_type', 'started_at']
    search_fields = ['sync_id', 'error_message']
    readonly_fields = [
        'sync_id',
        'started_at',
        'completed_at',
    ]
    date_hierarchy = 'started_at'

    fieldsets = (
        (
            'Sync Details',
            {
                'fields': (
                    'sync_id',
                    'provider',
                    'sync_type',
                    'status',
                )
            },
        ),
        (
            'Statistics',
            {
                'fields': (
                    'records_synced',
                    'records_failed',
                )
            },
        ),
        (
            'Timing',
            {
                'fields': (
                    'started_at',
                    'completed_at',
                )
            },
        ),
        (
            'Error Details',
            {
                'fields': ('error_message',),
                'classes': ('collapse',),
            },
        ),
        (
            'Sync Data',
            {
                'fields': ('metadata',),
                'classes': ('collapse',),
            },
        ),
    )

    def has_add_permission(self, request):
        """Sync logs are created automatically"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Keep audit trail"""
        return False

    def provider_display(self, obj):
        if obj.accounting_provider:
            return obj.accounting_provider.get_provider_display()
        return '-'

    provider_display.short_description = 'Provider'

    def status_display(self, obj):
        colors = {
            'pending': 'orange',
            'in_progress': 'blue',
            'success': 'green',
            'partial': 'orange',
            'failed': 'red',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = 'Status'

    def duration_display(self, obj):
        if obj.duration:
            minutes = int(obj.duration.total_seconds() // 60)
            seconds = int(obj.duration.total_seconds() % 60)
            return f"{minutes}m {seconds}s"
        return '-'

    duration_display.short_description = 'Duration'


@admin.register(FinancialReport)
class FinancialReportAdmin(admin.ModelAdmin):
    list_display = [
        'report_number',
        'report_type',
        'period_display',
        'status_display',
        'generated_by',
        'generated_at',
    ]
    list_filter = ['report_type', 'generated_at']
    search_fields = ['report_number']
    readonly_fields = ['report_number', 'generated_at']
    date_hierarchy = 'period_end'

    fieldsets = (
        (
            'Report Details',
            {
                'fields': (
                    'report_number',
                    'report_type',
                    'status',
                )
            },
        ),
        (
            'Period',
            {
                'fields': (
                    'period_start',
                    'period_end',
                )
            },
        ),
        (
            'Report Data',
            {
                'fields': (
                    'report_data',
                    'totals',
                )
            },
        ),
        (
            'File',
            {'fields': ('pdf_file',)},
        ),
        (
            'Generation',
            {
                'fields': (
                    'generated_by',
                    'generated_at',
                )
            },
        ),
        (
            'Notes',
            {'fields': ('notes',)},
        ),
    )

    def status_display(self, obj):
        colors = {
            'draft': 'gray',
            'generated': 'blue',
            'finalized': 'green',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = 'Status'

    def period_display(self, obj):
        return f"{obj.period_start} → {obj.period_end}"

    period_display.short_description = 'Period'


@admin.register(ReconciliationRecord)
class ReconciliationRecordAdmin(admin.ModelAdmin):
    list_display = [
        'reconciliation_id',
        'account',
        'period_display',
        'balance_difference_display',
        'status_display',
        'reconciled_by',
        'reconciled_at',
    ]
    list_filter = ['status', 'reconciled_at']
    search_fields = [
        'reconciliation_id',
        'account__account_name',
        'account__account_number',
    ]
    readonly_fields = [
        'reconciliation_id',
        'created_at',
        'updated_at',
        'reconciled_at',
        'balance_summary',
    ]
    date_hierarchy = 'reconciled_at'

    fieldsets = (
        (
            'Reconciliation Details',
            {
                'fields': (
                    'reconciliation_id',
                    'account',
                    'status',
                )
            },
        ),
        (
            'Period',
            {
                'fields': (
                    'period_start',
                    'period_end',
                )
            },
        ),
        (
            'Balances',
            {
                'fields': (
                    'statement_balance',
                    'book_balance',
                    'balance_summary',
                )
            },
        ),
        (
            'Adjustments',
            {
                'fields': (
                    'uncleared_deposits',
                    'uncleared_withdrawals',
                    'adjustments',
                ),
                'classes': ('collapse',),
            },
        ),
        (
            'Notes',
            {'fields': ('notes',)},
        ),
        (
            'Timestamps',
            {
                'fields': (
                    'reconciled_by',
                    'reconciled_at',
                    'created_at',
                    'updated_at',
                ),
                'classes': ('collapse',),
            },
        ),
    )

    def status_display(self, obj):
        colors = {
            'draft': 'gray',
            'in_progress': 'blue',
            'reconciled': 'green',
            'discrepancy': 'red',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_display.short_description = 'Status'

    def period_display(self, obj):
        return f"{obj.period_start} → {obj.period_end}"

    period_display.short_description = 'Period'

    def balance_difference_display(self, obj):
        diff = obj.balance_difference
        if diff == 0:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ Balanced</span>'
            )
        else:
            color = 'red'
            return format_html(
                '<span style="color: {}; font-weight: bold;">⚠️ {:,.2f}</span>',
                color,
                abs(diff),
            )

    balance_difference_display.short_description = 'Difference'

    def balance_summary(self, obj):
        diff = obj.balance_difference

        if diff == 0:
            bg_color = '#d4edda'
            border_color = '#c3e6cb'
            text_color = '#155724'
            status = '✓ Reconciled'
        else:
            bg_color = '#f8d7da'
            border_color = '#f5c6cb'
            text_color = '#721c24'
            status = '⚠️ Discrepancy Found'

        return format_html(
            '<div style="padding: 10px; background-color: {}; border: 1px solid {}; border-radius: 4px;">'
            '<strong style="color: {};">{}</strong><br>'
            'Statement Balance: {:,.2f}<br>'
            'Book Balance: {:,.2f}<br>'
            'Difference: {:,.2f}'
            '</div>',
            bg_color,
            border_color,
            text_color,
            status,
            obj.statement_balance,
            obj.book_balance,
            diff,
        )

    balance_summary.short_description = 'Balance Summary'
