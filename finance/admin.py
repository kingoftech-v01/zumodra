"""
Django Admin configuration for finance app.
Includes admin classes for Stripe Connect marketplace integration models.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone

from .models import (
    PaymentTransaction,
    SubscriptionPlan,
    UserSubscription,
    Invoice,
    RefundRequest,
    PaymentMethod,
    StripeWebhookEvent,
    EscrowTransaction,
    Dispute,
    EscrowPayout,
    EscrowAudit,
    # Stripe Connect models
    ConnectedAccount,
    PayoutSchedule,
    PlatformFee,
    StripeConnectOnboarding,
)


# =============================================================================
# Existing Finance Models Admin
# =============================================================================

@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'user', 'amount', 'currency', 'status_badge',
        'stripe_payment_intent_id', 'created_at'
    ]
    list_filter = ['succeeded', 'currency', 'created_at']
    search_fields = ['user__email', 'stripe_payment_intent_id', 'description']
    readonly_fields = ['id', 'created_at']
    raw_id_fields = ['user']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Transaction Info', {
            'fields': ('id', 'user', 'description')
        }),
        ('Payment Details', {
            'fields': ('amount', 'currency', 'stripe_payment_intent_id')
        }),
        ('Status', {
            'fields': ('succeeded', 'failure_code', 'failure_message')
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        if obj.succeeded:
            return format_html(
                '<span style="background-color: #10b981; color: white; padding: 3px 8px; '
                'border-radius: 3px;">Succeeded</span>'
            )
        return format_html(
            '<span style="background-color: #ef4444; color: white; padding: 3px 8px; '
            'border-radius: 3px;">Failed</span>'
        )
    status_badge.short_description = 'Status'


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ['name', 'price', 'currency', 'interval', 'stripe_product_id']
    list_filter = ['interval', 'currency']
    search_fields = ['name', 'stripe_product_id', 'stripe_price_id']


@admin.register(UserSubscription)
class UserSubscriptionAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'plan', 'status_badge', 'current_period_start', 'current_period_end'
    ]
    list_filter = ['status', 'plan']
    search_fields = ['user__email', 'stripe_subscription_id']
    raw_id_fields = ['user', 'plan']

    def status_badge(self, obj):
        colors = {
            'active': '#10b981',
            'past_due': '#f59e0b',
            'canceled': '#6b7280',
            'unpaid': '#ef4444',
            'trialing': '#3b82f6',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.status.upper()
        )
    status_badge.short_description = 'Status'


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = [
        'invoice_number', 'user', 'amount_due', 'amount_paid',
        'currency', 'paid_badge', 'due_date', 'created_at'
    ]
    list_filter = ['paid', 'currency', 'created_at']
    search_fields = ['invoice_number', 'user__email', 'stripe_invoice_id']
    readonly_fields = ['created_at', 'paid_at']
    raw_id_fields = ['user']
    date_hierarchy = 'created_at'

    def paid_badge(self, obj):
        if obj.paid:
            return format_html(
                '<span style="background-color: #10b981; color: white; padding: 3px 8px; '
                'border-radius: 3px;">Paid</span>'
            )
        return format_html(
            '<span style="background-color: #f59e0b; color: white; padding: 3px 8px; '
            'border-radius: 3px;">Unpaid</span>'
        )
    paid_badge.short_description = 'Paid'


@admin.register(RefundRequest)
class RefundRequestAdmin(admin.ModelAdmin):
    list_display = [
        'payment', 'approved_badge', 'requested_at', 'processed_at', 'processed_by'
    ]
    list_filter = ['approved', 'requested_at']
    search_fields = ['payment__user__email', 'reason']
    readonly_fields = ['requested_at', 'processed_at']
    raw_id_fields = ['payment', 'processed_by']

    def approved_badge(self, obj):
        if obj.approved:
            return format_html(
                '<span style="background-color: #10b981; color: white; padding: 3px 8px; '
                'border-radius: 3px;">Approved</span>'
            )
        return format_html(
            '<span style="background-color: #f59e0b; color: white; padding: 3px 8px; '
            'border-radius: 3px;">Pending</span>'
        )
    approved_badge.short_description = 'Status'


@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'card_display', 'is_default', 'added_at'
    ]
    list_filter = ['card_brand', 'is_default', 'added_at']
    search_fields = ['user__email', 'stripe_payment_method_id']
    readonly_fields = ['added_at']
    raw_id_fields = ['user']

    def card_display(self, obj):
        return f"{obj.card_brand} ****{obj.card_last4}"
    card_display.short_description = 'Card'


@admin.register(StripeWebhookEvent)
class StripeWebhookEventAdmin(admin.ModelAdmin):
    list_display = ['event_id', 'processed_badge', 'received_at', 'processed_at']
    list_filter = ['processed', 'received_at']
    search_fields = ['event_id']
    readonly_fields = ['event_id', 'json_payload', 'received_at', 'processed_at', 'error_message']
    date_hierarchy = 'received_at'

    def processed_badge(self, obj):
        if obj.processed:
            return format_html(
                '<span style="background-color: #10b981; color: white; padding: 3px 8px; '
                'border-radius: 3px;">Processed</span>'
            )
        return format_html(
            '<span style="background-color: #f59e0b; color: white; padding: 3px 8px; '
            'border-radius: 3px;">Pending</span>'
        )
    processed_badge.short_description = 'Status'

    def has_add_permission(self, request):
        return False


class EscrowAuditInline(admin.TabularInline):
    model = EscrowAudit
    extra = 0
    readonly_fields = ['user', 'action', 'timestamp', 'notes']
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


class DisputeInline(admin.TabularInline):
    model = Dispute
    extra = 0
    readonly_fields = ['raised_by', 'reason', 'created_at', 'resolved', 'resolved_at']
    can_delete = False


@admin.register(EscrowTransaction)
class EscrowTransactionAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'buyer', 'seller', 'amount', 'currency',
        'status_badge', 'created_at'
    ]
    list_filter = ['status', 'currency', 'created_at']
    search_fields = ['buyer__email', 'seller__email', 'payment_intent_id']
    readonly_fields = [
        'id', 'created_at', 'funded_at', 'service_delivered_at',
        'released_at', 'refunded_at', 'cancelled_at', 'dispute_raised_at'
    ]
    raw_id_fields = ['buyer', 'seller']
    date_hierarchy = 'created_at'
    inlines = [EscrowAuditInline, DisputeInline]

    fieldsets = (
        ('Transaction Info', {
            'fields': ('id', 'buyer', 'seller')
        }),
        ('Payment Details', {
            'fields': ('amount', 'currency', 'status')
        }),
        ('Stripe References', {
            'fields': ('payment_intent_id', 'payout_id'),
            'classes': ('collapse',)
        }),
        ('Agreement', {
            'fields': ('agreement_details',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': (
                'created_at', 'funded_at', 'service_delivered_at',
                'released_at', 'refunded_at', 'cancelled_at', 'dispute_raised_at'
            ),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'initialized': '#6b7280',
            'funded': '#3b82f6',
            'service_delivered': '#8b5cf6',
            'dispute': '#f59e0b',
            'released': '#10b981',
            'refunded': '#ef4444',
            'cancelled': '#374151',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(Dispute)
class DisputeAdmin(admin.ModelAdmin):
    list_display = [
        'escrow', 'raised_by', 'resolved_badge', 'created_at', 'resolved_at'
    ]
    list_filter = ['resolved', 'created_at']
    search_fields = ['escrow__buyer__email', 'escrow__seller__email', 'reason']
    readonly_fields = ['created_at', 'resolved_at']
    raw_id_fields = ['escrow', 'raised_by']
    date_hierarchy = 'created_at'

    def resolved_badge(self, obj):
        if obj.resolved:
            return format_html(
                '<span style="background-color: #10b981; color: white; padding: 3px 8px; '
                'border-radius: 3px;">Resolved</span>'
            )
        return format_html(
            '<span style="background-color: #ef4444; color: white; padding: 3px 8px; '
            'border-radius: 3px;">Open</span>'
        )
    resolved_badge.short_description = 'Status'


@admin.register(EscrowPayout)
class EscrowPayoutAdmin(admin.ModelAdmin):
    list_display = [
        'payout_id', 'escrow', 'amount', 'currency', 'status_badge', 'paid_at'
    ]
    list_filter = ['status', 'currency', 'paid_at']
    search_fields = ['payout_id', 'escrow__seller__email']
    readonly_fields = ['paid_at']
    raw_id_fields = ['escrow']

    def status_badge(self, obj):
        colors = {
            'pending': '#f59e0b',
            'completed': '#10b981',
            'failed': '#ef4444',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.status.capitalize()
        )
    status_badge.short_description = 'Status'


@admin.register(EscrowAudit)
class EscrowAuditAdmin(admin.ModelAdmin):
    list_display = ['escrow', 'user', 'action', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['escrow__buyer__email', 'escrow__seller__email', 'action', 'notes']
    readonly_fields = ['escrow', 'user', 'action', 'timestamp', 'notes']
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# =============================================================================
# Stripe Connect Marketplace Integration Admin
# =============================================================================

class PayoutScheduleInline(admin.StackedInline):
    """Inline for viewing/editing payout schedule on connected account."""
    model = PayoutSchedule
    extra = 0
    readonly_fields = ['created_at', 'updated_at']
    can_delete = False


class StripeConnectOnboardingInline(admin.StackedInline):
    """Inline for viewing onboarding status on connected account."""
    model = StripeConnectOnboarding
    extra = 0
    readonly_fields = [
        'status', 'onboarding_url', 'requirements_current',
        'requirements_past_due', 'requirements_eventually_due',
        'requirements_pending_verification', 'started_at',
        'completed_at', 'last_updated_at', 'link_expires_at',
        'error_message', 'created_at'
    ]
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


class PlatformFeeInline(admin.TabularInline):
    """Inline for viewing platform fees on connected account."""
    model = PlatformFee
    extra = 0
    readonly_fields = [
        'escrow', 'payment_transaction', 'fee_type',
        'transaction_amount', 'fee_amount', 'status', 'created_at'
    ]
    can_delete = False
    max_num = 10

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(ConnectedAccount)
class ConnectedAccountAdmin(admin.ModelAdmin):
    """Admin for ConnectedAccount model - Stripe Connect accounts for sellers/freelancers."""
    list_display = [
        'account_id_display', 'user', 'account_status_badge',
        'business_type', 'country', 'charges_enabled_badge',
        'payouts_enabled_badge', 'created_at'
    ]
    list_filter = [
        'account_status', 'business_type', 'country',
        'charges_enabled', 'payouts_enabled', 'details_submitted',
        'created_at'
    ]
    search_fields = [
        'user__email', 'user__username', 'account_id'
    ]
    readonly_fields = [
        'id', 'account_id', 'charges_enabled', 'payouts_enabled',
        'details_submitted', 'capabilities', 'stripe_metadata',
        'created_at', 'updated_at', 'activated_at'
    ]
    raw_id_fields = ['user']
    date_hierarchy = 'created_at'
    inlines = [PayoutScheduleInline, StripeConnectOnboardingInline, PlatformFeeInline]

    fieldsets = (
        ('Account Identification', {
            'fields': ('id', 'user', 'account_id', 'account_status')
        }),
        ('Business Information', {
            'fields': ('business_type', 'country', 'default_currency')
        }),
        ('Account Capabilities', {
            'fields': ('charges_enabled', 'payouts_enabled', 'details_submitted'),
            'description': 'These fields reflect the current status from Stripe.'
        }),
        ('Detailed Capabilities', {
            'fields': ('capabilities',),
            'classes': ('collapse',),
            'description': 'JSON representation of all Stripe capabilities.'
        }),
        ('Stripe Metadata', {
            'fields': ('stripe_metadata',),
            'classes': ('collapse',),
            'description': 'Full account data from Stripe API.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'activated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['refresh_account_status']

    def account_id_display(self, obj):
        if obj.account_id:
            return format_html(
                '<code style="background: #f3f4f6; padding: 2px 6px; '
                'border-radius: 3px;">{}</code>',
                obj.account_id
            )
        return format_html(
            '<span style="color: #9ca3af;">Not created</span>'
        )
    account_id_display.short_description = 'Account ID'

    def account_status_badge(self, obj):
        colors = {
            'pending': '#6b7280',
            'onboarding': '#3b82f6',
            'active': '#10b981',
            'restricted': '#f59e0b',
            'disabled': '#ef4444',
        }
        color = colors.get(obj.account_status, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_account_status_display()
        )
    account_status_badge.short_description = 'Status'

    def charges_enabled_badge(self, obj):
        if obj.charges_enabled:
            return format_html(
                '<span style="color: #10b981; font-weight: bold;">&#10003;</span>'
            )
        return format_html(
            '<span style="color: #ef4444; font-weight: bold;">&#10007;</span>'
        )
    charges_enabled_badge.short_description = 'Charges'

    def payouts_enabled_badge(self, obj):
        if obj.payouts_enabled:
            return format_html(
                '<span style="color: #10b981; font-weight: bold;">&#10003;</span>'
            )
        return format_html(
            '<span style="color: #ef4444; font-weight: bold;">&#10007;</span>'
        )
    payouts_enabled_badge.short_description = 'Payouts'

    @admin.action(description='Refresh account status from Stripe')
    def refresh_account_status(self, request, queryset):
        success_count = 0
        error_count = 0
        for account in queryset:
            try:
                account.refresh_account_status()
                success_count += 1
            except Exception as e:
                error_count += 1
                self.message_user(
                    request,
                    f'Error refreshing {account.account_id}: {str(e)}',
                    level='error'
                )
        if success_count:
            self.message_user(
                request,
                f'Successfully refreshed {success_count} account(s).'
            )


@admin.register(PayoutSchedule)
class PayoutScheduleAdmin(admin.ModelAdmin):
    """Admin for PayoutSchedule model - Configurable payout schedules for connected accounts."""
    list_display = [
        'connected_account', 'interval_badge', 'delay_days',
        'minimum_payout_amount', 'schedule_details', 'updated_at'
    ]
    list_filter = ['interval', 'delay_days', 'created_at']
    search_fields = [
        'connected_account__user__email',
        'connected_account__account_id'
    ]
    readonly_fields = ['id', 'created_at', 'updated_at']
    raw_id_fields = ['connected_account']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Connected Account', {
            'fields': ('id', 'connected_account')
        }),
        ('Schedule Configuration', {
            'fields': ('interval', 'delay_days'),
            'description': 'Configure how often payouts should occur.'
        }),
        ('Weekly Settings', {
            'fields': ('weekly_anchor',),
            'description': 'Only applies when interval is set to Weekly.',
            'classes': ('collapse',)
        }),
        ('Monthly Settings', {
            'fields': ('monthly_anchor',),
            'description': 'Only applies when interval is set to Monthly (1-31).',
            'classes': ('collapse',)
        }),
        ('Payout Threshold', {
            'fields': ('minimum_payout_amount',),
            'description': 'Minimum balance required to trigger a payout.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['apply_schedule_to_stripe']

    def interval_badge(self, obj):
        colors = {
            'manual': '#6b7280',
            'daily': '#10b981',
            'weekly': '#3b82f6',
            'monthly': '#8b5cf6',
        }
        color = colors.get(obj.interval, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_interval_display()
        )
    interval_badge.short_description = 'Interval'

    def schedule_details(self, obj):
        if obj.interval == 'weekly':
            return f"Every {obj.get_weekly_anchor_display()}"
        elif obj.interval == 'monthly':
            day = obj.monthly_anchor
            suffix = 'th'
            if day == 1 or day == 21 or day == 31:
                suffix = 'st'
            elif day == 2 or day == 22:
                suffix = 'nd'
            elif day == 3 or day == 23:
                suffix = 'rd'
            return f"On the {day}{suffix} of each month"
        elif obj.interval == 'daily':
            return f"Daily (+{obj.delay_days} day delay)"
        return "Manual payouts only"
    schedule_details.short_description = 'Schedule'

    @admin.action(description='Apply schedule to Stripe')
    def apply_schedule_to_stripe(self, request, queryset):
        success_count = 0
        error_count = 0
        for schedule in queryset:
            try:
                schedule.apply_to_stripe()
                success_count += 1
            except Exception as e:
                error_count += 1
                self.message_user(
                    request,
                    f'Error applying schedule for {schedule.connected_account}: {str(e)}',
                    level='error'
                )
        if success_count:
            self.message_user(
                request,
                f'Successfully applied {success_count} schedule(s) to Stripe.'
            )


@admin.register(PlatformFee)
class PlatformFeeAdmin(admin.ModelAdmin):
    """Admin for PlatformFee model - Platform commission tracking for marketplace transactions."""
    list_display = [
        'id_display', 'connected_account', 'transaction_amount',
        'fee_amount', 'fee_type_badge', 'status_badge',
        'currency', 'created_at'
    ]
    list_filter = [
        'status', 'fee_type', 'currency', 'created_at'
    ]
    search_fields = [
        'connected_account__user__email',
        'connected_account__account_id',
        'stripe_application_fee_id',
        'stripe_transfer_id'
    ]
    readonly_fields = [
        'id', 'stripe_application_fee_id', 'stripe_transfer_id',
        'collected_at', 'refunded_at', 'created_at', 'updated_at'
    ]
    raw_id_fields = ['escrow', 'payment_transaction', 'connected_account']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Identification', {
            'fields': ('id', 'connected_account')
        }),
        ('Related Transactions', {
            'fields': ('escrow', 'payment_transaction'),
            'description': 'The original transaction this fee is associated with.'
        }),
        ('Fee Configuration', {
            'fields': ('fee_type', 'percentage_rate', 'fixed_amount'),
            'description': 'How the fee amount is calculated.'
        }),
        ('Amounts', {
            'fields': ('transaction_amount', 'fee_amount', 'currency'),
        }),
        ('Stripe References', {
            'fields': ('stripe_application_fee_id', 'stripe_transfer_id'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('status', 'collected_at', 'refunded_at', 'refunded_amount'),
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['recalculate_fees', 'mark_as_collected']

    def id_display(self, obj):
        return format_html(
            '<code style="background: #f3f4f6; padding: 2px 6px; '
            'border-radius: 3px; font-size: 10px;">{}</code>',
            str(obj.id)[:8]
        )
    id_display.short_description = 'ID'

    def fee_type_badge(self, obj):
        colors = {
            'percentage': '#3b82f6',
            'fixed': '#8b5cf6',
            'combined': '#10b981',
        }
        color = colors.get(obj.fee_type, '#6b7280')
        label = obj.get_fee_type_display()
        if obj.fee_type == 'percentage':
            label = f"{obj.percentage_rate}%"
        elif obj.fee_type == 'fixed':
            label = f"${obj.fixed_amount}"
        elif obj.fee_type == 'combined':
            label = f"{obj.percentage_rate}% + ${obj.fixed_amount}"
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            color, label
        )
    fee_type_badge.short_description = 'Fee Type'

    def status_badge(self, obj):
        colors = {
            'pending': '#f59e0b',
            'collected': '#10b981',
            'refunded': '#ef4444',
            'partially_refunded': '#8b5cf6',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    @admin.action(description='Recalculate fee amounts')
    def recalculate_fees(self, request, queryset):
        count = 0
        for fee in queryset.filter(status='pending'):
            fee.calculate_fee()
            count += 1
        self.message_user(request, f'Recalculated {count} fee(s).')

    @admin.action(description='Mark as collected')
    def mark_as_collected(self, request, queryset):
        count = queryset.filter(status='pending').update(
            status='collected',
            collected_at=timezone.now()
        )
        self.message_user(request, f'Marked {count} fee(s) as collected.')


@admin.register(StripeConnectOnboarding)
class StripeConnectOnboardingAdmin(admin.ModelAdmin):
    """Admin for StripeConnectOnboarding model - Onboarding status tracking for Stripe Connect accounts."""
    list_display = [
        'connected_account', 'status_badge', 'requirements_summary',
        'link_status', 'started_at', 'completed_at'
    ]
    list_filter = ['status', 'started_at', 'completed_at', 'created_at']
    search_fields = [
        'connected_account__user__email',
        'connected_account__account_id'
    ]
    readonly_fields = [
        'id', 'onboarding_url', 'requirements_current',
        'requirements_past_due', 'requirements_eventually_due',
        'requirements_pending_verification', 'started_at',
        'completed_at', 'last_updated_at', 'link_expires_at',
        'error_message', 'created_at'
    ]
    raw_id_fields = ['connected_account']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Connected Account', {
            'fields': ('id', 'connected_account', 'status')
        }),
        ('Onboarding URLs', {
            'fields': ('onboarding_url', 'return_url', 'refresh_url'),
            'description': 'URLs used for the Stripe Connect onboarding flow.'
        }),
        ('Current Requirements', {
            'fields': ('requirements_current',),
            'description': 'Requirements that must be completed now.'
        }),
        ('Past Due Requirements', {
            'fields': ('requirements_past_due',),
            'description': 'Requirements that are overdue.',
            'classes': ('collapse',)
        }),
        ('Eventually Due Requirements', {
            'fields': ('requirements_eventually_due',),
            'description': 'Requirements that will be due in the future.',
            'classes': ('collapse',)
        }),
        ('Pending Verification', {
            'fields': ('requirements_pending_verification',),
            'description': 'Requirements currently being verified by Stripe.',
            'classes': ('collapse',)
        }),
        ('Error Information', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('started_at', 'completed_at', 'last_updated_at', 'link_expires_at', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['refresh_onboarding_link', 'generate_new_onboarding_link']

    def status_badge(self, obj):
        colors = {
            'not_started': '#6b7280',
            'in_progress': '#3b82f6',
            'pending_verification': '#f59e0b',
            'completed': '#10b981',
            'failed': '#ef4444',
            'expired': '#374151',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def requirements_summary(self, obj):
        current = len(obj.requirements_current) if obj.requirements_current else 0
        past_due = len(obj.requirements_past_due) if obj.requirements_past_due else 0
        pending = len(obj.requirements_pending_verification) if obj.requirements_pending_verification else 0

        if past_due > 0:
            return format_html(
                '<span style="color: #ef4444; font-weight: bold;">'
                '{} past due</span>, {} current, {} pending',
                past_due, current, pending
            )
        elif current > 0:
            return format_html(
                '<span style="color: #f59e0b;">{} current</span>, {} pending',
                current, pending
            )
        elif pending > 0:
            return format_html(
                '<span style="color: #3b82f6;">{} pending verification</span>',
                pending
            )
        return format_html(
            '<span style="color: #10b981;">All complete</span>'
        )
    requirements_summary.short_description = 'Requirements'

    def link_status(self, obj):
        if not obj.onboarding_url:
            return format_html(
                '<span style="color: #6b7280;">No link</span>'
            )
        if obj.is_link_expired():
            return format_html(
                '<span style="color: #ef4444;">Expired</span>'
            )
        return format_html(
            '<span style="color: #10b981;">Active</span>'
        )
    link_status.short_description = 'Link'

    @admin.action(description='Refresh onboarding link')
    def refresh_onboarding_link(self, request, queryset):
        success_count = 0
        error_count = 0
        for onboarding in queryset:
            if onboarding.return_url and onboarding.refresh_url:
                try:
                    onboarding.refresh_onboarding_link()
                    success_count += 1
                except Exception as e:
                    error_count += 1
                    self.message_user(
                        request,
                        f'Error refreshing link for {onboarding.connected_account}: {str(e)}',
                        level='error'
                    )
            else:
                error_count += 1
                self.message_user(
                    request,
                    f'Cannot refresh link for {onboarding.connected_account}: URLs not configured',
                    level='warning'
                )
        if success_count:
            self.message_user(
                request,
                f'Successfully refreshed {success_count} onboarding link(s).'
            )

    @admin.action(description='Generate new onboarding link')
    def generate_new_onboarding_link(self, request, queryset):
        self.message_user(
            request,
            'Use the connected account view to generate new links with proper URLs.',
            level='warning'
        )
