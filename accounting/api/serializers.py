"""
Accounting API Serializers
"""

from rest_framework import serializers
from django.utils import timezone
from ..models import (
    AccountingProvider,
    ChartOfAccounts,
    JournalEntry,
    JournalEntryLine,
    AccountingSyncLog,
    FinancialReport,
    ReconciliationRecord,
)


# ============= AccountingProvider Serializers =============

class AccountingProviderListSerializer(serializers.ModelSerializer):
    """Lightweight accounting provider list"""
    provider_display = serializers.CharField(source='get_provider_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    days_since_last_sync = serializers.SerializerMethodField()

    class Meta:
        model = AccountingProvider
        fields = [
            'id', 'provider', 'provider_display', 'status', 'status_display',
            'last_sync', 'days_since_last_sync', 'created_at',
        ]
        read_only_fields = fields

    def get_days_since_last_sync(self, obj):
        if not obj.last_sync:
            return None
        delta = timezone.now() - obj.last_sync
        return delta.days


class AccountingProviderDetailSerializer(serializers.ModelSerializer):
    """Full accounting provider details"""
    provider_display = serializers.CharField(source='get_provider_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    sync_logs_count = serializers.IntegerField(source='sync_logs.count', read_only=True)

    class Meta:
        model = AccountingProvider
        fields = [
            'id', 'provider', 'provider_display', 'company_name', 'base_currency',
            'status', 'status_display', 'last_sync', 'sync_logs_count',
            'metadata', 'auto_sync', 'sync_frequency', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class AccountingProviderCreateSerializer(serializers.ModelSerializer):
    """Create/update accounting provider"""
    class Meta:
        model = AccountingProvider
        fields = [
            'provider', 'company_name', 'base_currency', 'status',
            'auto_sync', 'sync_frequency', 'metadata',
        ]


# ============= ChartOfAccounts Serializers =============

class ChartOfAccountsListSerializer(serializers.ModelSerializer):
    """Lightweight chart of accounts list"""
    provider_name = serializers.CharField(source='provider.get_provider_display', read_only=True)
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)

    class Meta:
        model = ChartOfAccounts
        fields = [
            'id', 'provider_name', 'account_number', 'account_name',
            'account_type', 'account_type_display', 'is_active', 'created_at',
        ]
        read_only_fields = fields


class ChartOfAccountsDetailSerializer(serializers.ModelSerializer):
    """Full chart of accounts details"""
    provider = AccountingProviderListSerializer(read_only=True)
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)

    class Meta:
        model = ChartOfAccounts
        fields = [
            'id', 'provider', 'account_number', 'account_name',
            'account_type', 'account_type_display', 'description',
            'parent_account', 'is_active',
            'provider_account_id', 'current_balance', 'last_synced',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'current_balance', 'last_synced', 'created_at', 'updated_at']


# ============= JournalEntry Serializers =============

class JournalEntryLineSerializer(serializers.ModelSerializer):
    """Journal entry line serializer"""
    account_number = serializers.CharField(source='account.account_number', read_only=True)
    account_name = serializers.CharField(source='account.account_name', read_only=True)

    class Meta:
        model = JournalEntryLine
        fields = [
            'id', 'account', 'account_number', 'account_name', 'debit', 'credit', 'description',
        ]


class JournalEntryListSerializer(serializers.ModelSerializer):
    """Lightweight journal entry list"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    line_count = serializers.IntegerField(source='lines.count', read_only=True)
    is_balanced = serializers.BooleanField(read_only=True)

    class Meta:
        model = JournalEntry
        fields = [
            'id', 'entry_number', 'entry_date', 'description', 'status',
            'status_display', 'line_count', 'is_balanced', 'created_at',
        ]
        read_only_fields = fields


class JournalEntryDetailSerializer(serializers.ModelSerializer):
    """Full journal entry details with lines"""
    lines = JournalEntryLineSerializer(many=True, read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_balanced = serializers.BooleanField(read_only=True)
    total_debits = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)
    total_credits = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)

    class Meta:
        model = JournalEntry
        fields = [
            'id', 'entry_number', 'entry_date', 'description', 'reference',
            'status', 'status_display', 'lines', 'is_balanced',
            'total_debits', 'total_credits', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class JournalEntryCreateSerializer(serializers.ModelSerializer):
    """Create journal entry with lines"""
    lines = JournalEntryLineSerializer(many=True)

    class Meta:
        model = JournalEntry
        fields = [
            'entry_number', 'entry_date', 'description', 'reference', 'lines',
        ]

    def validate_lines(self, value):
        """Validate that debits equal credits"""
        if not value:
            raise serializers.ValidationError("At least one line is required")

        total_debits = sum(line.get('debit', 0) for line in value)
        total_credits = sum(line.get('credit', 0) for line in value)

        if abs(total_debits - total_credits) > 0.01:
            raise serializers.ValidationError(
                f"Debits ({total_debits}) must equal credits ({total_credits})"
            )

        return value

    def create(self, validated_data):
        lines_data = validated_data.pop('lines')
        entry = JournalEntry.objects.create(**validated_data)

        for line_data in lines_data:
            JournalEntryLine.objects.create(entry=entry, **line_data)

        return entry


# ============= AccountingSyncLog Serializers =============

class AccountingSyncLogListSerializer(serializers.ModelSerializer):
    """Lightweight sync log list"""
    provider_name = serializers.CharField(source='provider.get_provider_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    sync_type_display = serializers.CharField(source='get_sync_type_display', read_only=True)
    duration = serializers.SerializerMethodField()

    class Meta:
        model = AccountingSyncLog
        fields = [
            'id', 'provider_name', 'sync_type', 'sync_type_display',
            'status', 'status_display', 'records_synced', 'duration',
            'sync_started_at',
        ]
        read_only_fields = fields

    def get_duration(self, obj):
        """Calculate sync duration in seconds"""
        if obj.sync_completed_at and obj.sync_started_at:
            delta = obj.sync_completed_at - obj.sync_started_at
            return delta.total_seconds()
        return None


class AccountingSyncLogDetailSerializer(serializers.ModelSerializer):
    """Full sync log details"""
    provider = AccountingProviderListSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    sync_type_display = serializers.CharField(source='get_sync_type_display', read_only=True)
    duration = serializers.SerializerMethodField()

    class Meta:
        model = AccountingSyncLog
        fields = [
            'id', 'provider', 'sync_type', 'sync_type_display',
            'status', 'status_display', 'sync_started_at', 'sync_completed_at',
            'duration', 'records_synced', 'error_message', 'sync_details',
            'created_at',
        ]
        read_only_fields = fields

    def get_duration(self, obj):
        if obj.sync_completed_at and obj.sync_started_at:
            delta = obj.sync_completed_at - obj.sync_started_at
            return delta.total_seconds()
        return None


# ============= FinancialReport Serializers =============

class FinancialReportListSerializer(serializers.ModelSerializer):
    """Lightweight financial report list"""
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    generated_by_name = serializers.SerializerMethodField()

    class Meta:
        model = FinancialReport
        fields = [
            'id', 'report_type', 'report_type_display', 'period_start',
            'period_end', 'status', 'status_display', 'generated_by_name',
            'generated_at',
        ]
        read_only_fields = fields

    def get_generated_by_name(self, obj):
        if obj.generated_by:
            return obj.generated_by.get_full_name()
        return None


class FinancialReportDetailSerializer(serializers.ModelSerializer):
    """Full financial report details"""
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    generated_by_email = serializers.EmailField(source='generated_by.email', read_only=True)

    class Meta:
        model = FinancialReport
        fields = [
            'id', 'report_type', 'report_type_display', 'period_start', 'period_end',
            'status', 'status_display', 'report_data', 'file_path',
            'generated_by_email', 'generated_at', 'error_message',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'file_path', 'generated_at', 'created_at', 'updated_at']


class FinancialReportCreateSerializer(serializers.ModelSerializer):
    """Create financial report"""
    class Meta:
        model = FinancialReport
        fields = [
            'report_type', 'period_start', 'period_end',
        ]

    def validate(self, data):
        """Validate period dates"""
        if data['period_end'] < data['period_start']:
            raise serializers.ValidationError({
                'period_end': 'End date must be after start date'
            })
        return data


# ============= ReconciliationRecord Serializers =============

class ReconciliationRecordListSerializer(serializers.ModelSerializer):
    """Lightweight reconciliation record list"""
    account_name = serializers.CharField(source='account.account_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    difference = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)

    class Meta:
        model = ReconciliationRecord
        fields = [
            'id', 'account_name', 'reconciliation_date', 'status',
            'status_display', 'book_balance', 'bank_balance', 'difference',
            'created_at',
        ]
        read_only_fields = fields


class ReconciliationRecordDetailSerializer(serializers.ModelSerializer):
    """Full reconciliation record details"""
    account = ChartOfAccountsListSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    reconciled_by_name = serializers.SerializerMethodField()
    difference = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)

    class Meta:
        model = ReconciliationRecord
        fields = [
            'id', 'account', 'reconciliation_date', 'book_balance', 'bank_balance',
            'difference', 'status', 'status_display', 'adjustments',
            'reconciled_by_name', 'reconciled_at', 'notes',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'reconciled_at', 'created_at', 'updated_at']

    def get_reconciled_by_name(self, obj):
        if obj.reconciled_by:
            return obj.reconciled_by.get_full_name()
        return None


class ReconciliationRecordCreateSerializer(serializers.ModelSerializer):
    """Create reconciliation record"""
    class Meta:
        model = ReconciliationRecord
        fields = [
            'account', 'reconciliation_date', 'book_balance', 'bank_balance',
            'adjustments', 'notes',
        ]

    def validate(self, data):
        """Validate balances are reasonable"""
        book_balance = data.get('book_balance', 0)
        bank_balance = data.get('bank_balance', 0)

        # Check for unreasonably large differences
        difference = abs(book_balance - bank_balance)
        if difference > 100000:  # $100,000 threshold
            raise serializers.ValidationError({
                'bank_balance': f'Large difference detected: ${difference}. Please verify balances.'
            })

        return data
