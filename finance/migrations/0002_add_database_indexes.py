# Generated migration for adding database indexes to Finance models
# Improves query performance for frequently accessed fields and financial reporting

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('finance', '0001_initial'),
        ('tenants', '__latest__'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Payment indexes
        migrations.AlterField(
            model_name='payment',
            name='amount',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Payment amount'
            ),
        ),
        migrations.AlterField(
            model_name='payment',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When payment was created'
            ),
        ),
        migrations.AlterField(
            model_name='payment',
            name='succeeded',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether payment succeeded'
            ),
        ),

        # Subscription indexes
        migrations.AlterField(
            model_name='subscription',
            name='plan',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name='subscriptions',
                to='finance.subscriptionplan',
                db_index=True,
                help_text='Subscription plan'
            ),
        ),
        migrations.AlterField(
            model_name='subscription',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('active', 'Active'),
                    ('past_due', 'Past Due'),
                    ('canceled', 'Canceled'),
                    ('expired', 'Expired'),
                ],
                db_index=True,
                help_text='Subscription status'
            ),
        ),
        migrations.AlterField(
            model_name='subscription',
            name='amount_due',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Amount due for subscription'
            ),
        ),
        migrations.AlterField(
            model_name='subscription',
            name='amount_paid',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                default=0,
                db_index=True,
                help_text='Amount paid so far'
            ),
        ),

        # Invoice indexes
        migrations.AlterField(
            model_name='invoice',
            name='paid',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether invoice is paid'
            ),
        ),
        migrations.AlterField(
            model_name='invoice',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When invoice was created'
            ),
        ),
        migrations.AlterField(
            model_name='invoice',
            name='paid_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When invoice was paid'
            ),
        ),

        # RefundRequest indexes
        migrations.AlterField(
            model_name='refundrequest',
            name='requested_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When refund was requested'
            ),
        ),
        migrations.AlterField(
            model_name='refundrequest',
            name='approved',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether refund was approved'
            ),
        ),
        migrations.AlterField(
            model_name='refundrequest',
            name='processed_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When refund was processed'
            ),
        ),

        # PaymentMethod indexes
        migrations.AlterField(
            model_name='paymentmethod',
            name='is_default',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether this is the default payment method'
            ),
        ),
        migrations.AlterField(
            model_name='paymentmethod',
            name='added_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When payment method was added'
            ),
        ),

        # WebhookEvent indexes
        migrations.AlterField(
            model_name='webhookenvent',
            name='received_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When webhook was received'
            ),
        ),
        migrations.AlterField(
            model_name='webhookenvent',
            name='processed',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether webhook was processed'
            ),
        ),
        migrations.AlterField(
            model_name='webhookenvent',
            name='processed_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When webhook was processed'
            ),
        ),

        # EscrowTransaction indexes
        migrations.AlterField(
            model_name='escrowtransaction',
            name='amount',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Escrow amount'
            ),
        ),
        migrations.AlterField(
            model_name='escrowtransaction',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('initialized', 'Initialized'),
                    ('held', 'Held'),
                    ('released', 'Released'),
                    ('returned', 'Returned'),
                    ('disputed', 'Disputed'),
                ],
                default='initialized',
                db_index=True,
                help_text='Escrow status'
            ),
        ),
        migrations.AlterField(
            model_name='escrowtransaction',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When escrow was created'
            ),
        ),

        # DisputeResolution indexes
        migrations.AlterField(
            model_name='disputeresolution',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When dispute was created'
            ),
        ),
        migrations.AlterField(
            model_name='disputeresolution',
            name='resolved',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether dispute is resolved'
            ),
        ),
        migrations.AlterField(
            model_name='disputeresolution',
            name='resolved_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When dispute was resolved'
            ),
        ),

        # Payout indexes
        migrations.AlterField(
            model_name='payout',
            name='amount',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Payout amount'
            ),
        ),
        migrations.AlterField(
            model_name='payout',
            name='paid_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When payout was made'
            ),
        ),
        migrations.AlterField(
            model_name='payout',
            name='status',
            field=models.CharField(
                max_length=50,
                default='completed',
                db_index=True,
                help_text='Payout status'
            ),
        ),

        # AuditLog indexes
        migrations.AlterField(
            model_name='auditlog',
            name='timestamp',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When audit event occurred'
            ),
        ),

        # FinanceAccount indexes
        migrations.AlterField(
            model_name='financeaccount',
            name='account_status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('pending', 'Pending'),
                    ('active', 'Active'),
                    ('suspended', 'Suspended'),
                    ('closed', 'Closed'),
                ],
                default='pending',
                db_index=True,
                help_text='Account status'
            ),
        ),
        migrations.AlterField(
            model_name='financeaccount',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When account was created'
            ),
        ),
        migrations.AlterField(
            model_name='financeaccount',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When account was last updated'
            ),
        ),
        migrations.AlterField(
            model_name='financeaccount',
            name='activated_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When account was activated'
            ),
        ),

        # PayoutSchedule indexes
        migrations.AlterField(
            model_name='payoutschedule',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When schedule was created'
            ),
        ),
        migrations.AlterField(
            model_name='payoutschedule',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When schedule was last updated'
            ),
        ),

        # PlatformFee indexes
        migrations.AlterField(
            model_name='platformfee',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('pending', 'Pending'),
                    ('collected', 'Collected'),
                    ('refunded', 'Refunded'),
                ],
                default='pending',
                db_index=True,
                help_text='Fee status'
            ),
        ),
        migrations.AlterField(
            model_name='platformfee',
            name='collected_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When fee was collected'
            ),
        ),
        migrations.AlterField(
            model_name='platformfee',
            name='refunded_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When fee was refunded'
            ),
        ),
        migrations.AlterField(
            model_name='platformfee',
            name='refunded_amount',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                default=0,
                db_index=True,
                help_text='Amount refunded'
            ),
        ),
        migrations.AlterField(
            model_name='platformfee',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When fee was created'
            ),
        ),
        migrations.AlterField(
            model_name='platformfee',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When fee was last updated'
            ),
        ),
    ]
