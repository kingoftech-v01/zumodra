# Migration to add escrow transaction FK to ServiceContract
# This is a separate migration as it depends on finance app

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0001_initial'),
        ('finance', '0001_initial'),  # Adjust based on actual finance migration
    ]

    operations = [
        migrations.AddField(
            model_name='servicecontract',
            name='escrow_transaction',
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='service_contract',
                to='finance.escrowtransaction',
            ),
        ),
    ]
