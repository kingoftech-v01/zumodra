# Generated manually - Add company fields to Tenant model
from decimal import Decimal
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenant',
            name='rating',
            field=models.DecimalField(
                blank=True,
                decimal_places=2,
                help_text='Company rating (1.00-5.00)',
                max_digits=3,
                null=True,
                validators=[
                    MinValueValidator(Decimal('0.00')),
                    MaxValueValidator(Decimal('5.00'))
                ],
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='established_date',
            field=models.DateField(
                blank=True,
                help_text='Date company was established/founded',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='linkedin_url',
            field=models.URLField(
                blank=True,
                help_text='LinkedIn company page URL',
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='twitter_url',
            field=models.URLField(
                blank=True,
                help_text='Twitter/X company profile URL',
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='facebook_url',
            field=models.URLField(
                blank=True,
                help_text='Facebook company page URL',
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='instagram_url',
            field=models.URLField(
                blank=True,
                help_text='Instagram company profile URL',
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='pinterest_url',
            field=models.URLField(
                blank=True,
                help_text='Pinterest company profile URL',
            ),
        ),
    ]
