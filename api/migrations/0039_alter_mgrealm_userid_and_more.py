# Generated by Django 5.0.4 on 2025-01-04 16:08

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0038_mg_products_prvkey_mg_products_pubkey_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mgrealm',
            name='userid',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2025, 1, 4, 21, 38, 56, 711834)),
        ),
    ]
