# Generated by Django 5.0.4 on 2024-06-26 17:35

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0023_alter_mgrealm_email_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2024, 6, 26, 23, 5, 34, 238848)),
        ),
    ]