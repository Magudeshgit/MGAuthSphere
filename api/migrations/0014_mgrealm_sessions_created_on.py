# Generated by Django 4.2.1 on 2024-04-08 17:56

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_rename_expire_date_mgrealm_sessions_expire_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2024, 4, 8, 23, 26, 37, 984641)),
        ),
    ]
