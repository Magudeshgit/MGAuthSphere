# Generated by Django 5.0.4 on 2025-05-07 13:46

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0039_alter_mgrealm_userid_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='mgrealm',
            name='is_oauth',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='mgrealm',
            name='oauth_credentials',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2025, 5, 7, 19, 16, 35, 353934)),
        ),
    ]
