# Generated by Django 5.0.4 on 2024-09-04 16:56

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0035_alter_mgrealm_sessions_created_on'),
    ]

    operations = [
        migrations.AddField(
            model_name='mgrealm',
            name='mg_id',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2024, 9, 4, 22, 26, 13, 726718)),
        ),
    ]