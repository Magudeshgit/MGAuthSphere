# Generated by Django 5.0.4 on 2024-06-27 07:39

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0025_alter_mgrealm_managers_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2024, 6, 27, 13, 9, 56, 566122)),
        ),
    ]