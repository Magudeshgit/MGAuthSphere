# Generated by Django 5.0.4 on 2024-09-04 17:03

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0036_mgrealm_mg_id_alter_mgrealm_sessions_created_on'),
    ]

    operations = [
        migrations.RenameField(
            model_name='mgrealm',
            old_name='mg_id',
            new_name='userid',
        ),
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2024, 9, 4, 22, 33, 34, 85930)),
        ),
    ]
