# Generated by Django 4.2.1 on 2024-04-09 16:47

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_alter_mgrealm_sessions_created_on'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Products',
            new_name='MG_Products',
        ),
        migrations.RemoveField(
            model_name='mgrealm',
            name='signed_services',
        ),
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='created_on',
            field=models.DateTimeField(default=datetime.datetime(2024, 4, 9, 22, 17, 20, 805118)),
        ),
    ]
