# Generated by Django 4.2.1 on 2024-04-08 17:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_alter_mgrealm_sessions_expire_date'),
    ]

    operations = [
        migrations.RenameField(
            model_name='mgrealm_sessions',
            old_name='expire_Date',
            new_name='expire_date',
        ),
    ]
