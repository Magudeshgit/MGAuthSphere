# Generated by Django 4.2.1 on 2024-04-06 16:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_remove_mgrealm_groups_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mgrealm',
            name='developer',
            field=models.BooleanField(default=False),
        ),
    ]
