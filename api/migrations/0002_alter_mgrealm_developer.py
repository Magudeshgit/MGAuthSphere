# Generated by Django 4.2.1 on 2024-04-06 16:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mgrealm',
            name='developer',
            field=models.BooleanField(null=True),
        ),
    ]