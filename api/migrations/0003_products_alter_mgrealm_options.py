# Generated by Django 4.2.1 on 2024-04-06 16:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_alter_mgrealm_developer'),
    ]

    operations = [
        migrations.CreateModel(
            name='Products',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('productname', models.CharField(max_length=50)),
                ('description', models.TextField()),
                ('version', models.FloatField()),
            ],
            options={
                'verbose_name': 'MGRealm Product',
                'verbose_name_plural': 'MGRealm Products',
            },
        ),
        migrations.AlterModelOptions(
            name='mgrealm',
            options={'verbose_name': 'MGRealm Account', 'verbose_name_plural': 'MGRealm Accounts'},
        ),
    ]
