# Generated by Django 4.2.1 on 2024-04-07 19:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_remove_mgrealm_sessions_session_data_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='mgrealm_sessions',
            options={'verbose_name': 'MGRealm_Session', 'verbose_name_plural': 'MGRealm_Sessions'},
        ),
        migrations.RemoveField(
            model_name='mgrealm_sessions',
            name='expire_date',
        ),
        migrations.AlterField(
            model_name='mgrealm_sessions',
            name='session_key',
            field=models.CharField(max_length=40, primary_key=True, serialize=False),
        ),
        migrations.AddField(
            model_name='mgrealm_sessions',
            name='expire_Date',
            field=models.DateTimeField(db_index=True, default='2024-04-07T18:42:23.275734+00:00'),
            preserve_default=False,
        ),
    ]
