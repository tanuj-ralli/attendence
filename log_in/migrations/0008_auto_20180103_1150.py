# Generated by Django 2.0 on 2018-01-03 11:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('log_in', '0007_auto_20180103_1146'),
    ]

    operations = [
        migrations.RenameField(
            model_name='loginlogs',
            old_name='ip_addres',
            new_name='ip_address',
        ),
    ]
