# Generated by Django 2.0 on 2019-04-16 12:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_in', '0020_auto_20190416_1103'),
    ]

    operations = [
        migrations.CreateModel(
            name='TeacherData',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tname', models.CharField(max_length=100, null=True)),
                ('tid', models.IntegerField(default=0)),
                ('tpassword', models.CharField(max_length=100, null=True)),
                ('temail', models.CharField(max_length=100, null=True)),
            ],
        ),
        migrations.AddField(
            model_name='userdata',
            name='email',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
