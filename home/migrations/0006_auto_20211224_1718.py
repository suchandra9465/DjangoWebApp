# Generated by Django 3.2.9 on 2021-12-24 11:48

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0005_statuslog_ip'),
    ]

    operations = [
        migrations.CreateModel(
            name='jobLogs',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.CharField(max_length=200)),
                ('log', models.TextField(null=True)),
                ('jobid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='home.large')),
            ],
        ),
        migrations.DeleteModel(
            name='StatusLog',
        ),
    ]
