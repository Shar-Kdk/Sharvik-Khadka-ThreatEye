from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(db_index=True)),
                ('src_ip', models.GenericIPAddressField(protocol='both', unpack_ipv4=True)),
                ('src_port', models.PositiveIntegerField(blank=True, null=True)),
                ('dest_ip', models.GenericIPAddressField(protocol='both', unpack_ipv4=True)),
                ('dest_port', models.PositiveIntegerField(blank=True, null=True)),
                ('protocol', models.CharField(max_length=20)),
                ('sid', models.CharField(db_index=True, max_length=64)),
                ('message', models.CharField(max_length=512)),
                ('classification', models.CharField(blank=True, default='', max_length=255)),
                ('priority', models.PositiveIntegerField(blank=True, null=True)),
                ('threat_level', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], db_index=True, max_length=16)),
                ('raw_line', models.TextField()),
                ('event_hash', models.CharField(db_index=True, max_length=64, unique=True)),
                ('ingested_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-timestamp', '-id'],
            },
        ),
        migrations.CreateModel(
            name='LogIngestionState',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_path', models.CharField(max_length=512, unique=True)),
                ('inode', models.CharField(blank=True, default='', max_length=128)),
                ('offset', models.BigIntegerField(default=0)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Log ingestion state',
                'verbose_name_plural': 'Log ingestion states',
            },
        ),
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['-timestamp'], name='alerts_aler_timesta_12837f_idx'),
        ),
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['threat_level', '-timestamp'], name='alerts_aler_threat__097f80_idx'),
        ),
    ]
