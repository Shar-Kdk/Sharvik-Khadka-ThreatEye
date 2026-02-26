"""
Create database indexes for performance optimization
Run: python manage.py migrate
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('alerts', '0004_rename_alerts_aler_timesta_12837f_idx_alerts_aler_timesta_0459bf_idx_and_more'),
    ]

    operations = [
        # Index for threat level queries (used in dashboards/analytics)
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['threat_level', '-timestamp'], name='threat_ts_idx'),
        ),
        # Index for timestamp filtering (used in all recent data queries)
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['-timestamp'], name='timestamp_idx'),
        ),
        # Index for src_ip filtering (attacker tracking)
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['src_ip', '-timestamp'], name='src_ip_ts_idx'),
        ),
        # Index for dest_ip filtering (target tracking)
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['dest_ip', '-timestamp'], name='dest_ip_ts_idx'),
        ),
        # Index for SID lookups (attack type distribution)
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['sid'], name='sid_idx'),
        ),
        # Index for protocol statistics
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['protocol'], name='protocol_idx'),
        ),
        # Index for classification queries
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['classification'], name='classification_idx'),
        ),
        # Index for ML processed status
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['ml_processed', '-timestamp'], name='ml_processed_idx'),
        ),
        # Composite index for the most complex dashboard query
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['timestamp', 'threat_level'], name='timestamp_threat_idx'),
        ),
    ]
