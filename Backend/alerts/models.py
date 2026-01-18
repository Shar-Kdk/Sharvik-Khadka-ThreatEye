from django.db import models


class Alert(models.Model):
    THREAT_SAFE = 'safe'
    THREAT_MEDIUM = 'medium'
    THREAT_HIGH = 'high'

    THREAT_LEVEL_CHOICES = [
        (THREAT_SAFE, 'Safe'),
        (THREAT_MEDIUM, 'Medium'),
        (THREAT_HIGH, 'High'),
    ]

    timestamp = models.DateTimeField(db_index=True)
    src_ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=True)
    src_port = models.PositiveIntegerField(null=True, blank=True)
    dest_ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=True)
    dest_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20)
    sid = models.CharField(max_length=64, db_index=True)
    message = models.CharField(max_length=512)
    classification = models.CharField(max_length=255, blank=True, default='')
    priority = models.PositiveIntegerField(null=True, blank=True)
    threat_level = models.CharField(max_length=16, choices=THREAT_LEVEL_CHOICES, db_index=True)
    raw_line = models.TextField()
    event_hash = models.CharField(max_length=64, unique=True, db_index=True)
    ingested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp', '-id']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['threat_level', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.timestamp.isoformat()} {self.src_ip}->{self.dest_ip} {self.message}"


class LogIngestionState(models.Model):
    file_path = models.CharField(max_length=512, unique=True)
    inode = models.CharField(max_length=128, blank=True, default='')
    offset = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Log ingestion state'
        verbose_name_plural = 'Log ingestion states'

    def __str__(self):
        return f"{self.file_path} @ {self.offset}"
