from django.db import models


class Alert(models.Model):
    """
    Alert model stores security alerts detected by Snort IDS.
    Each alert represents a potential security event with source/dest IPs, protocols, and threat level.
    """
    
    # Threat severity levels
    THREAT_SAFE = 'safe'
    THREAT_MEDIUM = 'medium'
    THREAT_HIGH = 'high'

    THREAT_LEVEL_CHOICES = [
        (THREAT_SAFE, 'Safe'),
        (THREAT_MEDIUM, 'Medium'),
        (THREAT_HIGH, 'High'),
    ]

    # Alert timestamp when event occurred
    timestamp = models.DateTimeField(db_index=True)
    
    # Source IP and port of attacker/sender
    src_ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=True)
    src_port = models.PositiveIntegerField(null=True, blank=True)
    
    # Destination IP and port of target
    dest_ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=True)
    dest_port = models.PositiveIntegerField(null=True, blank=True)
    
    # Network protocol (TCP, UDP, ICMP, etc.)
    protocol = models.CharField(max_length=20)
    
    # Snort Signature ID - identifies the rule that triggered
    sid = models.CharField(max_length=64, db_index=True)
    
    # Alert message/description
    message = models.CharField(max_length=512)
    
    # Snort classification category
    classification = models.CharField(max_length=255, blank=True, default='')
    
    # Snort priority level (1=high, 2=medium, 3=low)
    priority = models.PositiveIntegerField(null=True, blank=True)
    
    # Threat level computed from priority or ML model
    threat_level = models.CharField(max_length=16, choices=THREAT_LEVEL_CHOICES, db_index=True)
    
    # Raw Snort log line for reference
    raw_line = models.TextField()
    
    # Hash of alert for deduplication (prevents duplicate alerts in DB)
    event_hash = models.CharField(max_length=64, unique=True, db_index=True)
    
    # When this alert was stored in database
    ingested_at = models.DateTimeField(auto_now_add=True)

    # ML model fields - enrichment via threat_analyzer
    ml_processed = models.BooleanField(default=False, db_index=True)  # Flag: did ML run?
    ml_threat_score = models.FloatField(null=True, blank=True)  # ML confidence (0-1)
    ml_classification = models.CharField(max_length=20, blank=True, default='')  # "benign" or "attack"
    ml_features = models.JSONField(null=True, blank=True)  # 12 features extracted

    class Meta:
        ordering = ['-timestamp', '-id']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['threat_level', '-timestamp']),
            models.Index(fields=['ml_processed', '-timestamp']),
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
