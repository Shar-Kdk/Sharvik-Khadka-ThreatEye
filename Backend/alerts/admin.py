from django.contrib import admin

from .models import Alert, LogIngestionState


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp',
        'src_ip',
        'src_port',
        'dest_ip',
        'dest_port',
        'protocol',
        'sid',
        'threat_level',
    ]
    list_filter = ['protocol', 'threat_level', 'sid']
    search_fields = ['src_ip', 'dest_ip', 'sid', 'message', 'classification']
    readonly_fields = ['ingested_at', 'event_hash']
    ordering = ['-timestamp']


@admin.register(LogIngestionState)
class LogIngestionStateAdmin(admin.ModelAdmin):
    list_display = ['file_path', 'inode', 'offset', 'updated_at']
    readonly_fields = ['updated_at']
