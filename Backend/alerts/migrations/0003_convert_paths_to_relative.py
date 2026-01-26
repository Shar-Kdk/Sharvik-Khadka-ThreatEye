# Generated migration to convert absolute paths to relative in LogIngestionState

from django.db import migrations
from pathlib import Path
from django.conf import settings


def convert_to_relative(apps, schema_editor):
    """Convert absolute file paths to relative paths relative to SNORT_LOG_DIR"""
    LogIngestionState = apps.get_model('alerts', 'LogIngestionState')
    log_dir_path = Path(settings.SNORT_LOG_DIR)
    
    updated = 0
    for state in LogIngestionState.objects.all():
        original_path = state.file_path
        try:
            # Try to convert absolute path to relative
            file_path_obj = Path(original_path)
            if file_path_obj.is_absolute():
                # Path is absolute, convert to relative
                relative_path = str(file_path_obj.relative_to(log_dir_path))
                state.file_path = relative_path
                state.save(update_fields=['file_path'])
                updated += 1
        except (ValueError, OSError):
            # Path doesn't start with log_dir_path or other error, skip
            pass
    
    print(f'Converted {updated} LogIngestionState records to relative paths')


def convert_to_absolute(apps, schema_editor):
    """Reverse: convert relative paths back to absolute (for rollback)"""
    LogIngestionState = apps.get_model('alerts', 'LogIngestionState')
    log_dir_path = Path(settings.SNORT_LOG_DIR)
    
    updated = 0
    for state in LogIngestionState.objects.all():
        original_path = state.file_path
        try:
            file_path_obj = Path(original_path)
            if not file_path_obj.is_absolute():
                # Path is relative, convert to absolute
                absolute_path = str(log_dir_path / file_path_obj)
                state.file_path = absolute_path
                state.save(update_fields=['file_path'])
                updated += 1
        except (ValueError, OSError):
            pass
    
    print(f'Reverted {updated} LogIngestionState records to absolute paths')


class Migration(migrations.Migration):

    dependencies = [
        ('alerts', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(convert_to_relative, convert_to_absolute),
    ]
