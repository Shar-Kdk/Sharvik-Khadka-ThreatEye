from django.core.management.base import BaseCommand
from django.db import connection
from alerts.models import Alert, LogIngestionState


class Command(BaseCommand):
    help = 'Clear all alerts and log ingestion state (for testing/reset)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm deletion (prevents accidental data loss)',
        )

    def handle(self, *args, **options):
        if not options['confirm']:
            self.stdout.write(
                self.style.WARNING(
                    'WARNING: This will delete ALL alerts and ingestion state.\n'
                    'Run with --confirm to proceed'
                )
            )
            return

        alert_count = Alert.objects.count()
        state_count = LogIngestionState.objects.count()

        with connection.cursor() as cursor:
            cursor.execute('TRUNCATE TABLE alerts_alert')
            cursor.execute('TRUNCATE TABLE alerts_logingestionstate')

        # Tell the frontend to clear its memory too
        from alerts.services import broadcast_clear_signal
        broadcast_clear_signal()

        self.stdout.write(
            self.style.SUCCESS(
                f'[OK] Deleted {alert_count} alerts and {state_count} ingestion states'
            )
        )
