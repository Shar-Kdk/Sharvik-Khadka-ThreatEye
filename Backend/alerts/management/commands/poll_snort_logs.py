from django.conf import settings
from django.core.management.base import BaseCommand

from alerts.services import run_polling_loop


class Command(BaseCommand):
    help = 'Continuously polls Snort alert logs and ingests new alerts into the database.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=settings.SNORT_POLL_INTERVAL_SECONDS,
            help='Polling interval in seconds (default from settings)',
        )

    def handle(self, *args, **options):
        interval = max(1, options['interval'])
        self.stdout.write(
            self.style.SUCCESS(
                f'Starting Snort log polling from {settings.SNORT_LOG_DIR} every {interval}s'
            )
        )
        run_polling_loop(settings.SNORT_LOG_DIR, interval_seconds=interval)
