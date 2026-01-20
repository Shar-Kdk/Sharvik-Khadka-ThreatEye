from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from alerts.services import ingest_snort_logs, ingest_snort_packet_logs


class Command(BaseCommand):
    help = 'Continuously polls Snort logs and ingests new alerts/packets into the database.'

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

        while True:
            try:
                text_result = ingest_snort_logs(settings.SNORT_LOG_DIR)
                packet_result = ingest_snort_packet_logs(settings.SNORT_LOG_DIR)
                self.stdout.write(
                    f"[{timezone.now().isoformat()}] text={text_result} packet={packet_result}"
                )
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('Snort polling stopped by user.'))
                break
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f'Polling cycle failed: {exc}'))

            self.stdout.flush()
            self.stderr.flush()
            self._sleep(interval)

    @staticmethod
    def _sleep(seconds):
        import time

        time.sleep(max(1, seconds))
