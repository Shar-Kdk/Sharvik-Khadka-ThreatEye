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
        import time
        
        interval = max(1, options['interval'])
        self.stdout.write(
            self.style.SUCCESS(
                f'✓ Snort log polling started'
            )
        )
        self.stdout.write(f'  Location: {settings.SNORT_LOG_DIR}')
        self.stdout.write(f'  Interval: {interval}s')
        self.stdout.write(f'  Press Ctrl+C to stop\n')
        self.stdout.write('Loading ML analyzer...(running in silent mode)\n')
        
        total_alerts = 0
        total_ingested = 0
        total_failed = 0

        try:
            while True:
                try:
                    text_result = ingest_snort_logs(settings.SNORT_LOG_DIR)
                    packet_result = ingest_snort_packet_logs(settings.SNORT_LOG_DIR)
                    
                    # Track cumulative stats
                    inserted = text_result.get('inserted', 0)
                    processed = text_result.get('processed_lines', 0)
                    failed = text_result.get('failed_lines', 0)
                    
                    if processed > 0 or inserted > 0 or failed > 0:
                        # Show real-time activity
                        timestamp = timezone.now().strftime('%H:%M:%S')
                        self.stdout.write(f'[{timestamp}] Detected: {processed} | Inserted: {inserted} | Failed: {failed}')
                        total_alerts += processed
                        total_ingested += inserted
                        total_failed += failed
                    
                    self.stdout.flush()
                    self.stderr.flush()
                    
                    time.sleep(max(1, interval))
                            
                except Exception as exc:
                    self.stderr.write(self.style.ERROR(f'Error: {exc}'))
                    self.stdout.flush()
                    self.stderr.flush()
                    time.sleep(max(1, interval))
        
        except KeyboardInterrupt:
            # Show final summary
            self.stdout.write(self.style.WARNING('\n✓ Snort polling stopped\n'))
            self.stdout.write(self.style.SUCCESS('═══════ Session Summary ═══════'))
            self.stdout.write(f'✓ Alerts Found:        {total_alerts}')
            self.stdout.write(f'✓ Alerts Ingested:     {total_ingested}')
            self.stdout.write(f'✓ ML Analysis Done:    {total_ingested}')
            self.stdout.write(f'✓ Emails Sent:         {total_ingested}')
            self.stdout.write(f'✓ Failures:            {total_failed}')
            self.stdout.write(self.style.SUCCESS('═════════════════════════════\n'))
