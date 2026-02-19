from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from alerts.models import LogIngestionState
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

        parser.add_argument(
            '--reset-state',
            action='store_true',
            help='Reset LogIngestionState offsets to 0 before starting (forces re-read).',
        )

        parser.add_argument(
            '--backfill',
            action='store_true',
            help='On startup, ingest existing logs once WITHOUT email/websocket (faster, avoids spam), then start polling.',
        )

        parser.add_argument(
            '--once',
            action='store_true',
            help='Ingest/backfill once and exit (no continuous polling).',
        )

        parser.add_argument(
            '--no-ml',
            action='store_true',
            help='Disable ML enrichment during ingestion.',
        )

        parser.add_argument(
            '--no-email',
            action='store_true',
            help='Disable alert email notifications during ingestion.',
        )

        parser.add_argument(
            '--no-websocket',
            action='store_true',
            help='Disable WebSocket broadcasts during ingestion.',
        )

    def handle(self, *args, **options):
        import time
        
        interval = max(1, options['interval'])
        enable_ml = not bool(options.get('no_ml'))
        enable_email = not bool(options.get('no_email'))
        enable_websocket = not bool(options.get('no_websocket'))

        if options.get('reset_state'):
            updated = LogIngestionState.objects.update(offset=0)
            self.stdout.write(self.style.WARNING(f'[RESET] LogIngestionState offsets reset ({updated} rows)'))

        self.stdout.write(
            self.style.SUCCESS(
                f'[OK] Snort log polling started'
            )
        )
        self.stdout.write(f'  Location: {settings.SNORT_LOG_DIR}')
        self.stdout.write(f'  Interval: {interval}s')
        self.stdout.write(f'  Press Ctrl+C to stop\n')
        self.stdout.write('Loading ML analyzer...(running in silent mode)\n')
        
        total_alerts = 0
        total_ingested = 0
        total_failed = 0

        if options.get('backfill'):
            self.stdout.write(self.style.WARNING('[BACKFILL] Ingesting existing logs (email/websocket disabled)...'))
            try:
                backfill_text = ingest_snort_logs(
                    settings.SNORT_LOG_DIR,
                    enable_ml=enable_ml,
                    enable_email=False,
                    enable_websocket=False,
                )
                backfill_packets = ingest_snort_packet_logs(
                    settings.SNORT_LOG_DIR,
                    enable_ml=enable_ml,
                    enable_email=False,
                    enable_websocket=False,
                )
                self.stdout.write(
                    self.style.SUCCESS(
                        f"[BACKFILL] Alerts inserted={backfill_text.get('inserted', 0)} processed={backfill_text.get('processed_lines', 0)} failed={backfill_text.get('failed_lines', 0)}"
                    )
                )
                if backfill_packets.get('processed_packets', 0) or backfill_packets.get('inserted', 0):
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"[BACKFILL] Packets inserted={backfill_packets.get('inserted', 0)} processed={backfill_packets.get('processed_packets', 0)} failed={backfill_packets.get('failed_packets', 0)}"
                        )
                    )
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f'[BACKFILL] Error: {exc}'))

            if options.get('once'):
                return

        try:
            while True:
                try:
                    text_result = ingest_snort_logs(
                        settings.SNORT_LOG_DIR,
                        enable_ml=enable_ml,
                        enable_email=enable_email,
                        enable_websocket=enable_websocket,
                    )
                    packet_result = ingest_snort_packet_logs(
                        settings.SNORT_LOG_DIR,
                        enable_ml=enable_ml,
                        enable_email=enable_email,
                        enable_websocket=enable_websocket,
                    )
                    
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
            self.stdout.write(self.style.WARNING('\n[STOP] Snort polling stopped\n'))
            self.stdout.write(self.style.SUCCESS('======= Session Summary ======='))
            self.stdout.write(f'  Alerts Found:        {total_alerts}')
            self.stdout.write(f'  Alerts Ingested:     {total_ingested}')
            self.stdout.write(f"  ML Enabled:          {enable_ml}")
            self.stdout.write(f"  Email Enabled:       {enable_email}")
            self.stdout.write(f"  WebSocket Enabled:   {enable_websocket}")
            self.stdout.write(f'  Failures:            {total_failed}')
            self.stdout.write(self.style.SUCCESS('===============================\n'))
