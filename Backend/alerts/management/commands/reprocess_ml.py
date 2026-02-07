from django.core.management.base import BaseCommand

from alerts.models import Alert
from alerts.services import enrich_alert_with_ml


class Command(BaseCommand):
    help = 'Re-run ML enrichment for alerts in the database (updates ml_* fields).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--all',
            action='store_true',
            help='Reprocess all alerts (default: only those not ML-processed or missing ML fields).',
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=0,
            help='Limit number of alerts to process (0=all).',
        )
        parser.add_argument(
            '--threat-level',
            type=str,
            default='all',
            choices=['all', 'safe', 'medium', 'high'],
            help='Filter by threat level. Default: all',
        )

    def handle(self, *args, **options):
        process_all = bool(options['all'])
        limit = int(options['limit'])
        threat_level = options['threat_level']

        qs = Alert.objects.all()

        if threat_level != 'all':
            qs = qs.filter(threat_level=threat_level)

        if not process_all:
            qs = qs.filter(ml_processed=False) | qs.filter(ml_classification='') | qs.filter(ml_threat_score__isnull=True)

        qs = qs.order_by('id')

        total = qs.count()
        if limit > 0:
            total = min(total, limit)
            qs = qs[:limit]

        if total == 0:
            self.stdout.write(self.style.WARNING('No alerts matched the selected filter(s).'))
            return

        self.stdout.write(self.style.SUCCESS('Reprocessing ML enrichment...'))
        self.stdout.write(f'  Alerts to process: {total}')
        if threat_level != 'all':
            self.stdout.write(f'  Threat level:      {threat_level}')
        self.stdout.write(f"  Mode:              {'all alerts' if process_all else 'only missing/unprocessed'}\n")

        ok = 0
        failed = 0
        processed = 0

        for alert in qs.iterator(chunk_size=200):
            processed += 1
            if enrich_alert_with_ml(alert):
                ok += 1
            else:
                failed += 1

            if processed % 200 == 0:
                self.stdout.write(f'  Progress: {processed}/{total} (ok={ok}, failed={failed})')

        self.stdout.write(self.style.SUCCESS('\n✓ ML reprocessing complete'))
        self.stdout.write(f'  Processed: {processed}')
        self.stdout.write(f'  Updated:   {ok}')
        self.stdout.write(f'  Failed:    {failed}')
