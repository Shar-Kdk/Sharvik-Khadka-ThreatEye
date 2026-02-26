"""
Django management command to re-evaluate all existing alerts with the newly trained ML model.
This command re-scores all alerts in the database using the improved fine-tuned model.
"""

import sys
import logging
from django.core.management.base import BaseCommand
from django.db.models import Q, Count
from alerts.models import Alert
from ml_features.threat_analyzer import ThreatAnalyzer

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Re-evaluate all existing alerts with the newly trained ML model'

    def add_arguments(self, parser):
        parser.add_argument(
            '--model',
            type=str,
            default='random_forest_local',
            help='Model name to use (default: random_forest_local)',
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=None,
            help='Limit number of alerts to process (default: all)',
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Batch size for processing (default: 100)',
        )
        parser.add_argument(
            '--no-update',
            action='store_true',
            help='Show results without updating database',
        )

    def handle(self, *args, **options):
        model_name = options['model']
        limit = options['limit']
        batch_size = options['batch_size']
        no_update = options['no_update']

        self.stdout.write(self.style.SUCCESS('=== ALERT RE-EVALUATION WITH NEW MODEL ===\n'))

        # Initialize ThreatAnalyzer with the new model
        try:
            self.stdout.write(f'Loading model: {model_name}...')
            threat_analyzer = ThreatAnalyzer(
                model_name=model_name,
                models_dir='trained_models'
            )
            if not threat_analyzer.model_loaded:
                self.stdout.write(self.style.ERROR(f'Failed to load model: {model_name}'))
                sys.exit(1)
            self.stdout.write(self.style.SUCCESS(f'✓ Model loaded: {model_name}\n'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error loading model: {e}'))
            sys.exit(1)

        # Get all alerts
        try:
            query = Alert.objects.all()
            if limit:
                query = query[:limit]
            
            total_alerts = query.count()
            if total_alerts == 0:
                self.stdout.write(self.style.WARNING('No alerts found in database'))
                return

            self.stdout.write(f'Found {total_alerts} alerts to re-evaluate\n')

            # Statistics tracking
            stats = {
                'total': total_alerts,
                'processed': 0,
                'safe': 0,
                'medium': 0,
                'high': 0,
                'changed': 0,
                'errors': 0,
            }
            threat_changes = {}

            # Process alerts in batches
            alerts = list(query)
            
            for batch_num, i in enumerate(range(0, len(alerts), batch_size)):
                batch = alerts[i:i+batch_size]
                batch_changed = 0

                self.stdout.write(f'Processing batch {batch_num + 1}/{(total_alerts + batch_size - 1) // batch_size}...')

                for alert in batch:
                    try:
                        # Analyze alert with new model
                        result = threat_analyzer.analyze_alert({
                            'id': alert.id,
                            'src_ip': alert.src_ip,
                            'src_port': alert.src_port or 0,
                            'dest_ip': alert.dest_ip,
                            'dest_port': alert.dest_port or 0,
                            'protocol': alert.protocol,
                            'priority': alert.priority or 3,
                            'classification': alert.classification,
                            'sid': alert.sid,
                            'message': alert.message,
                        })

                        if result.get('error'):
                            stats['errors'] += 1
                            continue

                        # Map confidence to threat level
                        old_threat = alert.threat_level
                        new_threat = self._map_threat_level(result)

                        # Update if changed
                        if new_threat != old_threat:
                            batch_changed += 1
                            stats['changed'] += 1
                            
                            threat_changes[f"{old_threat} → {new_threat}"] = \
                                threat_changes.get(f"{old_threat} → {new_threat}", 0) + 1

                            if not no_update:
                                alert.threat_level = new_threat
                                alert.save(update_fields=['threat_level'])

                        # Update statistics
                        stats['processed'] += 1
                        stats[new_threat] += 1

                    except Exception as e:
                        logger.error(f"Error processing alert {alert.id}: {e}")
                        stats['errors'] += 1

                self.stdout.write(f'  ✓ {len(batch)} alerts processed, {batch_changed} changed\n')

            # Print results
            self._print_results(stats, threat_changes, no_update)

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error during re-evaluation: {e}'))
            sys.exit(1)

    def _map_threat_level(self, result):
        """Map analyzer result to threat level."""
        threat_class = result.get('threat_class')
        confidence = result.get('confidence', 0)

        if threat_class == 1:  # Threat
            if confidence > 0.8:
                return Alert.THREAT_HIGH
            else:
                return Alert.THREAT_MEDIUM
        else:  # Benign
            return Alert.THREAT_SAFE

    def _print_results(self, stats, threat_changes, no_update):
        """Print re-evaluation results."""
        self.stdout.write(self.style.SUCCESS('\n=== RE-EVALUATION RESULTS ===\n'))
        
        self.stdout.write('Summary:')
        self.stdout.write(f'  Total alerts: {stats["total"]}')
        self.stdout.write(f'  Processed: {stats["processed"]}')
        self.stdout.write(f'  Errors: {stats["errors"]}')
        self.stdout.write(f'  Changed: {stats["changed"]} ({self._percent(stats["changed"], stats["total"])}%)\n')

        self.stdout.write('New Classification Distribution:')
        self.stdout.write(f'  Safe: {stats["safe"]} ({self._percent(stats["safe"], stats["total"])}%)')
        self.stdout.write(f'  Medium: {stats["medium"]} ({self._percent(stats["medium"], stats["total"])}%)')
        self.stdout.write(f'  High: {stats["high"]} ({self._percent(stats["high"], stats["total"])}%)\n')

        if threat_changes:
            self.stdout.write('Classification Changes:')
            for change, count in sorted(threat_changes.items(), key=lambda x: x[1], reverse=True):
                self.stdout.write(f'  {change}: {count} alerts')
            self.stdout.write()

        if no_update:
            self.stdout.write(self.style.WARNING('\n⚠️  DRY RUN - Database not updated'))
            self.stdout.write('Run without --no-update flag to apply changes\n')
        else:
            self.stdout.write(self.style.SUCCESS('\n✅ Database updated with new threat levels\n'))

    @staticmethod
    def _percent(num, total):
        """Calculate percentage."""
        if total == 0:
            return 0
        return round(100 * num / total, 1)
