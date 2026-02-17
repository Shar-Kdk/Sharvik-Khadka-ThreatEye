from django.core.management.base import BaseCommand
from django.utils import timezone
from alerts.models import Alert
from alerts.services import send_alert_notification


class Command(BaseCommand):
    help = 'Test alert email notification system by sending emails for existing high/medium alerts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--threat-level',
            type=str,
            default='high',
            choices=['high', 'medium'],
            help='Threat level to test (default: high)',
        )
        parser.add_argument(
            '--count',
            type=int,
            default=1,
            help='Number of recent alerts to send emails for (default: 1)',
        )

    def handle(self, *args, **options):
        threat_level = options['threat_level']
        count = max(1, options['count'])

        # Get recent alerts of specified threat level
        alerts = Alert.objects.filter(threat_level=threat_level).order_by('-timestamp')[:count]

        if not alerts.exists():
            self.stdout.write(self.style.WARNING(f'No {threat_level} severity alerts found'))
            return

        self.stdout.write(
            self.style.SUCCESS(f'Testing email notifications for {alerts.count()} {threat_level} alerts...')
        )

        for alert in alerts:
            self.stdout.write(f'  Sending email for Alert ID {alert.id}: {alert.message}')
            send_alert_notification(alert)

        self.stdout.write(self.style.SUCCESS('Email notifications queued successfully'))
        self.stdout.write(self.style.WARNING('Check your email inbox for alerts (may take a few seconds)'))
