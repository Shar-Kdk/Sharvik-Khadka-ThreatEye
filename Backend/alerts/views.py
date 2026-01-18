from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Alert
from .services import ingest_snort_logs, ingest_snort_packet_logs, map_priority_to_threat_level


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def live_alerts(request):
    # Keep API responsive by processing logs in small chunks per request.
    text_sync_result = ingest_snort_logs(settings.SNORT_LOG_DIR, max_lines=5000)
    packet_sync_result = ingest_snort_packet_logs(settings.SNORT_LOG_DIR, max_packets=1500)

    limit = request.query_params.get('limit', '100')
    try:
        limit = max(1, min(500, int(limit)))
    except ValueError:
        limit = 100

    alerts = Alert.objects.all().order_by('-timestamp')[:limit]

    return Response({
        'synced': {
            'text_alerts': text_sync_result,
            'packet_logs': packet_sync_result,
        },
        'count': alerts.count(),
        'results': [
            {
                'id': alert.id,
                'timestamp': alert.timestamp.isoformat(),
                'src_ip': alert.src_ip,
                'src_port': alert.src_port,
                'dest_ip': alert.dest_ip,
                'dest_port': alert.dest_port,
                'protocol': alert.protocol,
                'sid': alert.sid,
                'message': alert.message,
                'classification': alert.classification,
                'priority': alert.priority,
                'threat_level': map_priority_to_threat_level(alert.priority),
            }
            for alert in alerts
        ],
    })
