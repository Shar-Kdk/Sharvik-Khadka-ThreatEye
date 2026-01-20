from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count
from django.db.models.functions import TruncMinute

from .models import Alert
from .services import map_priority_to_threat_level


SID_ATTACK_MAP = {
    '1000015': 'Possible Malware C2 Communication',
    '1000014': 'Possible MITM Activity Detected',
    'packet_capture': 'Packet Capture Event',
}


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def live_alerts(request):
    limit = request.query_params.get('limit', '100')
    try:
        limit = max(1, min(500, int(limit)))
    except ValueError:
        limit = 100

    alerts = Alert.objects.all().order_by('-timestamp')[:limit]

    return Response({
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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_level_distribution(request):
    aggregated = (
        Alert.objects.values('threat_level')
        .annotate(count=Count('id'))
        .order_by('threat_level')
    )

    counts = {'safe': 0, 'medium': 0, 'high': 0}
    for row in aggregated:
        level = row['threat_level']
        if level in counts:
            counts[level] = row['count']

    return Response({
        'results': [
            {'threat_level': 'safe', 'count': counts['safe']},
            {'threat_level': 'medium', 'count': counts['medium']},
            {'threat_level': 'high', 'count': counts['high']},
        ]
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def top_attacks(request):
    top_sids = list(
        Alert.objects.values('sid')
        .annotate(count=Count('id'))
        .order_by('-count', 'sid')[:5]
    )

    sid_values = [row['sid'] for row in top_sids]
    message_rows = (
        Alert.objects.filter(sid__in=sid_values)
        .values('sid', 'message')
        .annotate(message_count=Count('id'))
        .order_by('sid', '-message_count')
    )

    top_message_by_sid = {}
    for row in message_rows:
        sid = row['sid']
        if sid not in top_message_by_sid:
            top_message_by_sid[sid] = row['message']

    results = []
    for row in top_sids:
        sid = row['sid']
        attack_name = SID_ATTACK_MAP.get(sid) or top_message_by_sid.get(sid) or f'Attack SID {sid}'
        results.append({
            'sid': sid,
            'count': row['count'],
            'attack_name': attack_name,
        })

    return Response({'results': results})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def alerts_timeline(request):
    timeline = (
        Alert.objects.annotate(bucket=TruncMinute('timestamp'))
        .values('bucket')
        .annotate(count=Count('id'))
        .order_by('bucket')
    )

    return Response({
        'results': [
            {
                'time': row['bucket'].isoformat() if row['bucket'] else None,
                'count': row['count'],
            }
            for row in timeline
        ]
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protocol_statistics(request):
    protocol_stats = (
        Alert.objects.values('protocol')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    return Response({
        'results': [
            {
                'protocol': row['protocol'] or 'Unknown',
                'count': row['count'],
            }
            for row in protocol_stats
        ]
    })
