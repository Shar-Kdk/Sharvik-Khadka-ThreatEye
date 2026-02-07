from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count
from django.db.models.functions import TruncMinute

from .models import Alert
from .services import map_priority_to_threat_level

# Map Snort Signature IDs to human-readable attack names
SID_ATTACK_MAP = {
    '1000015': 'Possible Malware C2 Communication',
    '1000014': 'Possible MITM Activity Detected',
    'packet_capture': 'Packet Capture Event',
}


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def live_alerts(request):
    """
    Get latest security alerts (limit: 1-10000, default 100)
    Used for live alert feed in dashboard
    """
    limit = request.query_params.get('limit', '100')
    try:
        limit = max(1, min(10000, int(limit)))
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
                'threat_level': alert.threat_level,
            }
            for alert in alerts
        ],
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_level_distribution(request):
    """
    Get count of alerts grouped by threat level (safe, medium, high)
    Returns: {'safe': 100, 'medium': 50, 'high': 10}
    Used for pie/donut chart on dashboard
    """
    # Count alerts by threat level
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
    """
    Get top 5 most common attack types
    Shows which attacks are happening most frequently
    Used for Top Attacks bar chart on dashboard
    """
    # Find top 5 attacks by occurrence count
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
    """
    Get alerts grouped by time (1-minute buckets)
    Shows alert frequency over time in a line chart
    Used for alerts timeline/activity chart on dashboard
    """
    # Group alerts by 1-minute time buckets and count
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
    """
    Get breakdown of network protocols in alerts (TCP, UDP, ICMP, etc.)
    Shows which protocols are being attacked most
    Used for protocol distribution chart on dashboard
    """
    # Count alerts by protocol type
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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def top_suspicious_ips(request):
    """
    Get top 5 most suspicious source IPs based on alert frequency
    Shows: IP address, alert count, last seen timestamp
    Used for Suspicious IPs tracking on dashboard
    """
    from django.db.models import Max
    
    # Get top 5 source IPs by alert count
    top_ips = (
        Alert.objects.values('src_ip')
        .annotate(
            alert_count=Count('id'),
            last_seen=Max('timestamp')
        )
        .order_by('-alert_count')[:5]
    )
    
    return Response({
        'results': [
            {
                'src_ip': row['src_ip'],
                'alert_count': row['alert_count'],
                'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
            }
            for row in top_ips
        ]
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_alert_email(request):
    """
    Manually trigger email notification for a specific alert.
    Used for testing or manual notifications.
    
    Request body: { "alert_id": 123 }
    """
    from .services import send_alert_notification
    
    alert_id = request.data.get('alert_id')
    
    if not alert_id:
        return Response({'error': 'alert_id is required'}, status=400)
    
    try:
        alert = Alert.objects.get(id=alert_id)
    except Alert.DoesNotExist:
        return Response({'error': f'Alert with id {alert_id} not found'}, status=404)
    
    # Send notification
    send_alert_notification(alert)
    
    return Response({
        'success': True,
        'message': f'Alert notification queued for alert {alert_id}',
        'alert': {
            'id': alert.id,
            'threat_level': alert.threat_level,
            'message': alert.message,
            'timestamp': alert.timestamp.isoformat(),
        }
    })

