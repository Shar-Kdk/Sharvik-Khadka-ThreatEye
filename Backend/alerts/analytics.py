"""
Analytics endpoints for ThreatEye alerts dashboard.
Handles all analytics and statistics queries without mixing with core alert operations.
"""
import logging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count, Max
from django.db.models.functions import TruncMinute
from django.utils import timezone as dj_timezone
from datetime import timedelta

from .models import Alert, LogIngestionState

logger = logging.getLogger(__name__)

# Map Snort Signature IDs to human-readable attack names
SID_ATTACK_MAP = {
    '1000015': 'Possible Malware C2 Communication',
    '1000014': 'Possible MITM Activity Detected',
    'packet_capture': 'Packet Capture Event',
}


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
    
    OPTIMIZATION: Cache commonly used SIDs to avoid extra queries
    """
    # Find top 5 attacks by occurrence count with message in one query
    top_sids = Alert.objects.values('sid', 'message').annotate(
        count=Count('id')
    ).order_by('-count')[:5]

    results = []
    for row in top_sids:
        sid = row['sid']
        message = row['message']
        attack_name = SID_ATTACK_MAP.get(sid) or message[:80] or f'Attack SID {sid}'
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
    Get alerts grouped by time (1-minute buckets) - LIMITED TO LAST 24 HOURS
    Shows alert frequency over time in a line chart
    Used for alerts timeline/activity chart on dashboard.
    
    OPTIMIZATION: Only queries last 24 hours instead of all time (for speed)
    """
    # Limit to last 24 hours to avoid scanning all 558k+ alerts
    cutoff = dj_timezone.now() - timedelta(hours=24)
    
    # Group alerts by 1-minute time buckets and count (24h only)
    timeline = (
        Alert.objects.filter(timestamp__gte=cutoff)
        .annotate(bucket=TruncMinute('timestamp'))
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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_summary(request):
    """
    Get comprehensive dashboard summary with all key metrics.
    
    Returns:
    - totalAlerts24h: Total alerts in last 24 hours
    - alertsBySeverity: Count of high/medium/low severity alerts (last 24h)
    - activeThreats: High severity alerts (last 7 days)
    - falsePositives: Alerts classified as benign by ML model
    - topAttackType: Most common attack type/classification (last 24h)
    - mostTargetedIp: IP address most frequently targeted (last 24h)
    - mostFrequentSourceIp: IP address most frequently attacking (last 24h)
    - ingestionRunning: Whether log ingestion is currently active
    - lastLogReceived: Timestamp of most recent alert
    
    OPTIMIZATION: All queries limited to 24h window except active threats (7d) and false positives (all-time)
    """
    now = dj_timezone.now()
    time_24h_ago = now - timedelta(hours=24)
    time_7d_ago = now - timedelta(days=7)
    
    # Get all recent alerts once (24h window) to avoid multiple full table scans
    recent_alerts_24h = Alert.objects.filter(timestamp__gte=time_24h_ago)
    
    # Total alerts (last 24h)
    total_alerts_24h = recent_alerts_24h.count()
    
    # Alerts by severity (last 24h)
    severity_counts = (
        recent_alerts_24h
        .values('threat_level')
        .annotate(count=Count('id'))
    )
    
    # Map database threat levels to dashboard display names
    alerts_by_severity = {
        'high': 0,
        'medium': 0,
        'safe': 0,  # Using 'safe' to match database threat_level values
    }
    for item in severity_counts:
        threat_level = item['threat_level']
        if threat_level in alerts_by_severity:
            alerts_by_severity[threat_level] = item['count']
    
    # Active threats (high severity, last 7 days)
    active_threats = Alert.objects.filter(
        threat_level='high',
        timestamp__gte=time_7d_ago
    ).count()
    
    # False positives: high/medium severity alerts classified as benign by ML
    false_positives = Alert.objects.filter(
        threat_level__in=['high', 'medium'],
        ml_classification='benign',
        ml_processed=True
    ).count()
    
    # Top attack type (most common classification in last 24h)
    top_attack = (
        recent_alerts_24h
        .values('classification')
        .annotate(count=Count('id'))
        .order_by('-count')
        .first()
    )
    top_attack_type = top_attack['classification'] if top_attack and top_attack['classification'] else 'N/A'
    
    # Most targeted IP (most common dest_ip in last 24h)
    most_targeted = (
        recent_alerts_24h
        .values('dest_ip')
        .annotate(count=Count('id'))
        .order_by('-count')
        .first()
    )
    most_targeted_ip = most_targeted['dest_ip'] if most_targeted else 'N/A'
    
    # Most frequent source IP (attacker in last 24h)
    most_frequent_source = (
        recent_alerts_24h
        .values('src_ip')
        .annotate(count=Count('id'))
        .order_by('-count')
        .first()
    )
    most_frequent_source_ip = most_frequent_source['src_ip'] if most_frequent_source else 'N/A'
    
    # Check if ingestion is running (use database query instead of Python loop)
    ingestion_running = LogIngestionState.objects.filter(
        updated_at__gte=now - timedelta(minutes=5)
    ).exists()
    
    # Last log received (most recent alert timestamp)
    last_alert = Alert.objects.order_by('-timestamp').values_list('timestamp', flat=True).first()
    last_log_received = (
        last_alert.isoformat() 
        if last_alert 
        else 'Never'
    )
    
    return Response({
        'totalAlerts24h': total_alerts_24h,
        'alertsBySeverity': alerts_by_severity,
        'activeThreats': active_threats,
        'falsePositives': false_positives,
        'topAttackType': top_attack_type,
        'mostTargetedIp': most_targeted_ip,
        'mostFrequentSourceIp': most_frequent_source_ip,
        'ingestionRunning': ingestion_running,
        'lastLogReceived': last_log_received,
    })
