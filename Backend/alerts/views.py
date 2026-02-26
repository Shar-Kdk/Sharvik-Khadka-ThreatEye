"""
Core alert operations: live alerts listing, filtering, and WebSocket broadcasting.
Analytics endpoints are in analytics.py for better separation of concerns.
"""
import logging

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count, Q
from django.utils import timezone as dj_timezone
from datetime import datetime, timedelta

from .models import Alert
from .services import map_priority_to_threat_level

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def live_alerts(request):
    """
    Get latest security alerts with comprehensive filtering support.
    
    Query Parameters:
    - limit: number of results (1-10000, default 100)
    - threat_level: comma-separated values (safe,medium,high)
    - sid: comma-separated signature IDs
    - src_ip: source/attacker IP address (supports partial match)
    - dest_ip: destination IP address (supports partial match)
    - protocol: comma-separated protocols (TCP,UDP,ICMP)
    - date_from: start date (ISO format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)
    - date_to: end date (ISO format)
    - search: search in message/classification/SID
    
    Returns: filtered alerts ordered by timestamp (newest first)
    """
    # Parse and validate limit
    limit = request.query_params.get('limit', '100')
    try:
        limit = max(1, min(10000, int(limit)))
    except ValueError:
        limit = 100

    # Optional pagination offset (0-based)
    offset = request.query_params.get('offset', '0')
    try:
        offset = max(0, int(offset))
    except ValueError:
        offset = 0

    # Start with all alerts
    queryset = Alert.objects.all()
    
    # Log incoming filter parameters for debugging
    filter_params = {k: v for k, v in request.query_params.items() if k != 'limit'}
    if filter_params:
        logger.info(f"[live_alerts] Filters received: {filter_params}")
    
    # Filter by threat level (can be multiple: "high,medium")
    threat_levels = request.query_params.get('threat_level', '')
    if threat_levels:
        levels = [l.strip().lower() for l in threat_levels.split(',') if l.strip()]
        if levels:
            queryset = queryset.filter(threat_level__in=levels)
            logger.info(f"[live_alerts] Filtering threat_level__in={levels}")
    
    # Filter by SID (can be multiple: "1000015,1000014")
    sids = request.query_params.get('sid', '')
    if sids:
        sid_list = [s.strip() for s in sids.split(',') if s.strip()]
        if sid_list:
            queryset = queryset.filter(sid__in=sid_list)
    
    # Filter by source IP (attacker IP) — supports partial match
    src_ip = request.query_params.get('src_ip', '')
    if src_ip:
        src_ip = src_ip.strip()
        queryset = queryset.filter(src_ip__icontains=src_ip)
    
    # Filter by destination IP (target IP) — supports partial match
    dest_ip = request.query_params.get('dest_ip', '')
    if dest_ip:
        dest_ip = dest_ip.strip()
        queryset = queryset.filter(dest_ip__icontains=dest_ip)
    
    # Filter by protocol (can be multiple: "TCP,UDP")
    # Case-insensitive: normalize both filter values and DB comparison
    protocols = request.query_params.get('protocol', '')
    if protocols:
        protocol_list = [p.strip().upper() for p in protocols.split(',') if p.strip()]
        if protocol_list:
            # Use case-insensitive matching to handle mixed-case data in DB
            protocol_q = Q()
            for proto in protocol_list:
                protocol_q |= Q(protocol__iexact=proto)
            queryset = queryset.filter(protocol_q)
    
    # Filter by date range
    # IMPORTANT: USE_TZ=True requires timezone-aware datetimes for comparison
    date_from = request.query_params.get('date_from', '')
    date_to = request.query_params.get('date_to', '')
    
    if date_from:
        try:
            # Normalize: datetime-local sends "YYYY-MM-DDTHH:MM" (no seconds) which
            # fromisoformat() rejects on Python < 3.11 — pad to full ISO format first
            date_from_norm = date_from.strip().replace('Z', '+00:00')
            if len(date_from_norm) == 16:  # "YYYY-MM-DDTHH:MM"
                date_from_norm += ':00'
            from_dt = datetime.fromisoformat(date_from_norm)
            # Make timezone-aware if naive (required when USE_TZ=True)
            if from_dt.tzinfo is None:
                from_dt = dj_timezone.make_aware(from_dt, dj_timezone.get_current_timezone())
            queryset = queryset.filter(timestamp__gte=from_dt)
            logger.info(f"[live_alerts] Filtering timestamp >= {from_dt.isoformat()}")
        except (ValueError, AttributeError) as e:
            logger.warning(f"[live_alerts] Invalid date_from '{date_from}': {e}")
    
    if date_to:
        try:
            date_to_norm = date_to.strip().replace('Z', '+00:00')
            if len(date_to_norm) == 16:  # "YYYY-MM-DDTHH:MM"
                date_to_norm += ':00'
            to_dt = datetime.fromisoformat(date_to_norm)
            # Add end-of-day if only date is provided (to include entire day)
            if len(date_to.strip()) == 10:  # YYYY-MM-DD format
                to_dt = to_dt.replace(hour=23, minute=59, second=59)
            # Make timezone-aware if naive (required when USE_TZ=True)
            if to_dt.tzinfo is None:
                to_dt = dj_timezone.make_aware(to_dt, dj_timezone.get_current_timezone())
            queryset = queryset.filter(timestamp__lte=to_dt)
            logger.info(f"[live_alerts] Filtering timestamp <= {to_dt.isoformat()}")
        except (ValueError, AttributeError) as e:
            logger.warning(f"[live_alerts] Invalid date_to '{date_to}': {e}")
    
    # Search in message, classification, SID
    search_query = request.query_params.get('search', '')
    if search_query:
        search_query = search_query.strip()
        queryset = queryset.filter(
            Q(message__icontains=search_query) |
            Q(classification__icontains=search_query) |
            Q(sid__icontains=search_query) |
            Q(src_ip__icontains=search_query) |
            Q(dest_ip__icontains=search_query)
        )
    
    # Get total count BEFORE applying limit (for pagination info)
    total_available = queryset.count()
    
    # Order by newest first (stable ordering for pagination), apply offset+limit,
    # and evaluate to list ONCE (avoids extra queries from iteration)
    alerts_list = list(queryset.order_by('-timestamp', '-id')[offset:offset + limit])
    
    logger.info(
        f"[live_alerts] Returning {len(alerts_list)} alerts (total_available={total_available}, offset={offset}, limit={limit})"
    )

    return Response({
        'count': len(alerts_list),
        'total_available': total_available,
        'offset': offset,
        'limit': limit,
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
            for alert in alerts_list
        ],
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def filter_options(request):
    """
    Get distinct values for filter dropdowns (SID, Attacker IP, Target IP).
    Returns sorted, deduplicated lists populated from recent alert data.
    
    OPTIMIZATION: Limited to alerts from last 7 days + limited results
    to avoid full table scans on 558k+ row tables
    
    Response format:
    {
        "sids": [{"value": "1000015", "label": "1000015 — Possible Malware C2 Communication"}, ...],
        "src_ips": ["8.8.8.8", "192.168.1.50", ...],  (top 100 by frequency)
        "dest_ips": ["10.0.0.5", ...]  (top 100 by frequency)
    }
    """
    from django.utils import timezone as dj_timezone
    from datetime import timedelta
    
    # Limit to last 7 days for performance
    cutoff = dj_timezone.now() - timedelta(days=7)
    recent_alerts = Alert.objects.filter(timestamp__gte=cutoff)
    
    # Distinct SIDs with their most common message for labelling
    sid_rows = (
        recent_alerts.values('sid', 'message')
        .annotate(msg_count=Count('id'))
        .order_by('sid', '-msg_count')[:100]  # Limit to top 100 SIDs
    )
    # Pick the most frequent message per SID
    sid_labels = {}
    for row in sid_rows:
        sid = row['sid']
        if sid not in sid_labels:
            sid_labels[sid] = row['message']
    
    sids = [
        {'value': sid, 'label': f"{sid} — {msg[:80]}"}
        for sid, msg in sorted(sid_labels.items())
    ]
    
    # Top 100 source IPs by frequency (sorted by frequency, then alphabetically)
    src_ips_data = (
        recent_alerts
        .values('src_ip')
        .annotate(count=Count('id'))
        .order_by('-count', 'src_ip')[:100]
    )
    src_ips = [row['src_ip'] for row in src_ips_data]
    
    # Top 100 destination IPs by frequency
    dest_ips_data = (
        recent_alerts
        .values('dest_ip')
        .annotate(count=Count('id'))
        .order_by('-count', 'dest_ip')[:100]
    )
    dest_ips = [row['dest_ip'] for row in dest_ips_data]
    
    return Response({
        'sids': sids,
        'src_ips': src_ips,
        'dest_ips': dest_ips,
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


# ===== INTERNAL WEBSOCKET BROADCAST ENDPOINT =====
# Called by poll_snort_logs (separate process) to broadcast alerts
# via the Daphne server's InMemoryChannelLayer.

@api_view(['POST'])
def ws_broadcast_alert(request):
    """
    Internal endpoint for cross-process WebSocket broadcasting.

    InMemoryChannelLayer is process-local — poll_snort_logs runs in a
    separate process, so its channel_layer.group_send() never reaches
    the Daphne server where WebSocket clients are connected.

    Solution: poll_snort_logs POSTs the alert data here via HTTP.
    This view runs *inside* Daphne, so the broadcast reaches all clients.
    """
    from django.conf import settings as django_settings

    # Simple shared-secret auth (not exposed to the internet)
    internal_key = request.headers.get('X-Internal-Key', '')
    expected_key = django_settings.SECRET_KEY[:16]
    if internal_key != expected_key:
        return Response({'error': 'forbidden'}, status=403)

    event_type = request.data.get('type', 'alert.new')
    payload = None

    if event_type == 'alert.new':
        payload = request.data.get('alert')
        if not payload:
            return Response({'error': 'missing alert data'}, status=400)
    elif event_type == 'alert.clear':
        payload = {} # No extra data needed for clear
    else:
        return Response({'error': f'unknown event type: {event_type}'}, status=400)

    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        from .consumers import ALERTS_GROUP

        channel_layer = get_channel_layer()
        if channel_layer is not None:
            async_to_sync(channel_layer.group_send)(
                ALERTS_GROUP,
                {
                    'type': event_type, 
                    'data': payload,
                }
            )
            logger.debug(f"[ws_broadcast_alert] Broadcast {event_type} to WebSocket clients")
    except Exception as e:
        logger.warning(f'[ws_broadcast_alert] Broadcast failed: {e}')
        return Response({'error': str(e)}, status=500)

    return Response({'status': 'ok'})
