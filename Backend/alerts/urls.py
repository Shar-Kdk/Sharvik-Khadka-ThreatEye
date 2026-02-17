from django.urls import path

from .views import live_alerts, filter_options, threat_level_distribution, top_attacks, alerts_timeline, protocol_statistics, top_suspicious_ips, send_alert_email, ws_broadcast_alert

# ===== ALERTS API ENDPOINTS =====
# Real-time security alerts from Snort IDS and analytics endpoints
urlpatterns = [
    # GET: limit param (1-500) → latest security alerts for real-time feed
    path('live/', live_alerts, name='live_alerts'),
    # GET: → distinct SIDs, src_ips, dest_ips for filter dropdowns
    path('filter-options/', filter_options, name='filter_options'),
    # GET: → count alerts grouped by threat level (safe/medium/high) for pie chart
    path('threat-level-distribution/', threat_level_distribution, name='threat_level_distribution'),
    # GET: → top 5 most common attack types by frequency for bar chart
    path('top-attacks/', top_attacks, name='top_attacks'),
    # GET: → alerts grouped by time (1-minute buckets) for line chart
    path('alerts-timeline/', alerts_timeline, name='alerts_timeline'),
    # GET: → count alerts by network protocol (TCP/UDP/ICMP) for breakdown chart
    path('protocol-statistics/', protocol_statistics, name='protocol_statistics'),
    # GET: → top 5 most suspicious source IPs by alert frequency for IP tracking
    path('top-suspicious-ips/', top_suspicious_ips, name='top_suspicious_ips'),
    # POST: → manually send email notification for an alert (for testing)
    path('send-email/', send_alert_email, name='send_alert_email'),
    # POST: → internal webhook for cross-process WebSocket broadcasting
    path('ws-broadcast/', ws_broadcast_alert, name='ws_broadcast_alert'),
]
