from django.urls import path

from .views import live_alerts, threat_level_distribution, top_attacks, alerts_timeline, protocol_statistics

# ===== ALERTS API ENDPOINTS =====
# Real-time security alerts from Snort IDS and analytics endpoints
urlpatterns = [
    # GET: limit param (1-500) → latest security alerts for real-time feed
    path('live/', live_alerts, name='live_alerts'),
    # GET: → count alerts grouped by threat level (safe/medium/high) for pie chart
    path('threat-level-distribution/', threat_level_distribution, name='threat_level_distribution'),
    # GET: → top 5 most common attack types by frequency for bar chart
    path('top-attacks/', top_attacks, name='top_attacks'),
    # GET: → alerts grouped by time (1-minute buckets) for line chart
    path('alerts-timeline/', alerts_timeline, name='alerts_timeline'),
    # GET: → count alerts by network protocol (TCP/UDP/ICMP) for breakdown chart
    path('protocol-statistics/', protocol_statistics, name='protocol_statistics'),
]
