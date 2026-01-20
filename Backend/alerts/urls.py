from django.urls import path

from .views import live_alerts, threat_level_distribution, top_attacks, alerts_timeline, protocol_statistics

urlpatterns = [
    path('live/', live_alerts, name='live_alerts'),
    path('threat-level-distribution/', threat_level_distribution, name='threat_level_distribution'),
    path('top-attacks/', top_attacks, name='top_attacks'),
    path('alerts-timeline/', alerts_timeline, name='alerts_timeline'),
    path('protocol-statistics/', protocol_statistics, name='protocol_statistics'),
]
