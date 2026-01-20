from django.contrib import admin
from django.urls import path, include
from alerts.views import threat_level_distribution, top_attacks, alerts_timeline, protocol_statistics

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')),
    path('api/alerts/', include('alerts.urls')),
    path('api/threat-level-distribution/', threat_level_distribution, name='api_threat_level_distribution'),
    path('api/top-attacks/', top_attacks, name='api_top_attacks'),
    path('api/alerts-timeline/', alerts_timeline, name='api_alerts_timeline'),
    path('api/protocol-statistics/', protocol_statistics, name='api_protocol_statistics'),
    path('subscriptions/', include('subscription.urls')),
]
