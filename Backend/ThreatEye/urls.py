from django.contrib import admin
from django.urls import path, include
from alerts.views import threat_level_distribution, top_attacks, alerts_timeline, protocol_statistics, top_suspicious_ips

# ===== MAIN URL ROUTING CONFIGURATION =====
# Maps all incoming requests to the appropriate app endpoints
# API routes for authentication, alerts, and subscriptions
# Admin panel for superuser management
urlpatterns = [
    path('admin/', admin.site.urls),
    # Authentication API: login, logout, email verification, user profile
    path('api/auth/', include('authentication.urls')),
    # Alerts API: live alerts, analytics endpoints
    path('api/alerts/', include('alerts.urls')),
    # Analytics endpoints: threat level, attack types, timeline, protocols
    path('api/threat-level-distribution/', threat_level_distribution, name='api_threat_level_distribution'),
    path('api/top-attacks/', top_attacks, name='api_top_attacks'),
    path('api/alerts-timeline/', alerts_timeline, name='api_alerts_timeline'),
    path('api/protocol-statistics/', protocol_statistics, name='api_protocol_statistics'),
    path('api/top-suspicious-ips/', top_suspicious_ips, name='api_top_suspicious_ips'),
    # Subscription API: subscription plans, user subscriptions, payments
    path('subscriptions/', include('subscription.urls')),
]
