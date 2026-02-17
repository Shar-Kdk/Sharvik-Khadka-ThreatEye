"""
ASGI config for ThreatEye project.

Routes incoming connections by protocol:
  - HTTP requests  → standard Django views (REST API, admin, etc.)
  - WebSocket connections → Django Channels consumers (real-time alerts)
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')

# Initialize Django BEFORE importing any app code
django.setup()

from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

from alerts.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    # Standard HTTP traffic → Django REST Framework, Admin, etc.
    'http': get_asgi_application(),
    
    # WebSocket traffic → Alert streaming consumer
    'websocket': URLRouter(websocket_urlpatterns),
})
