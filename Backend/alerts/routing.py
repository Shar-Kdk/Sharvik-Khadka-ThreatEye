"""
WebSocket URL routing for the alerts app.

Maps WebSocket paths to consumers:
  ws://<host>/ws/alerts/  →  AlertConsumer (real-time alert stream)
"""

from django.urls import re_path
from .consumers import AlertConsumer

websocket_urlpatterns = [
    # Real-time alert stream — clients connect here to receive live alerts
    re_path(r'ws/alerts/$', AlertConsumer.as_asgi()),
]
