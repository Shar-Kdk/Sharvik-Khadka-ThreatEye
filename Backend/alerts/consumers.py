"""
WebSocket consumer for real-time alert streaming.

Clients connect to ws://<host>/ws/alerts/ and receive new alerts
as they are ingested by the poll_snort_logs management command.

Authentication: JWT token passed as query parameter
  ws://localhost:8000/ws/alerts/?token=<jwt_access_token>

Message format (server → client):
{
    "type": "new_alert",
    "alert": {
        "id": 123,
        "timestamp": "2026-04-19T12:00:00+00:00",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "protocol": "TCP",
        "sid": "1000001",
        "message": "Possible SQL Injection Attempt",
        "classification": "Web Application Attack",
        "priority": 1,
        "threat_level": "high",
        "ml_processed": true,
        "ml_threat_score": 0.95,
        "ml_classification": "attack"
    }
}
"""

import json
import logging
from urllib.parse import parse_qs

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

# Group name for broadcasting alerts to all connected clients
ALERTS_GROUP = 'live_alerts'

User = get_user_model()


class AlertConsumer(AsyncJsonWebsocketConsumer):
    """
    WebSocket consumer for real-time alert streaming.
    
    Lifecycle:
    1. Client connects with JWT token in query string
    2. Server validates token and joins the client to 'live_alerts' group
    3. When poll_snort_logs finds a new alert, it broadcasts to this group
    4. All connected clients receive the alert instantly
    """
    
    async def connect(self):
        """Authenticate via JWT query param and join the alerts broadcast group."""
        # Extract token from query string: ws://host/ws/alerts/?token=xxx
        query_string = self.scope.get('query_string', b'').decode('utf-8')
        params = parse_qs(query_string)
        token_list = params.get('token', [])
        
        if not token_list:
            logger.warning('[AlertConsumer] Connection rejected: no token provided')
            await self.close(code=4001)
            return
        
        token_str = token_list[0]
        
        # Validate the JWT token
        user = await self._authenticate(token_str)
        if user is None:
            logger.warning('[AlertConsumer] Connection rejected: invalid token')
            await self.close(code=4003)
            return
        
        self.scope['user'] = user
        
        # Join the broadcast group — all alert consumers share one group
        await self.channel_layer.group_add(ALERTS_GROUP, self.channel_name)
        await self.accept()
        
        logger.info(f'[AlertConsumer] Client connected: {user.email} (channel={self.channel_name})')
    
    async def disconnect(self, close_code):
        """Leave the alerts group on disconnect."""
        await self.channel_layer.group_discard(ALERTS_GROUP, self.channel_name)
        user_email = getattr(self.scope.get('user'), 'email', 'unknown')
        logger.info(f'[AlertConsumer] Client disconnected: {user_email} (code={close_code})')
    
    async def receive_json(self, content, **kwargs):
        """
        Handle messages FROM the client.
        Currently not used — this is a server-push-only channel.
        Reserved for future features like "Block IP" commands.
        """
        logger.debug(f'[AlertConsumer] Received from client: {content}')
    
    # ----- Group message handlers -----
    
    async def alert_new(self, event):
        """Called when a new alert is broadcasted."""
        await self.send_json({
            'type': 'new_alert',
            'alert': event['data'],
        })

    async def alert_clear(self, event):
        """Called when the database is cleared."""
        await self.send_json({
            'type': 'clear_alerts',
            'data': event.get('data', {}),
        })
    
    async def alert_batch(self, event):
        """Called when a batch of alerts is broadcasted."""
        await self.send_json({
            'type': 'batch_alert',
            'data': event.get('data', {}),
        })
    
    # ----- Private helpers -----
    
    @database_sync_to_async
    def _authenticate(self, token_str):
        """Validate JWT access token and return the User, or None."""
        try:
            access_token = AccessToken(token_str)
            user_id = access_token['user_id']
            return User.objects.get(id=user_id, is_active=True)
        except Exception as e:
            logger.debug(f'[AlertConsumer] Auth failed: {e}')
            return None
